import io
import json
import os
import tempfile
import unittest
import csv
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

import pandas as pd


os.environ.setdefault("NVIDIA_API_KEY", "test-api-key")

import evaluator
import run_pipeline


LAB_DIR = Path(__file__).resolve().parents[1]
EVALUATION_COLUMNS = [
    "run_id",
    "run_timestamp_utc",
    "model",
    "nim_base_url",
    "temperature",
    "max_completion_tokens",
    "source_alert_count",
    "alert_count",
    "prompt_strategy",
    "precision",
    "recall",
    "f1_macro",
    "f1_weighted",
    "kappa",
    "parse_success_rate",
    "parse_failure_count",
    "repaired_json_count",
    "false_negative_count",
    "mapped_alert_count",
    "unmapped_alert_count",
    "ground_truth_positive_count",
    "ground_truth_negative_count",
    "scan_coverage_gap_count",
    "friedman_statistic",
    "friedman_p_value",
    "statistical_results_file",
]


def load_alerts():
    return [
        {
            "app": "juice_shop", "alert_name": "Timestamp Disclosure - Unix",
            "cweid": "497", "risk": "Low", "confidence": "Low",
            "url": "http://juice-shop:3000/app.js", "description": "timestamp",
            "evidence": "1700000000",
        },
        {
            "app": "juice_shop", "alert_name": "Content Security Policy (CSP) Header Not Set",
            "cweid": "693", "risk": "Medium", "confidence": "Medium",
            "url": "http://juice-shop:3000/", "description": "header missing",
            "evidence": "",
        },
    ]


def prepared_alert(alert, alert_id):
    return {
        **alert,
        "alert_id": alert_id,
        "zap_cwe_id": evaluator.normalize_cwe_id(alert.get("cweid", "")),
    }


class SequencedPromptChain:
    def __init__(self, outcomes):
        self.outcomes = list(outcomes)
        self.invocations = 0

    def __or__(self, other):
        return self

    def invoke(self, alert):
        outcome = self.outcomes[self.invocations]
        self.invocations += 1
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


class DedupAndInferenceTests(unittest.TestCase):
    def test_exact_dedup_key_separates_url_and_evidence(self):
        base = prepared_alert({
            "app": "juice_shop",
            "alert_name": "Timestamp Disclosure - Unix",
            "cweid": "497",
            "risk": "Low",
            "confidence": "Low",
            "url": "http://juice-shop:3000/app.js",
            "description": "timestamp",
            "evidence": "1666666667",
        }, 0)
        exact_copy = {**base, "alert_id": 1}
        other_evidence = {**base, "alert_id": 2, "evidence": "1777777777"}
        other_url = {**base, "alert_id": 3, "url": "http://juice-shop:3000/main.js"}

        clusters = run_pipeline.deduplicate_alerts(
            [base, exact_copy, other_evidence, other_url]
        )

        self.assertEqual(len(clusters), 3)
        self.assertEqual(len(clusters[0]["members"]), 2)
        self.assertNotEqual(clusters[0]["key_token"], clusters[1]["key_token"])
        self.assertNotEqual(clusters[0]["key_token"], clusters[2]["key_token"])

    def test_prefilter_skips_unmapped_and_reexpands_raw_rows(self):
        alerts = load_alerts()
        timestamp = next(
            alert for alert in alerts
            if alert["alert_name"] == "Timestamp Disclosure - Unix"
        )
        unmapped_csp = next(
            alert for alert in alerts
            if alert["app"] == "juice_shop"
            and alert["alert_name"] == "Content Security Policy (CSP) Header Not Set"
        )
        fixture_alerts = [timestamp, dict(timestamp), unmapped_csp]
        llm_result = {
            "json_parsed": True,
            "json_repaired": False,
            "is_vulnerability": False,
            "raw_output": '{"is_vulnerability": false}',
            "parse_error": False,
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_dir = Path(temp_dir)
            alerts_path = temp_dir / "alerts.json"
            with open(alerts_path, "w", encoding="utf-8") as file:
                json.dump(fixture_alerts, file)

            with (
                patch.object(run_pipeline, "ALERTS_FILE", str(alerts_path)),
                patch.object(run_pipeline, "RESULTS_DIR", str(temp_dir / "results")),
                patch.object(run_pipeline, "GT_FILE", str(LAB_DIR / "ground_truth.csv")),
                patch.object(run_pipeline, "RULES_FILE", str(LAB_DIR / "ground_truth_match_rules.csv")),
                patch.object(run_pipeline, "evaluate_pipeline_results"),
                patch.object(run_pipeline, "assess_alert", return_value=llm_result) as assess,
                redirect_stdout(io.StringIO()),
            ):
                run_pipeline.main([])

            timestamped_pipeline_paths = list(
                (temp_dir / "results" / "pipeline").glob("pipeline_results_*.json")
            )
            timestamped_diagnostic_paths = list(
                (temp_dir / "results" / "summary").glob("parse_diagnostics_*.json")
            )
            self.assertEqual(len(timestamped_pipeline_paths), 1)
            self.assertEqual(len(timestamped_diagnostic_paths), 1)
            with open(timestamped_pipeline_paths[0], encoding="utf-8") as file:
                records = json.load(file)
            with open(timestamped_diagnostic_paths[0], encoding="utf-8") as file:
                diagnostics = json.load(file)

        self.assertEqual(assess.call_count, len(run_pipeline.PROMPT_STRATEGIES))
        self.assertEqual(len(records), len(fixture_alerts) * len(run_pipeline.PROMPT_STRATEGIES))
        mapped = [record for record in records if not record["inference_skipped"]]
        skipped = [record for record in records if record["inference_skipped"]]
        self.assertEqual(len(mapped), 2 * len(run_pipeline.PROMPT_STRATEGIES))
        self.assertEqual(len(skipped), len(run_pipeline.PROMPT_STRATEGIES))
        self.assertTrue(all(record["predicted_vulnerable"] is None for record in skipped))
        self.assertTrue(all(record["dedup_cluster_size"] == 2 for record in mapped))
        self.assertTrue(all(isinstance(record["dedup_key"], dict) for record in records))
        self.assertEqual(diagnostics["strategies"]["zero_shot"]["attempted_calls"], 1)

    def test_missing_cluster_result_fails_reexpansion(self):
        alert = prepared_alert({
            "app": "vulnerable_app",
            "alert_name": "SQL Injection",
            "cweid": "89",
            "risk": "High",
            "confidence": "High",
            "url": "http://vulnerable-app:9090/VulnerableApp/SQLInjectionVulnerability/LEVEL_1",
            "description": "SQL injection",
            "evidence": "error",
        }, 0)
        cluster = run_pipeline.deduplicate_alerts([alert])[0]
        cluster["ground_truth_match"] = {"ground_truth_label": "VULNERABLE"}
        with self.assertRaisesRegex(ValueError, "Missing zero_shot inference"):
            run_pipeline.expand_strategy_results(
                [alert],
                "zero_shot",
                {0: cluster},
                {},
                {},
            )

    def test_print_examples_exits_without_pipeline_side_effects(self):
        output = io.StringIO()
        with (
            patch.object(run_pipeline, "build_run_output_paths") as output_paths,
            patch.object(run_pipeline, "wait_for_zap") as scan,
            patch.object(run_pipeline, "get_llm") as get_llm,
            redirect_stdout(output),
        ):
            run_pipeline.main(["--print-examples"])

        rendered = output.getvalue()
        self.assertIn("Example 1", rendered)
        self.assertIn("Timestamp Disclosure - Unix", rendered)
        self.assertIn("Cross-Domain Misconfiguration", rendered)
        output_paths.assert_not_called()
        scan.assert_not_called()
        get_llm.assert_not_called()

    def test_every_output_path_uses_the_same_run_timestamp(self):
        paths = run_pipeline.build_run_output_paths("20260716T153045Z")
        self.assertEqual(set(paths), {
            "pipeline", "evaluation", "audit", "statistics", "summary", "unmapped",
            "parse_diagnostics", "scan",
        })
        self.assertTrue(all("_20260716T153045Z." in path for path in paths.values()))
        self.assertEqual(
            paths["pipeline"],
            os.path.join("results", "pipeline", "pipeline_results_20260716T153045Z.json"),
        )
        self.assertEqual(
            paths["evaluation"],
            os.path.join("results", "evaluation", "evaluation_results_20260716T153045Z.csv"),
        )
        self.assertEqual(
            paths["parse_diagnostics"],
            os.path.join("results", "summary", "parse_diagnostics_20260716T153045Z.json"),
        )
        self.assertEqual(
            paths["scan"],
            os.path.join("results", "scan", "zap_scan_report_20260716T153045Z.json"),
        )
        self.assertEqual(
            {Path(path).parent.name for path in paths.values()},
            set(run_pipeline.RESULT_SUBDIRECTORIES.values()),
        )

    def test_transient_nim_failure_is_retried_with_backoff(self):
        alert = prepared_alert({
            "app": "juice_shop",
            "alert_name": "Cross-Domain Misconfiguration",
            "cweid": "264",
            "risk": "Medium",
            "confidence": "Medium",
            "url": "http://juice-shop:3000/api/test",
            "description": "CORS",
            "evidence": "Access-Control-Allow-Origin: *",
        }, 0)
        chain = SequencedPromptChain([
            Exception("[503] ResourceExhausted: Worker request limit reached"),
            '{"is_vulnerability": false, "confidence": 0.1}',
        ])
        with (
            patch.object(run_pipeline, "build_assessment_chain", return_value=chain),
            patch.object(run_pipeline, "NVIDIA_MAX_RETRIES", 2),
            patch.object(run_pipeline, "NVIDIA_RETRY_BASE_SECONDS", 0.25),
            patch.object(run_pipeline, "NVIDIA_RETRY_MAX_SECONDS", 1.0),
            patch.object(run_pipeline.time, "sleep") as sleep,
            redirect_stdout(io.StringIO()),
        ):
            result = run_pipeline.assess_alert(alert, "zero_shot")

        self.assertTrue(result["json_parsed"])
        self.assertEqual(chain.invocations, 2)
        sleep.assert_called_once_with(0.25)

    def test_malformed_initial_output_is_repaired_once(self):
        alert = prepared_alert({
            "app": "juice_shop",
            "alert_name": "Timestamp Disclosure - Unix",
            "cweid": "497",
            "risk": "Low",
            "confidence": "Low",
            "url": "http://juice-shop:3000/app.js",
            "description": "timestamp",
            "evidence": "1666666667",
        }, 0)
        initial_chain = SequencedPromptChain(["not valid JSON"])
        repair_chain = SequencedPromptChain([
            '{"is_vulnerability": false, "confidence": 0.1}'
        ])
        with patch.object(
            run_pipeline,
            "build_assessment_chain",
            side_effect=[initial_chain, repair_chain],
        ):
            result = run_pipeline.assess_alert(alert, "zero_shot")

        self.assertTrue(result["json_parsed"])
        self.assertTrue(result["json_repaired"])
        self.assertEqual(initial_chain.invocations, 1)
        self.assertEqual(repair_chain.invocations, 1)
        self.assertTrue(result["inference_diagnostic"]["repair_attempted"])
        self.assertEqual(
            result["inference_diagnostic"]["initial_parse_error"],
            "No JSON object found",
        )

    def test_unrecoverable_parse_failure_has_no_safe_prediction(self):
        alert = prepared_alert({
            "app": "juice_shop",
            "alert_name": "Timestamp Disclosure - Unix",
            "cweid": "497",
            "risk": "Low",
            "confidence": "Low",
            "url": "http://juice-shop:3000/app.js",
            "description": "timestamp",
            "evidence": "1666666667",
        }, 0)
        invalid_chain = SequencedPromptChain(["not valid JSON", "still not JSON"])
        with patch.object(run_pipeline, "build_assessment_chain", return_value=invalid_chain):
            output = run_pipeline.assess_alert(alert, "zero_shot")
        record = run_pipeline.build_pipeline_record(
            alert=alert,
            llm_output=output,
            strategy="zero_shot",
            run_metadata={},
            dedup_key=run_pipeline.build_dedup_key(alert),
            dedup_cluster_size=1,
        )

        self.assertFalse(record["parsed_successfully"])
        self.assertIsNone(record["predicted_vulnerable"])
        self.assertEqual(invalid_chain.invocations, 2)

    def test_permanent_nim_failure_is_not_retried(self):
        alert = prepared_alert({
            "app": "vulnerable_app",
            "alert_name": "SQL Injection",
            "cweid": "89",
            "risk": "High",
            "confidence": "High",
            "url": "http://vulnerable-app:9090/VulnerableApp/SQLInjectionVulnerability/LEVEL_1",
            "description": "SQL injection",
            "evidence": "error",
        }, 0)
        chain = SequencedPromptChain([Exception("[401] Invalid API key")])
        with (
            patch.object(run_pipeline, "build_assessment_chain", return_value=chain),
            patch.object(run_pipeline.time, "sleep") as sleep,
        ):
            with self.assertRaisesRegex(Exception, "Invalid API key"):
                run_pipeline.assess_alert(alert, "zero_shot")

        self.assertEqual(chain.invocations, 1)
        sleep.assert_not_called()

    def test_cached_out_of_scope_alerts_require_a_fresh_scan(self):
        legacy_alert = {
            "app": "webgoat",
            "alert_name": "SQL Injection",
            "cweid": "89",
            "url": "http://webgoat:8080/WebGoat/register.mvc",
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            alerts_path = Path(temp_dir) / "zap_alerts.json"
            with open(alerts_path, "w", encoding="utf-8") as file:
                json.dump([legacy_alert], file)
            with (
                patch.object(run_pipeline, "ALERTS_FILE", str(alerts_path)),
                patch.object(run_pipeline, "RESULTS_DIR", str(Path(temp_dir) / "results")),
                patch.object(run_pipeline, "assess_alert") as assess,
                redirect_stdout(io.StringIO()),
            ):
                with self.assertRaisesRegex(ValueError, "run_pipeline.py --scan"):
                    run_pipeline.main([])
        assess.assert_not_called()


class EvaluationObservabilityTests(unittest.TestCase):
    def test_compute_metrics_exposes_distribution_and_per_class_rows(self):
        frame = pd.DataFrame({
            "ground_truth": [True, False, False, False],
            "predicted_is_vuln": [True, True, False, False],
        })
        metrics = evaluator.compute_metrics(frame)
        self.assertEqual(metrics["prediction_distribution"], {
            "predicted_vulnerable": 2,
            "predicted_safe": 2,
            "actual_vulnerable": 1,
            "actual_safe": 3,
        })
        self.assertEqual(set(metrics["classification_report"]), {"SAFE", "VULNERABLE"})
        self.assertEqual(metrics["classification_report"]["VULNERABLE"]["support"], 1)
        self.assertEqual(metrics["classification_report"]["SAFE"]["support"], 3)

    def test_evaluation_writes_summary_unmapped_file_and_warning(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_dir = Path(temp_dir)
            paths = {
                "pipeline": temp_dir / "pipeline_results.json",
                "evaluation": temp_dir / "evaluation_results.csv",
                "audit": temp_dir / "audit.csv",
                "statistics": temp_dir / "statistics.csv",
                "summary": temp_dir / "evaluation_summary.json",
                "unmapped": temp_dir / "unmapped_alerts.json",
            }
            ground_truth_path = temp_dir / "ground_truth.csv"
            rules_path = temp_dir / "ground_truth_match_rules.csv"
            with open(ground_truth_path, "w", newline="", encoding="utf-8") as file:
                writer = csv.writer(file)
                writer.writerow(["app", "provider_key", "ground_truth_label"])
                writer.writerow(["vulnerable_app", "VULNERABLE_APP-SQLI", "VULNERABLE"])
            with open(rules_path, "w", newline="", encoding="utf-8") as file:
                writer = csv.writer(file)
                writer.writerow([
                    "rule_id", "app", "zap_alert_name", "zap_cwe_id", "url_regex",
                    "evidence_regex", "ground_truth_label", "challenge_ids", "rationale",
                ])
                writer.writerow([
                    "vulnerable_app_sqli", "vulnerable_app", "SQL Injection", "CWE-89", "^/VulnerableApp/SQLInjectionVulnerability/LEVEL_1$",
                    "", "VULNERABLE", "VULNERABLE_APP-SQLI", "Controlled positive fixture.",
                ])
                writer.writerow([
                    "juice_timestamp", "juice_shop", "Timestamp Disclosure - Unix", "CWE-497",
                    "", "", "NOT_VULNERABLE", "", "Controlled negative fixture.",
                ])

            positive = prepared_alert({
                "app": "vulnerable_app", "alert_name": "SQL Injection", "cweid": "89",
                "risk": "High", "confidence": "High",
                "url": "http://vulnerable-app:9090/VulnerableApp/SQLInjectionVulnerability/LEVEL_1", "description": "SQL error",
                "evidence": "database error", "pluginid": "40018",
            }, 0)
            negatives = [prepared_alert({
                "app": "juice_shop", "alert_name": "Timestamp Disclosure - Unix", "cweid": "497",
                "risk": "Low", "confidence": "Low", "url": f"http://juice-shop:3000/a{index}.js",
                "description": "timestamp", "evidence": str(index), "pluginid": "10096",
            }, index + 1) for index in range(10)]
            unmapped = prepared_alert({
                "app": "juice_shop", "alert_name": "CSP Header Not Set", "cweid": "693",
                "risk": "Medium", "confidence": "Medium", "url": "http://juice-shop:3000/",
                "description": "CSP", "evidence": "", "pluginid": "10038",
            }, 11)
            selected = [positive, *negatives, unmapped]
            records = []
            for strategy in evaluator.PROMPT_STRATEGIES:
                for alert in selected:
                    is_unmapped = alert is unmapped
                    is_positive = alert is positive
                    records.append({
                        "run_id": "fixture-run",
                        "run_timestamp_utc": "2026-07-16T10:00:00+00:00",
                        "model": "fixture/model",
                        "nim_base_url": "https://integrate.api.nvidia.com/v1",
                        "temperature": 0.0,
                        "max_completion_tokens": 4096,
                        "source_alert_count": len(selected),
                        "alert_count": len(selected),
                        **alert,
                        "prompt_strategy": strategy,
                        "parsed_successfully": not is_unmapped,
                        "json_repaired": False,
                        "predicted_vulnerable": None if is_unmapped else is_positive,
                        "inference_skipped": is_unmapped,
                        "skip_reason": "UNMAPPED" if is_unmapped else "",
                        "dedup_key": run_pipeline.build_dedup_key(alert),
                        "dedup_cluster_size": 1,
                    })
            with open(paths["pipeline"], "w", encoding="utf-8") as file:
                json.dump(records, file)

            output = io.StringIO()
            with self.assertLogs("evaluator", level="INFO") as logs, redirect_stdout(output):
                evaluator.evaluate_pipeline_results(
                    pipeline_results_path=paths["pipeline"],
                    ground_truth_path=ground_truth_path,
                    rules_path=rules_path,
                    evaluation_output_path=paths["evaluation"],
                    audit_output_path=paths["audit"],
                    statistical_output_path=paths["statistics"],
                    summary_output_path=paths["summary"],
                    unmapped_output_path=paths["unmapped"],
                )

            with open(paths["summary"], encoding="utf-8") as file:
                summary = json.load(file)
            with open(paths["unmapped"], encoding="utf-8") as file:
                unmapped_rows = json.load(file)
            evaluation_frame = pd.read_csv(paths["evaluation"])

        self.assertIn("CLASS IMBALANCE WARNING: Positive rate = 9.1%", output.getvalue())
        self.assertIn("Top unmapped alert names:", output.getvalue())
        self.assertTrue(any("Matched alerts: 11 / 12 (91.7%)" in line for line in logs.output))
        self.assertTrue(any("Unmapped alerts (excluded): 1" in line for line in logs.output))
        self.assertEqual(summary["coverage"]["matched_alerts"], 11)
        for strategy in evaluator.PROMPT_STRATEGIES:
            distribution = summary["strategies"][strategy]["prediction_distribution"]
            self.assertEqual(distribution["predicted_vulnerable"], 1)
            self.assertEqual(distribution["predicted_safe"], 10)
        self.assertEqual(len(unmapped_rows), len(evaluator.PROMPT_STRATEGIES))
        for row in unmapped_rows:
            self.assertTrue({"alert_name", "cweid", "pluginid", "app", "strategy", "risk"} <= set(row))
        self.assertEqual(list(evaluation_frame.columns), EVALUATION_COLUMNS)


if __name__ == "__main__":
    unittest.main()
