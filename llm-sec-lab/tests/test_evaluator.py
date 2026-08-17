import csv
import json
import tempfile
import unittest
from pathlib import Path

import pandas as pd

from evaluator import (
    PROMPT_STRATEGIES,
    build_match_audit,
    calculate_parse_quality,
    compute_metrics,
    evaluate_pipeline_results,
    friedman_test,
    load_ground_truth,
    load_match_rules,
    match_alert_to_ground_truth,
    mcnemar_test,
    normalize_cwe_id,
    validate_paired_design,
    wilcoxon_posthoc,
)


LAB_DIR = Path(__file__).resolve().parents[1]
SUPPORTED_APPS = {"juice_shop", "vulnerable_app"}
FIXTURE_ALERTS = [
    {
        "app": "juice_shop", "alert_name": "Timestamp Disclosure - Unix",
        "cweid": "497", "url": "http://juice-shop:3000/app.js", "evidence": "1700000000",
    },
    {
        "app": "juice_shop", "alert_name": "Cross-Domain Misconfiguration",
        "cweid": "264", "url": "http://juice-shop:3000/public", "evidence": "Access-Control-Allow-Origin: *",
    },
    {
        "app": "juice_shop", "alert_name": "Content Security Policy (CSP) Header Not Set",
        "cweid": "693", "url": "http://juice-shop:3000/", "evidence": "",
    },
]


class GroundTruthRuleTests(unittest.TestCase):
    def test_exact_provenance_constraints_fail_closed(self):
        rule = {
            "app": "juice_shop", "zap_alert_name": "sql injection", "zap_cwe_id": "CWE-89",
            "url_pattern": __import__("re").compile(r"^/rest/products/search$"),
            "evidence_pattern": __import__("re").compile(r"apple'"),
            "param_pattern": __import__("re").compile(r"^q$"), "plugin_id": "40018",
            "request_method": "GET", "authentication_context": "any", "target_version": "17.1.0",
            "target_image_digest": "sha256:abc", "environment_lock_sha256": "lock",
            "ground_truth_label": "VULNERABLE", "challenge_ids": ["dbSchemaChallenge"],
            "rationale": "source", "validation_basis": "official_source", "source_ref": "routes/search.ts",
            "rule_id": "exact",
        }
        alert = {
            "alert_id": "1", "app": "juice_shop", "alert_name": "SQL Injection",
            "zap_cwe_id": "CWE-89", "url": "http://juice-shop:3000/rest/products/search",
            "evidence": "apple'", "param": "q", "plugin_id": "40018",
            "request_method": "GET", "authentication_context": "authenticated",
            "target_version": "17.1.0", "target_image_digest": "sha256:abc",
            "environment_lock_sha256": "lock",
        }
        self.assertEqual(match_alert_to_ground_truth(alert, [rule])["ground_truth_label"], "VULNERABLE")
        inferred = match_alert_to_ground_truth({**alert, "target_version": "unknown"}, [rule])
        self.assertEqual(inferred["ground_truth_label"], "VULNERABLE")
        self.assertEqual(inferred["version_match_basis"], "immutable_provenance")
        self.assertEqual(
            match_alert_to_ground_truth(
                {**alert, "target_version": "unknown", "environment_lock_sha256": "different"},
                [rule],
            )["ground_truth_label"],
            "UNMAPPED",
        )
        for field, value in (("request_method", "POST"), ("param", "id"), ("plugin_id", "40019"), ("target_version", "18.0.0")):
            mismatch = match_alert_to_ground_truth({**alert, field: value}, [rule])
            self.assertEqual(mismatch["ground_truth_label"], "UNMAPPED")
            if field == "target_version":
                self.assertEqual(mismatch["version_match_basis"], "conflict")

    @classmethod
    def setUpClass(cls):
        cls.gt = load_ground_truth(LAB_DIR / "ground_truth.csv")
        cls.rules = load_match_rules(LAB_DIR / "ground_truth_match_rules.csv", cls.gt)
        cls.alerts = list(FIXTURE_ALERTS)
        cls.pipeline_alerts = [
            {
                "alert_id": index,
                **alert,
                "zap_cwe_id": normalize_cwe_id(alert.get("cweid", "")),
            }
            for index, alert in enumerate(cls.alerts)
        ]

    def test_provider_key_catalogue_is_normalized_to_challenge_id(self):
        self.assertEqual(len(self.gt), 225)
        self.assertIn("provider_key", self.gt.columns)
        self.assertIn("challenge_id", self.gt.columns)
        self.assertTrue((self.gt["provider_key"] == self.gt["challenge_id"]).all())
        self.assertNotIn("WG-SQLI", set(self.gt["challenge_id"]))
        self.assertTrue((self.gt["ground_truth_label"] == "VULNERABLE").all())

    def test_seed_rules_map_expected_current_dataset_counts(self):
        audit = build_match_audit(self.pipeline_alerts, self.rules)
        counts = audit["ground_truth_label"].value_counts().to_dict()
        self.assertEqual(counts.get("VULNERABLE", 0), 0)
        self.assertEqual(counts["NOT_VULNERABLE"], 2)
        self.assertEqual(counts["UNMAPPED"], 1)
        self.assertEqual(len(audit), len(self.pipeline_alerts))

    def test_unlinked_csp_and_clickjacking_alerts_are_unmapped(self):
        header_alerts = [
            alert for alert in self.pipeline_alerts
            if alert["alert_name"] in {
                "Content Security Policy (CSP) Header Not Set",
            }
        ]
        self.assertEqual(len(header_alerts), 1)
        for alert in header_alerts:
            match = match_alert_to_ground_truth(alert, self.rules)
            self.assertEqual(match["ground_truth_label"], "UNMAPPED")

    def test_overlapping_rules_are_rejected_for_an_alert(self):
        alert = next(alert for alert in self.pipeline_alerts if alert["alert_name"] == "Cross-Domain Misconfiguration")
        base_rule = {
            "app": "juice_shop",
            "zap_alert_name": "cross-domain misconfiguration",
            "zap_cwe_id": "CWE-264",
            "url_pattern": None,
            "evidence_pattern": None,
            "ground_truth_label": "NOT_VULNERABLE",
            "challenge_ids": [],
            "rationale": "test",
        }
        rules = [
            {"rule_id": "one", **base_rule},
            {"rule_id": "two", **base_rule},
        ]
        with self.assertRaisesRegex(ValueError, "overlapping rules"):
            match_alert_to_ground_truth(alert, rules)

    def test_unknown_challenge_reference_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            rules_path = Path(temp_dir) / "rules.csv"
            with open(rules_path, "w", newline="", encoding="utf-8") as file:
                writer = csv.writer(file)
                writer.writerow([
                    "rule_id", "app", "zap_alert_name", "zap_cwe_id",
                    "url_regex", "evidence_regex", "ground_truth_label",
                    "challenge_ids", "rationale",
                ])
                writer.writerow([
                    "bad", "vulnerable_app", "SQL Injection", "CWE-89", "", "",
                    "VULNERABLE", "DOES-NOT-EXIST", "test",
                ])
            with self.assertRaisesRegex(ValueError, "unknown challenge IDs"):
                load_match_rules(rules_path, self.gt)


class PairedDesignAndMetricTests(unittest.TestCase):
    @staticmethod
    def _record(strategy, alert_id, **overrides):
        record = {
            "prompt_strategy": strategy,
            "alert_id": alert_id,
            "app": "vulnerable_app",
            "alert_name": "SQL Injection",
            "zap_cwe_id": "CWE-89",
            "url": "http://vulnerable-app:9090/VulnerableApp/SQLInjectionVulnerability/LEVEL_1",
            "evidence": "",
            "parsed_successfully": True,
            "predicted_vulnerable": True,
        }
        record.update(overrides)
        return record

    def test_paired_design_requires_identical_alert_ids(self):
        records = []
        for strategy in PROMPT_STRATEGIES:
            records.append(self._record(strategy, 0))
        records[-1]["alert_id"] = 1
        with self.assertRaisesRegex(ValueError, "Paired design violation"):
            validate_paired_design(records)

    def test_paired_design_rejects_duplicate_alert_ids(self):
        records = [self._record(strategy, 0) for strategy in PROMPT_STRATEGIES]
        records.append(self._record("zero_shot", 0))
        with self.assertRaisesRegex(ValueError, "Duplicate alert_id"):
            validate_paired_design(records)

    def test_macro_and_weighted_f1_are_exposed(self):
        frame = pd.DataFrame({
            "ground_truth": [True, True, False, False],
            "predicted_is_vuln": [True, False, True, False],
        })
        metrics = compute_metrics(frame)
        self.assertEqual(metrics["f1_macro"], 0.5)
        self.assertEqual(metrics["f1_weighted"], 0.5)

    def test_complete_pair_filter_excludes_an_alert_from_every_strategy(self):
        records = []
        for strategy in PROMPT_STRATEGIES:
            records.extend([
                self._record(strategy, 0, predicted_vulnerable=False),
                self._record(strategy, 1, predicted_vulnerable=True),
            ])
        for record in records:
            if record["prompt_strategy"] == "cot" and record["alert_id"] == 1:
                record["parsed_successfully"] = False
                record["predicted_vulnerable"] = None

        grouped = validate_paired_design(records)
        quality = calculate_parse_quality(grouped, {"0", "1"})
        self.assertEqual(quality["complete_paired_alert_ids"], ["0"])
        self.assertEqual(quality["excluded_paired_alert_ids"], ["1"])
        self.assertEqual(quality["below_threshold_strategies"], ["cot"])

    def test_identical_correctness_vectors_have_deterministic_statistics(self):
        correctness = {strategy: [1, 0, 1, 1] for strategy in PROMPT_STRATEGIES}
        self.assertEqual(friedman_test(correctness), {"statistic": 0.0, "p_value": 1.0})
        for result in wilcoxon_posthoc(correctness):
            self.assertEqual(result["statistic"], 0.0)
            self.assertEqual(result["raw_p_value"], 1.0)
            self.assertEqual(result["bonferroni_p_value"], 1.0)
        self.assertEqual(mcnemar_test([1, 0], [1, 0])["p_value"], 1.0)


class EndToEndEvaluationTests(unittest.TestCase):
    def test_parse_quality_gate_writes_diagnostics_then_blocks_metrics(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_dir = Path(temp_dir)
            ground_truth_path = temp_dir / "ground_truth.csv"
            rules_path = temp_dir / "rules.csv"
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
                    "positive", "vulnerable_app", "SQL Injection", "CWE-89", "^/VulnerableApp/SQLInjectionVulnerability/LEVEL_1$",
                    "", "VULNERABLE", "VULNERABLE_APP-SQLI", "positive fixture",
                ])
                writer.writerow([
                    "negative", "juice_shop", "Timestamp Disclosure - Unix", "CWE-497",
                    "", "", "NOT_VULNERABLE", "", "negative fixture",
                ])

            alerts = [
                {
                    "alert_id": 0, "app": "vulnerable_app", "alert_name": "SQL Injection",
                    "zap_cwe_id": "CWE-89", "url": "http://vulnerable-app:9090/VulnerableApp/SQLInjectionVulnerability/LEVEL_1",
                    "evidence": "database error",
                },
                {
                    "alert_id": 1, "app": "juice_shop",
                    "alert_name": "Timestamp Disclosure - Unix", "zap_cwe_id": "CWE-497",
                    "url": "http://juice-shop:3000/app.js", "evidence": "1666666667",
                },
            ]
            records = []
            for strategy in PROMPT_STRATEGIES:
                for alert in alerts:
                    failed = strategy == "cot" and alert["alert_id"] == 0
                    records.append({
                        "run_id": "parse-gate", "model": "test/model",
                        "alert_id": alert["alert_id"], **alert,
                        "prompt_strategy": strategy,
                        "parsed_successfully": not failed,
                        "predicted_vulnerable": None if failed else alert["alert_id"] == 0,
                    })
            paths = {
                "pipeline": temp_dir / "pipeline.json",
                "evaluation": temp_dir / "evaluation.csv",
                "audit": temp_dir / "audit.csv",
                "statistics": temp_dir / "statistics.csv",
                "summary": temp_dir / "summary.json",
                "unmapped": temp_dir / "unmapped.json",
                "diagnostics": temp_dir / "parse_diagnostics.json",
            }
            with open(paths["pipeline"], "w", encoding="utf-8") as file:
                json.dump(records, file)

            with self.assertRaisesRegex(ValueError, "parse success below"):
                evaluate_pipeline_results(
                    pipeline_results_path=paths["pipeline"],
                    ground_truth_path=ground_truth_path,
                    rules_path=rules_path,
                    evaluation_output_path=paths["evaluation"],
                    audit_output_path=paths["audit"],
                    statistical_output_path=paths["statistics"],
                    summary_output_path=paths["summary"],
                    unmapped_output_path=paths["unmapped"],
                    parse_diagnostics_output_path=paths["diagnostics"],
                )

            with open(paths["summary"], encoding="utf-8") as file:
                summary = json.load(file)
            with open(paths["diagnostics"], encoding="utf-8") as file:
                diagnostics = json.load(file)
            self.assertEqual(summary["evaluation_status"], "blocked_parse_quality")
            self.assertEqual(summary["parse_quality"]["excluded_paired_alert_ids"], ["0"])
            self.assertEqual(
                diagnostics["evaluation_parse_quality"]["complete_paired_alert_ids"], ["1"]
            )
            self.assertTrue(paths["audit"].exists())
            self.assertTrue(paths["unmapped"].exists())
            self.assertFalse(paths["evaluation"].exists())
            self.assertFalse(paths["statistics"].exists())

    def test_negative_only_crosswalk_writes_audit_then_blocks_metrics(self):
        alerts = list(FIXTURE_ALERTS)
        records = []
        for strategy in PROMPT_STRATEGIES:
            for alert_id, alert in enumerate(alerts):
                records.append({
                    "run_id": "test-run",
                    "run_timestamp_utc": "2026-07-16T09:00:00+00:00",
                    "model": "test/model",
                    "nim_base_url": "https://integrate.api.nvidia.com/v1",
                    "temperature": 0.0,
                    "max_completion_tokens": 4096,
                    "source_alert_count": len(alerts),
                    "alert_count": len(alerts),
                    "alert_id": alert_id,
                    "app": alert["app"],
                    "alert_name": alert["alert_name"],
                    "zap_cwe_id": normalize_cwe_id(alert["cweid"]),
                    "url": alert["url"],
                    "evidence": alert["evidence"],
                    "prompt_strategy": strategy,
                    "parsed_successfully": True,
                    "json_repaired": False,
                    "predicted_vulnerable": False,
                })

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_dir = Path(temp_dir)
            pipeline_path = temp_dir / "pipeline_results.json"
            evaluation_path = temp_dir / "evaluation_results.csv"
            audit_path = temp_dir / "ground_truth_match_audit.csv"
            statistical_path = temp_dir / "statistical_results.csv"
            summary_path = temp_dir / "evaluation_summary.json"
            unmapped_path = temp_dir / "unmapped_alerts.json"
            with open(pipeline_path, "w", encoding="utf-8") as file:
                json.dump(records, file)

            with self.assertRaisesRegex(ValueError, "zero mapped VULNERABLE alerts"):
                evaluate_pipeline_results(
                    pipeline_results_path=pipeline_path,
                    ground_truth_path=LAB_DIR / "ground_truth.csv",
                    rules_path=LAB_DIR / "ground_truth_match_rules.csv",
                    evaluation_output_path=evaluation_path,
                    audit_output_path=audit_path,
                    statistical_output_path=statistical_path,
                    summary_output_path=summary_path,
                    unmapped_output_path=unmapped_path,
                )

            audit = pd.read_csv(audit_path)
            with open(summary_path, encoding="utf-8") as file:
                summary = json.load(file)
            self.assertEqual(summary["evaluation_status"], "blocked_no_mapped_vulnerable_alerts")
            self.assertEqual(summary["coverage"]["actual_vulnerable"], 0)
            self.assertEqual(len(audit), len(alerts))
            self.assertFalse(evaluation_path.exists())
            self.assertFalse(statistical_path.exists())
            self.assertTrue(unmapped_path.exists())


if __name__ == "__main__":
    unittest.main()
