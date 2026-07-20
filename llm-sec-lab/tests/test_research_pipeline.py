import json
import io
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

import research_pipeline as pipeline


class FakePrompt:
    def __init__(self, chain):
        self.chain = chain

    def __or__(self, _other):
        return self.chain


class FakeChain:
    def __or__(self, _other):
        return self


class AutomatedResearchPipelineTests(unittest.TestCase):
    def alert(self, alert_id, *, name="Timestamp Disclosure - Unix", cwe="497", evidence="1700000000", url="http://juice-shop:3000/app.js"):
        return pipeline.canonical_alert({
            "app": "juice_shop", "alert_name": name, "cweid": cwe,
            "risk": "Low", "confidence": "Low", "url": url,
            "description": "Scanner description", "evidence": evidence,
            "param": "", "attack": "", "pluginid": "10096",
        }, alert_id)

    @staticmethod
    def assessment(confirmed=False):
        return json.dumps({
            "confirmed": confirmed, "confidence": 0.2 if not confirmed else 0.9,
            "vulnerability_type": "Information Disclosure", "cwe_id": "CWE-497",
            "severity": "Low", "rationale": "Evidence reviewed.",
            "recommended_action": "Investigate", "cvss_av": "N", "cvss_ac": "L",
            "cvss_pr": "N", "cvss_ui": "N", "cvss_s": "U",
        })

    def rule(self, *, label="NOT_VULNERABLE", status="validated", evidence=None, negative=None, provider=""):
        return {
            "rule_id": "rule", "rule_status": status, "app": "juice_shop",
            "zap_alert_name": "timestamp disclosure - unix", "zap_cwe_id": "CWE-497",
            "url_pattern": None, "evidence_pattern": evidence,
            "negative_evidence_pattern": negative, "ground_truth_label": label,
            "provider_key": provider, "rationale": "fixture rule",
        }

    def test_dedup_key_is_prompt_complete_and_reexpands_source_order(self):
        alerts = [self.alert(0), self.alert(1), self.alert(2, evidence="1700000001")]
        clusters = pipeline.deduplicate_alerts(alerts)
        self.assertEqual(len(clusters), 2)
        self.assertEqual(clusters[0]["alert_ids"], ["0", "1"])
        self.assertEqual(clusters[0]["dedup_cluster_size"], 2)
        self.assertNotEqual(clusters[0]["cluster_id"], clusters[1]["cluster_id"])

    def test_bundled_examples_are_generic_balanced_and_source_cited(self):
        rows = json.loads(pipeline._load_examples())
        self.assertEqual(len(rows), 4)
        self.assertEqual(sum(row["confirmed"] for row in rows), 2)
        self.assertTrue(all(row["source_url"].startswith("https://") for row in rows))
        self.assertFalse(any("vulnerable_app" in json.dumps(row).lower() for row in rows))

    def test_few_shot_prompt_formats_json_examples_without_extra_variables(self):
        message = pipeline._prompt("few_shot", pipeline._load_examples()).invoke({
            "alert_name": "Example", "risk": "Low", "zap_confidence": "Low",
            "url": "https://target.invalid/", "description": "description",
            "evidence": "evidence", "param": "", "attack": "",
        })
        self.assertIn("Generic development examples", message.to_string())

    def test_triage_processes_every_cluster_without_loading_ground_truth(self):
        clusters = pipeline.deduplicate_alerts([self.alert(0), self.alert(1, evidence="different")])
        chain = FakeChain()
        with (
            patch.object(pipeline, "_model", return_value=object()),
            patch.object(pipeline, "_prompt", return_value=FakePrompt(chain)),
            patch.object(pipeline, "_repair_chain", return_value=chain),
            patch.object(pipeline, "_invoke", return_value=self.assessment()) as invoke,
            patch.object(pipeline, "load_automated_rules") as load_rules,
        ):
            records, diagnostics = pipeline.triage_clusters(clusters, "fixture")
        self.assertEqual(invoke.call_count, len(clusters) * len(pipeline.STRATEGIES))
        self.assertFalse(load_rules.called)
        self.assertEqual(len(records), 2 * len(pipeline.STRATEGIES))
        self.assertTrue(all(row["parsed_successfully"] for row in records))
        self.assertEqual(set(diagnostics["strategies"]), set(pipeline.STRATEGIES))

    def test_triage_reports_assessment_progress_request_count_and_eta(self):
        clusters = pipeline.deduplicate_alerts([self.alert(0)])
        chain = FakeChain()
        output = io.StringIO()
        with (
            patch.object(pipeline, "_model", return_value=object()),
            patch.object(pipeline, "_prompt", return_value=FakePrompt(chain)),
            patch.object(pipeline, "_repair_chain", return_value=chain),
            patch.object(chain, "invoke", return_value=self.assessment(), create=True),
            redirect_stdout(output),
        ):
            pipeline.triage_clusters(clusters, "fixture")

        progress = output.getvalue()
        self.assertIn("Assessment 1/3 started (0.0%)", progress)
        self.assertIn("strategy=zero_shot", progress)
        self.assertIn("Request #1: primary (attempt 1)", progress)
        self.assertIn("Assessment 3/3 complete (100.0%)", progress)
        self.assertIn("eta=0s", progress)
        self.assertIn("requests=3", progress)

    def test_scan_only_writes_scan_artifacts_without_triage(self):
        alerts = [{"app": "juice_shop", "alert_name": "Example", "url": "http://juice-shop:3000/"}]
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory) / "scan-only"
            with (
                patch.object(pipeline, "wait_for_zap"),
                patch.object(pipeline, "start_fresh_zap_session"),
                patch.object(pipeline, "reset_scan_metadata"),
                patch.object(pipeline, "run_scan", side_effect=[alerts, []]) as scan,
                patch.object(pipeline, "save_scan_report") as save_report,
                patch.object(pipeline, "run_automated") as triage,
            ):
                result = pipeline.scan_and_run(run_dir, "baseline", scan_only=True)
                raw_alerts_exists = (run_dir / "raw_alerts.json").exists()

        self.assertTrue(result["scan_only"])
        self.assertEqual(scan.call_count, 2)
        save_report.assert_called_once()
        triage.assert_not_called()
        self.assertTrue(raw_alerts_exists)

    def test_scan_order_is_vulnerable_app_then_juice_shop(self):
        alerts = [{"app": "vulnerable_app", "alert_name": "Example", "url": "http://target/"}]
        with tempfile.TemporaryDirectory() as directory:
            with (
                patch.object(pipeline, "wait_for_zap"),
                patch.object(pipeline, "start_fresh_zap_session"),
                patch.object(pipeline, "reset_scan_metadata"),
                patch.object(pipeline, "run_scan", side_effect=[alerts, []]) as scan,
                patch.object(pipeline, "save_scan_report"),
            ):
                pipeline.scan_and_run(Path(directory) / "ordered", "benchmark", scan_only=True)
        self.assertEqual([call.args[1] for call in scan.call_args_list], ["vulnerable_app", "juice_shop"])

    def test_benchmark_run_writes_request_response_without_triage(self):
        alerts = [{
            "app": "vulnerable_app", "alert_name": "SQL Injection", "url": "http://target/VulnerableApp/a",
            "cweid": "89", "wascid": "19", "request_method": "GET",
        }]
        response = {"coverage": 1.0, "detected": 1, "totalExpected": 1}
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory) / "benchmark"
            with (
                patch.object(pipeline, "wait_for_zap"),
                patch.object(pipeline, "start_fresh_zap_session"),
                patch.object(pipeline, "reset_scan_metadata"),
                patch.object(pipeline, "run_scan", return_value=alerts),
                patch.object(pipeline, "save_scan_report"),
                patch.object(pipeline, "submit_vulnerable_app_benchmark", return_value=response) as submit,
                patch.object(pipeline, "run_automated") as triage,
            ):
                result = pipeline.benchmark_vulnerable_app(run_dir)
            request = json.loads((run_dir / "vulnerable_app_benchmark_request.json").read_text())
            saved_response = json.loads((run_dir / "vulnerable_app_benchmark_response.json").read_text())
        self.assertEqual(result["benchmark"], response)
        self.assertEqual(request["findings"][0]["method"], "GET")
        self.assertEqual(saved_response, response)
        submit.assert_called_once()
        triage.assert_not_called()

    def test_reuse_source_selects_latest_or_explicit_artifact_without_zap(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            older = root / "run_20260101T000000Z"
            newer = root / "run_20260102T000000Z"
            older.mkdir()
            newer.mkdir()
            (older / "raw_alerts.json").write_text("[]")
            (newer / "raw_alerts.json").write_text("[]")
            self.assertEqual(pipeline.resolve_reuse_source(root), newer / "raw_alerts.json")
            self.assertEqual(pipeline.resolve_reuse_source(root, str(older)), older / "raw_alerts.json")
            with patch.object(pipeline, "run_automated", return_value={"ok": True}) as automated:
                result = pipeline.reuse_and_run(root / "new-triage", "benchmark", "fixture", root, str(older))
        self.assertEqual(result, {"ok": True})
        self.assertEqual(automated.call_args.kwargs["source_raw_alerts"], older / "raw_alerts.json")

    def test_rule_requires_app_name_cwe_route_and_evidence(self):
        rule = self.rule(evidence=__import__("re").compile(r"1700000000", __import__("re").I))
        alert = self.alert(0)
        self.assertTrue(pipeline._rule_matches(rule, alert))
        self.assertFalse(pipeline._rule_matches(rule, {**alert, "zap_cwe_id": "CWE-89"}))
        self.assertFalse(pipeline._rule_matches(rule, {**alert, "alert_name": "SQL Injection"}))
        self.assertFalse(pipeline._rule_matches(rule, {**alert, "evidence": "different"}))

    def test_candidate_match_is_auditable_but_not_metric_label(self):
        alert = {**self.alert(0), "cluster_id": "cluster"}
        audit = pipeline.build_match_audit([alert], [], [self.rule(status="candidate")])
        self.assertEqual(audit[0]["ground_truth_label"], "PROVISIONAL")
        self.assertEqual(audit[0]["rule_status"], "provisional")

    def test_zero_positive_run_completes_with_audit_artifacts(self):
        alert = {**self.alert(0), "cluster_id": "cluster"}
        records = []
        for strategy in pipeline.STRATEGIES:
            records.append({
                "alert_id": "0", "cluster_id": "cluster", "app": "juice_shop",
                "alert_name": alert["alert_name"], "zap_cwe_id": "CWE-497", "url": alert["url"],
                "evidence": alert["evidence"], "pluginid": "10096", "risk": "Low",
                "prompt_strategy": strategy, "parsed_successfully": True,
                "confirmed": False, "confidence": 0.2,
            })
        diagnostics = {"strategies": {strategy: {"parse_success_rate": 1.0} for strategy in pipeline.STRATEGIES}}
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory)
            with patch.object(pipeline, "load_automated_rules", return_value=([self.rule()], [])):
                summary = pipeline.evaluate_post_triage(run_dir, records, diagnostics)
            self.assertEqual(summary["evaluation_status"], "insufficient_validated_positives")
            self.assertTrue((run_dir / "ground_truth_match_audit.csv").exists())
            self.assertTrue((run_dir / "unmapped_alerts.json").exists())
            self.assertTrue((run_dir / "evaluation_summary.json").exists())
            self.assertTrue((run_dir / "evaluation_results.csv").exists())

    def test_parse_failure_never_becomes_safe_prediction(self):
        clusters = pipeline.deduplicate_alerts([self.alert(0)])
        chain = FakeChain()
        with (
            patch.object(pipeline, "_model", return_value=object()),
            patch.object(pipeline, "_prompt", return_value=FakePrompt(chain)),
            patch.object(pipeline, "_repair_chain", return_value=chain),
            patch.object(pipeline, "_invoke", return_value="not json"),
        ):
            records, diagnostics = pipeline.triage_clusters(clusters, "fixture")
        self.assertTrue(all(row["confirmed"] is None for row in records))
        self.assertEqual(sum(row["unrecoverable_failures"] for row in diagnostics["strategies"].values()), 3)


if __name__ == "__main__":
    unittest.main()
