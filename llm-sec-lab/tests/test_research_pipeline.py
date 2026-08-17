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
    def test_authentication_pilot_resume_reuses_only_lock_matched_completed_attempt(self):
        with tempfile.TemporaryDirectory() as tmp:
            attempt_dir = Path(tmp) / "attempt_1_unauthenticated"
            attempt_dir.mkdir()
            alert = self.alert(0)
            alert.update({
                "cluster_id": "saved-cluster",
                "authentication_context": "unauthenticated",
                "environment_lock_sha256": "lock-sha",
            })
            artifacts = {
                "raw_zap_alerts.json": [],
                "raw_alerts.json": [alert],
                "scan_metadata.json": {"target": {
                    "app": "juice_shop",
                    "scan_profile": "final",
                    "target_status": "completed",
                    "authentication": {"enabled": False},
                }},
                "ground_truth_match_audit.json": {},
            }
            for name, value in artifacts.items():
                (attempt_dir / name).write_text(json.dumps(value), encoding="utf-8")

            loaded = pipeline._load_authentication_pilot_attempt(
                attempt_dir, "off", {"environment_lock_sha256": "lock-sha"}, [], [],
            )
            self.assertEqual(len(loaded["alerts"]), 1)
            with self.assertRaisesRegex(RuntimeError, "Environment lock mismatch"):
                pipeline._load_authentication_pilot_attempt(
                    attempt_dir, "off", {"environment_lock_sha256": "different"}, [], [],
                )

    def test_authentication_gate_passes_only_for_new_validated_positive(self):
        alert = self.alert(0, name="SQL Injection", cwe="89", evidence="apple'", url="http://juice-shop:3000/rest/products/search")
        alert.update({
            "cluster_id": "auth", "plugin_id": "40018", "pluginid": "40018",
            "request_method": "GET", "param": "q", "authentication_context": "authenticated",
        })
        rule = {
            "rule_id": "source", "rule_status": "validated", "app": "juice_shop",
            "zap_alert_name": "sql injection", "zap_cwe_id": "CWE-89",
            "url_pattern": __import__("re").compile(r"^/rest/products/search$"),
            "evidence_pattern": __import__("re").compile(r"apple'"),
            "negative_evidence_pattern": None, "param_pattern": __import__("re").compile(r"^q$"),
            "plugin_id": "40018", "request_method": "GET", "authentication_context": "any",
            "target_version": "", "target_image_digest": "", "environment_lock_sha256": "",
            "ground_truth_label": "VULNERABLE", "provider_key": "dbSchemaChallenge",
            "rationale": "source backed", "validation_basis": "official_source",
            "source_ref": "routes/search.ts",
        }
        passed = pipeline.authentication_pilot_decision([], [alert], [rule], [])
        failed = pipeline.authentication_pilot_decision([alert], [alert], [rule], [])
        self.assertEqual(passed["decision"], "authenticated")
        self.assertTrue(passed["gate_passed"])
        self.assertEqual(failed["decision"], "unauthenticated")
        self.assertFalse(failed["gate_passed"])

    def test_final_scan_eligibility_requires_completed_active_and_discovery(self):
        complete_attempt = {
            "attempt": 1,
            "stages": {
                "broad_active_scan": {"status": "completed", "progress": 100},
                "discovery_validation": {"status": "completed"},
            },
        }
        status = {"targets": {
            app: {"status": "completed", "selected_attempt": 1, "attempts": [complete_attempt]}
            for app in pipeline.TARGETS
        }}
        self.assertTrue(pipeline.final_scan_eligibility(status)["triage_eligible"])
        status["targets"]["juice_shop"]["attempts"][0]["stages"]["broad_active_scan"] = {"status": "stalled"}
        self.assertFalse(pipeline.final_scan_eligibility(status)["triage_eligible"])

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
            "vulnerability_probability": 0.2 if not confirmed else 0.9,
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

    @staticmethod
    def scan_result(alerts, status="completed", warnings=None):
        return {
            "alerts": alerts,
            "raw_zap_alerts": [],
            "metadata": {"warnings": list(warnings or []), "target_status": status},
            "status": status,
        }

    @staticmethod
    def write_mock_report(_alerts, path, scan_profile="benchmark"):
        Path(path).write_text(json.dumps({"scan_profile": scan_profile}), encoding="utf-8")

    def test_dedup_key_is_prompt_complete_and_reexpands_source_order(self):
        alerts = [self.alert(0), self.alert(1), self.alert(2, evidence="1700000001")]
        clusters = pipeline.deduplicate_alerts(alerts)
        self.assertEqual(len(clusters), 2)
        self.assertEqual(clusters[0]["alert_ids"], ["0", "1"])
        self.assertEqual(clusters[0]["dedup_cluster_size"], 2)
        self.assertNotEqual(clusters[0]["cluster_id"], clusters[1]["cluster_id"])

    def test_dedup_separates_http_methods_and_zap_plugins(self):
        base = self.alert(0)
        same = {**base, "alert_id": "1"}
        different_method = {**base, "alert_id": "2", "request_method": "POST"}
        different_plugin = {**base, "alert_id": "3", "pluginid": "40026", "plugin_id": "40026"}
        clusters = pipeline.deduplicate_alerts([base, same, different_method, different_plugin])
        self.assertEqual(len(clusters), 3)
        self.assertEqual(clusters[0]["dedup_cluster_size"], 2)

    def test_ground_truth_candidates_require_official_route_method_cwe_and_evidence(self):
        alert = pipeline.canonical_alert({
            "app": "vulnerable_app",
            "alert_name": "Cross Site Scripting (Reflected)",
            "url": "http://target/VulnerableApp/XSSWithHtmlTagInjection/LEVEL_1?input=zap_seed",
            "cweid": "79",
            "request_method": "GET",
            "pluginid": "40012",
            "attack": "<script>alert(1)</script>",
            "evidence": "<script>alert(1)</script>",
            "evidence_source": "native",
        }, 0)
        candidates = pipeline.build_ground_truth_candidates([alert])
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0]["status"], "candidate")
        self.assertEqual(candidates[0]["plugin_id"], "40012")
        self.assertEqual(
            candidates[0]["route_pattern"],
            r"^/VulnerableApp/XSSWithHtmlTagInjection/LEVEL_1$",
        )
        self.assertTrue(candidates[0]["provider_key"].startswith("VULNERABLE_APP-REFLECTED_XSS"))
        self.assertIsNotNone(__import__("re").compile(candidates[0]["evidence_pattern"]).search(alert["evidence"]))
        self.assertEqual(
            pipeline.build_ground_truth_candidates([{**alert, "request_method": "POST"}]),
            [],
        )
        self.assertEqual(
            pipeline.build_ground_truth_candidates([{**alert, "evidence": ""}]),
            [],
        )

    def test_bundled_examples_are_generic_balanced_and_source_cited(self):
        rows = json.loads(pipeline._load_examples())
        self.assertEqual(len(rows), 4)
        self.assertEqual(
            sum(row["vulnerability_probability"] >= pipeline.VERDICT_THRESHOLD for row in rows),
            2,
        )
        self.assertTrue(all(set(pipeline.ASSESSMENT_SCHEMA["required"]) <= set(row) for row in rows))
        self.assertTrue(all("confidence" not in row and "confirmed" not in row for row in rows))
        self.assertTrue(all(row["source_url"].startswith("https://") for row in rows))
        self.assertFalse(any("vulnerable_app" in json.dumps(row).lower() for row in rows))

    def test_few_shot_prompt_formats_json_examples_without_extra_variables(self):
        message = pipeline._prompt("few_shot", pipeline._load_examples()).invoke({
            "alert_name": "Example", "risk": "Low", "zap_confidence": "Low",
            "url": "https://target.invalid/", "description": "description",
            "evidence": "evidence", "param": "", "attack": "",
        })
        self.assertIn("Generic development examples", message.to_string())

    def test_every_strategy_uses_the_exact_probability_contract(self):
        examples = pipeline._load_examples()
        payload = {
            "alert_name": "Example", "risk": "Low", "zap_confidence": "Low",
            "url": "https://target.invalid/", "description": "description",
            "evidence": "evidence", "param": "", "attack": "",
        }
        for strategy in pipeline.STRATEGIES:
            prompt = pipeline._prompt(strategy, examples).invoke(payload).to_string()
            self.assertIn(pipeline.PROBABILITY_EVENT, prompt)
            self.assertIn("only the supplied alert fields", prompt)
            self.assertIn("do not return a confirmed or confidence field", prompt)

    def test_probability_contract_derives_boolean_at_half_threshold(self):
        below = json.loads(self.assessment(False))
        below["vulnerability_probability"] = 0.4999
        boundary = {**below, "vulnerability_probability": 0.5}
        parsed_below = pipeline._parse_json(json.dumps(below))
        parsed_boundary = pipeline._parse_json(json.dumps(boundary))
        self.assertFalse(parsed_below["confirmed"])
        self.assertTrue(parsed_boundary["confirmed"])
        self.assertEqual(parsed_boundary["verdict_threshold"], 0.5)
        self.assertEqual(
            parsed_boundary["probability_contract_version"],
            pipeline.PROBABILITY_CONTRACT_VERSION,
        )

    def test_probability_contract_rejects_legacy_or_model_generated_verdict_fields(self):
        for field, value in (("confidence", 0.9), ("confirmed", True)):
            assessment = json.loads(self.assessment(True))
            assessment[field] = value
            with self.assertRaisesRegex(ValueError, "Unexpected assessment fields"):
                pipeline._parse_json(json.dumps(assessment))

    def test_probability_contract_rejects_invalid_probability_values(self):
        for value in (-0.01, 1.01, "0.9", True):
            assessment = json.loads(self.assessment(True))
            assessment["vulnerability_probability"] = value
            with self.assertRaisesRegex(ValueError, "Invalid vulnerability_probability"):
                pipeline._parse_json(json.dumps(assessment))

    def test_repair_prompt_replays_strategy_alert_and_malformed_response(self):
        examples = pipeline._load_examples()
        payload = {
            "alert_name": "SQL Injection marker",
            "risk": "High marker",
            "zap_confidence": "Medium marker",
            "url": "https://target.invalid/route-marker",
            "description": "description marker",
            "evidence": "database evidence marker",
            "param": "parameter marker",
            "attack": "attack marker",
            "malformed_response": '{"vulnerability_type":"SQL Injection","cwe_id":',
            "parse_error": "No JSON object found marker",
        }
        for strategy in pipeline.STRATEGIES:
            message = pipeline._repair_prompt(strategy, examples).invoke(payload).to_string()
            self.assertIn(pipeline.STRATEGY_INSTRUCTIONS[strategy], message)
            for value in payload.values():
                self.assertIn(value, message)
            if strategy == "few_shot":
                self.assertIn("Generic development examples", message)
            else:
                self.assertNotIn("Generic development examples", message)

    def test_strategy_preserving_repair_keeps_sql_injection_family_and_cwe(self):
        alert = self.alert(
            0,
            name="SQL Injection",
            cwe="89",
            evidence="database syntax error",
            url="http://target.invalid/search?id=1%27",
        )
        repaired = json.dumps({
            "vulnerability_probability": 0.9,
            "vulnerability_type": "SQL Injection", "cwe_id": "CWE-89",
            "severity": "High", "rationale": "Database evidence supports SQL injection.",
            "recommended_action": "Use parameterized queries.",
            "cvss_av": "N", "cvss_ac": "L", "cvss_pr": "N",
            "cvss_ui": "N", "cvss_s": "U",
        })
        calls = []

        def invoke(_chain, payload, **kwargs):
            calls.append((payload, kwargs["request_kind"]))
            if kwargs["request_kind"] == "primary":
                return '{"vulnerability_probability":0.9,"vulnerability_type":"SQL Injection","cwe_id":'
            return repaired

        chain = FakeChain()
        with (
            patch.object(pipeline, "_model", return_value=object()),
            patch.object(pipeline, "_prompt", return_value=FakePrompt(chain)),
            patch.object(pipeline, "_repair_chain", return_value=chain),
            patch.object(pipeline, "_invoke", side_effect=invoke),
            patch.object(pipeline, "load_automated_rules") as load_rules,
        ):
            records, diagnostics = pipeline.triage_clusters(
                pipeline.deduplicate_alerts([alert]), "fixture",
            )

        self.assertFalse(load_rules.called)
        self.assertEqual(len(calls), len(pipeline.STRATEGIES) * 2)
        self.assertTrue(all(row["vulnerability_type"] == "SQL Injection" for row in records))
        self.assertTrue(all(row["cwe_id"] == "CWE-89" for row in records))
        self.assertTrue(all(row["vulnerability_probability"] == 0.9 for row in records))
        self.assertTrue(all(row["confirmed"] for row in records))
        self.assertTrue(all(row["repair_attempted"] for row in records))
        self.assertTrue(all(row["repaired"] for row in records))
        self.assertTrue(all(row["assessment_origin"] == "strategy_preserving_repair" for row in records))
        repair_payloads = [payload for payload, kind in calls if kind != "primary"]
        self.assertTrue(all("SQL Injection" in payload["malformed_response"] for payload in repair_payloads))
        self.assertTrue(all(payload["parse_error"] for payload in repair_payloads))
        for strategy in pipeline.STRATEGIES:
            stats = diagnostics["strategies"][strategy]
            self.assertEqual(stats["initial_parse_success_rate"], 0.0)
            self.assertEqual(stats["repair_success_rate"], 1.0)
            self.assertEqual(stats["final_parse_success_rate"], 1.0)

    def test_exhausted_repair_request_fails_closed_without_stopping_triage(self):
        chain = FakeChain()

        def invoke(_chain, _payload, **kwargs):
            if kwargs["request_kind"] == "primary":
                return "not json"
            raise RuntimeError("repair unavailable")

        with (
            patch.object(pipeline, "_model", return_value=object()),
            patch.object(pipeline, "_prompt", return_value=FakePrompt(chain)),
            patch.object(pipeline, "_repair_chain", return_value=chain),
            patch.object(pipeline, "_invoke", side_effect=invoke),
        ):
            records, diagnostics = pipeline.triage_clusters(
                pipeline.deduplicate_alerts([self.alert(0)]), "fixture",
            )

        self.assertEqual(len(records), len(pipeline.STRATEGIES))
        self.assertTrue(all(row["confirmed"] is None for row in records))
        self.assertTrue(all(row["vulnerability_probability"] is None for row in records))
        self.assertTrue(all(row["assessment_origin"] == "unparsed" for row in records))
        self.assertTrue(all("repair unavailable" in row["repair_parse_error"] for row in records))
        self.assertEqual(
            sum(row["unrecoverable_failures"] for row in diagnostics["strategies"].values()),
            len(pipeline.STRATEGIES),
        )

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

    def test_remote_disconnect_is_retried(self):
        chain = FakeChain()
        disconnect = pipeline.RequestsConnectionError(
            "Connection aborted",
            pipeline.RemoteDisconnected("Remote end closed connection without response"),
        )
        with (
            patch.object(
                chain,
                "invoke",
                side_effect=[disconnect, self.assessment()],
                create=True,
            ) as invoke,
            patch.object(pipeline.time, "sleep") as sleep,
        ):
            result = pipeline._invoke(chain, {"alert": "fixture"})

        self.assertEqual(result, self.assessment())
        self.assertEqual(invoke.call_count, 2)
        sleep.assert_called_once_with(pipeline.NVIDIA_RETRY_BASE_SECONDS)

    def test_failed_triage_resumes_checkpoint_and_repairs_partial_tail(self):
        alert = self.alert(0)
        run_id = "run_checkpoint_fixture"
        chain = FakeChain()
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory) / run_id
            with (
                patch.object(pipeline, "_model", return_value=object()),
                patch.object(pipeline, "_prompt", return_value=FakePrompt(chain)),
                patch.object(pipeline, "_repair_chain", return_value=chain),
                patch.object(
                    pipeline,
                    "_invoke",
                    side_effect=[self.assessment(), RuntimeError("forced stop")],
                ),
            ):
                with self.assertRaisesRegex(RuntimeError, "forced stop"):
                    pipeline.run_automated([alert], run_dir, "benchmark")

            checkpoint = run_dir / pipeline.TRIAGE_CHECKPOINT_FILE
            state = json.loads(
                (run_dir / pipeline.TRIAGE_CHECKPOINT_STATE_FILE).read_text(encoding="utf-8")
            )
            manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(state["completed_assessment_count"], 1)
            self.assertEqual(state["version"], 3)
            self.assertEqual(manifest["probability_contract"], pipeline.PROBABILITY_CONTRACT)
            self.assertEqual(
                state["triage_protocol_sha256"],
                manifest["triage_protocol_sha256"],
            )
            self.assertEqual(len(checkpoint.read_text(encoding="utf-8").splitlines()), 1)
            with checkpoint.open("a", encoding="utf-8") as file:
                file.write('{"partial"')

            with (
                patch.object(pipeline, "_model", return_value=object()),
                patch.object(pipeline, "_prompt", return_value=FakePrompt(chain)),
                patch.object(pipeline, "_repair_chain", return_value=chain),
                patch.object(pipeline, "_invoke", return_value=self.assessment()) as invoke,
            ):
                result = pipeline.resume_and_run(run_dir)

            self.assertTrue(result["resumed"])
            self.assertEqual(invoke.call_count, 2)
            self.assertTrue((run_dir / "pipeline_results.json").is_file())
            self.assertFalse(checkpoint.exists())
            self.assertFalse((run_dir / pipeline.TRIAGE_CHECKPOINT_STATE_FILE).exists())
            records = json.loads((run_dir / "pipeline_results.json").read_text(encoding="utf-8"))
            self.assertEqual(len(records), len(pipeline.STRATEGIES))
            diagnostics = json.loads(
                (run_dir / "parse_diagnostics.json").read_text(encoding="utf-8")
            )
            self.assertEqual(diagnostics["metadata"]["resumed_assessment_count"], 1)

    def test_checkpoint_rejects_protocol_fingerprint_mismatch(self):
        clusters = pipeline.deduplicate_alerts([self.alert(0)])
        protocol_sha256 = pipeline._triage_protocol_sha256()
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory)
            state = pipeline._checkpoint_state(
                clusters, "fixture", pipeline.MODEL, 0, protocol_sha256,
            )
            state["triage_protocol_sha256"] = "old-protocol"
            (run_dir / pipeline.TRIAGE_CHECKPOINT_STATE_FILE).write_text(
                json.dumps(state), encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "start a new triage run"):
                pipeline._load_triage_checkpoint(
                    run_dir, clusters, "fixture", pipeline.MODEL, protocol_sha256,
                )

    def test_checkpoint_rejects_phase_one_version(self):
        clusters = pipeline.deduplicate_alerts([self.alert(0)])
        protocol_sha256 = pipeline._triage_protocol_sha256()
        state = pipeline._checkpoint_state(
            clusters, "fixture", pipeline.MODEL, 0, protocol_sha256,
        )
        state["version"] = 2
        with self.assertRaisesRegex(ValueError, "start a new triage run"):
            pipeline._validate_checkpoint_state(
                state, clusters, "fixture", pipeline.MODEL, protocol_sha256,
            )

    def test_scan_only_writes_scan_artifacts_without_triage(self):
        alerts = [{"app": "juice_shop", "alert_name": "Example", "url": "http://juice-shop:3000/"}]
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory) / "scan-only"
            with (
                patch.object(pipeline, "wait_for_zap"),
                patch.object(pipeline, "start_fresh_zap_session"),
                patch.object(pipeline, "reset_scan_metadata"),
                patch.object(
                    pipeline, "run_scan",
                    side_effect=[self.scan_result(alerts), self.scan_result([])],
                ) as scan,
                patch.object(pipeline, "save_scan_report", side_effect=self.write_mock_report) as save_report,
                patch.object(pipeline, "run_automated") as triage,
            ):
                result = pipeline.scan_and_run(run_dir, "baseline", scan_only=True)
                raw_alerts_exists = (run_dir / "raw_alerts.json").exists()
                candidates_exists = (run_dir / "ground_truth_candidates.csv").exists()

        self.assertTrue(result["scan_only"])
        self.assertEqual(scan.call_count, 2)
        save_report.assert_called_once()
        triage.assert_not_called()
        self.assertTrue(raw_alerts_exists)
        self.assertTrue(candidates_exists)

    def test_scan_order_is_vulnerable_app_then_juice_shop(self):
        alerts = [{"app": "vulnerable_app", "alert_name": "Example", "url": "http://target/"}]
        with tempfile.TemporaryDirectory() as directory:
            with (
                patch.object(pipeline, "wait_for_zap"),
                patch.object(pipeline, "start_fresh_zap_session"),
                patch.object(pipeline, "reset_scan_metadata"),
                patch.object(
                    pipeline, "run_scan",
                    side_effect=[self.scan_result(alerts), self.scan_result([])],
                ) as scan,
                patch.object(pipeline, "save_scan_report", side_effect=self.write_mock_report),
            ):
                pipeline.scan_and_run(Path(directory) / "ordered", "benchmark", scan_only=True)
        self.assertEqual([call.args[1] for call in scan.call_args_list], ["vulnerable_app", "juice_shop"])

    def test_controlled_timeout_finishes_with_warning_and_reusable_aggregate(self):
        alerts = [{"app": "vulnerable_app", "alert_name": "Example", "url": "http://target/"}]
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory) / "warnings"
            with (
                patch.object(pipeline, "wait_for_zap"),
                patch.object(pipeline, "start_fresh_zap_session"),
                patch.object(pipeline, "reset_scan_metadata"),
                patch.object(pipeline, "run_scan", side_effect=[
                    self.scan_result(alerts, "completed_with_warnings", ["client_spider"]),
                    self.scan_result([]),
                ]),
                patch.object(pipeline, "save_scan_report", side_effect=self.write_mock_report),
            ):
                result = pipeline.scan_and_run(run_dir, "benchmark", scan_only=True)
            status = json.loads((run_dir / "scan_status.json").read_text(encoding="utf-8"))
            aggregate_exists = (run_dir / "raw_alerts.json").exists()

        self.assertEqual(result["exit_code"], 0)
        self.assertEqual(result["scan_status"], "completed_with_warnings")
        self.assertEqual(status["status"], "completed_with_warnings")
        self.assertTrue(aggregate_exists)

    def test_hard_failure_retries_once_then_uses_successful_attempt(self):
        vulnerable_alert = {
            "app": "vulnerable_app", "alert_name": "Example", "url": "http://target/vuln",
        }
        juice_alert = {
            "app": "juice_shop", "alert_name": "Example", "url": "http://target/juice",
        }
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory) / "retry"
            with (
                patch.object(pipeline, "wait_for_zap"),
                patch.object(pipeline, "start_fresh_zap_session") as fresh,
                patch.object(pipeline, "reset_scan_metadata"),
                patch.object(pipeline, "collect_alerts", return_value=([], [])),
                patch.object(
                    pipeline, "run_scan",
                    side_effect=[
                        RuntimeError("connection lost"),
                        self.scan_result([vulnerable_alert]),
                        self.scan_result([juice_alert]),
                    ],
                ) as scan,
                patch.object(pipeline, "save_scan_report", side_effect=self.write_mock_report),
            ):
                result = pipeline.scan_and_run(run_dir, "benchmark", scan_only=True)
            status = json.loads((run_dir / "scan_status.json").read_text(encoding="utf-8"))
            aggregate = json.loads((run_dir / "raw_alerts.json").read_text(encoding="utf-8"))

        self.assertEqual(result["exit_code"], 0)
        self.assertEqual(fresh.call_count, 3)
        self.assertEqual([call.args[1] for call in scan.call_args_list], [
            "vulnerable_app", "vulnerable_app", "juice_shop",
        ])
        self.assertEqual(status["targets"]["vulnerable_app"]["selected_attempt"], 2)
        self.assertEqual(len(status["targets"]["vulnerable_app"]["attempts"]), 2)
        self.assertEqual(len(aggregate), 2)

    def test_retry_exhaustion_continues_other_target_and_blocks_aggregate(self):
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory) / "partial"
            with (
                patch.object(pipeline, "wait_for_zap"),
                patch.object(pipeline, "start_fresh_zap_session") as fresh,
                patch.object(pipeline, "reset_scan_metadata"),
                patch.object(pipeline, "collect_alerts", return_value=([], [])),
                patch.object(pipeline, "run_scan", side_effect=RuntimeError("ZAP unavailable")) as scan,
                patch.object(pipeline, "save_scan_report") as report,
                patch.object(pipeline, "run_automated") as triage,
            ):
                result = pipeline.scan_and_run(run_dir, "benchmark", scan_only=True)
            status = json.loads((run_dir / "scan_status.json").read_text(encoding="utf-8"))
            partial_exists = (run_dir / "partial_raw_alerts.json").exists()
            aggregate_exists = (run_dir / "raw_alerts.json").exists()

        self.assertEqual(result["exit_code"], 1)
        self.assertEqual(result["failed_targets"], ["vulnerable_app", "juice_shop"])
        self.assertEqual(scan.call_count, 4)
        self.assertEqual(fresh.call_count, 4)
        self.assertEqual(status["status"], "partial_failed")
        self.assertTrue(partial_exists)
        self.assertFalse(aggregate_exists)
        report.assert_not_called()
        triage.assert_not_called()

    def test_keyboard_interrupt_checkpoints_current_target(self):
        recovered = [{
            "app": "vulnerable_app", "alert_name": "Recovered", "url": "http://target/",
        }]
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory) / "interrupted"
            with (
                patch.object(pipeline, "TARGET_RETRIES", 0),
                patch.object(pipeline, "wait_for_zap"),
                patch.object(pipeline, "start_fresh_zap_session"),
                patch.object(pipeline, "reset_scan_metadata"),
                patch.object(pipeline, "run_scan", side_effect=KeyboardInterrupt),
                patch.object(pipeline, "collect_alerts", return_value=([{"alert": "Recovered"}], recovered)),
            ):
                with self.assertRaises(KeyboardInterrupt):
                    pipeline.scan_and_run(run_dir, "benchmark", scan_only=True)
            status = json.loads((run_dir / "scan_status.json").read_text(encoding="utf-8"))
            partial_exists = (run_dir / "partial_raw_alerts.json").exists()
            checkpoint_exists = (
                run_dir / "targets" / "vulnerable_app" / "attempt_1" / "raw_alerts.json"
            ).exists()

        self.assertEqual(status["status"], "interrupted")
        self.assertTrue(partial_exists)
        self.assertTrue(checkpoint_exists)

    def test_reuse_excludes_salvaged_and_partial_runs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            complete = root / "run_20260101T000000Z"
            partial = root / "run_20260102T000000Z"
            salvaged = root / "run_20260103T000000Z_salvaged"
            for path in (complete, partial, salvaged):
                path.mkdir()
                (path / "raw_alerts.json").write_text("[]", encoding="utf-8")
            (complete / "scan_status.json").write_text('{"status":"completed_with_warnings"}', encoding="utf-8")
            (partial / "scan_status.json").write_text('{"status":"partial_failed"}', encoding="utf-8")
            (salvaged / "salvage_manifest.json").write_text("{}", encoding="utf-8")

            self.assertEqual(pipeline.latest_raw_alerts_path(root), complete / "raw_alerts.json")
            with self.assertRaisesRegex(ValueError, "not a complete two-app run"):
                pipeline.resolve_reuse_source(root, str(partial))

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

    def test_unknown_target_version_binds_only_through_immutable_provenance(self):
        rule = {
            **self.rule(),
            "target_version": "26.04",
            "target_image_digest": "sha256:immutable",
            "environment_lock_sha256": "lock-sha",
        }
        alert = {
            **self.alert(0),
            "cluster_id": "cluster",
            "target_version": "unknown",
            "target_image_digest": "sha256:immutable",
            "environment_lock_sha256": "lock-sha",
        }

        self.assertTrue(pipeline._rule_matches(rule, alert))
        self.assertEqual(
            pipeline.build_match_audit([alert], [rule], [])[0]["version_match_basis"],
            "immutable_provenance",
        )
        self.assertFalse(pipeline._rule_matches(
            rule, {**alert, "environment_lock_sha256": "different"},
        ))

        exact = {**alert, "target_version": "26.04"}
        self.assertEqual(
            pipeline.build_match_audit([exact], [rule], [])[0]["version_match_basis"],
            "exact",
        )

        conflict = {**alert, "target_version": "27.01"}
        conflict_audit = pipeline.build_match_audit([conflict], [rule], [])[0]
        self.assertEqual(conflict_audit["ground_truth_label"], "UNMAPPED")
        self.assertEqual(conflict_audit["version_match_basis"], "conflict")

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
                "confirmed": False, "vulnerability_probability": 0.2,
                "probability_contract_version": pipeline.PROBABILITY_CONTRACT_VERSION,
                "verdict_threshold": pipeline.VERDICT_THRESHOLD,
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
            triage = pipeline.pd.read_csv(run_dir / "triage_results.csv")
            self.assertEqual(list(triage.columns), list(pipeline.TRIAGE_RESULT_COLUMNS))
            self.assertEqual(len(triage), len(pipeline.STRATEGIES))
            self.assertEqual(set(triage["duplicate_count"]), {1})

    def test_initial_only_sensitivity_excludes_repaired_cluster_from_every_strategy(self):
        cluster_specs = [
            ("positive_initial", "0", True, "initial"),
            ("positive_repaired", "1", True, "initial"),
            ("negative_initial", "2", False, "initial"),
        ]
        records = []
        for strategy in pipeline.STRATEGIES:
            for cluster_id, alert_id, confirmed, default_origin in cluster_specs:
                origin = (
                    "strategy_preserving_repair"
                    if strategy == "zero_shot" and cluster_id == "positive_repaired"
                    else default_origin
                )
                records.append({
                    "alert_id": alert_id, "cluster_id": cluster_id, "app": "juice_shop",
                    "alert_name": "SQL Injection" if confirmed else "Timestamp Disclosure - Unix",
                    "zap_cwe_id": "CWE-89" if confirmed else "CWE-497",
                    "url": f"http://target.invalid/{cluster_id}", "evidence": "fixture",
                    "pluginid": "40018", "risk": "High" if confirmed else "Low",
                    "zap_confidence": "Low" if confirmed else "High",
                    "prompt_strategy": strategy, "parsed_successfully": True,
                    "initial_parsed_successfully": origin == "initial",
                    "repair_attempted": origin != "initial", "repaired": origin != "initial",
                    "assessment_origin": origin, "confirmed": confirmed,
                    "vulnerability_probability": 0.9 if confirmed else 0.1,
                    "probability_contract_version": pipeline.PROBABILITY_CONTRACT_VERSION,
                    "verdict_threshold": pipeline.VERDICT_THRESHOLD,
                })
        audit = [
            {
                "alert_id": alert_id, "cluster_id": cluster_id, "app": "juice_shop",
                "alert_name": "SQL Injection" if confirmed else "Timestamp Disclosure - Unix",
                "zap_cwe_id": "CWE-89" if confirmed else "CWE-497",
                "ground_truth_label": "VULNERABLE" if confirmed else "NOT_VULNERABLE",
                "matched_rule_id": f"rule_{cluster_id}", "rule_status": "validated",
                "provider_key": "provider" if confirmed else "", "rationale": "fixture",
                "validation_basis": "fixture", "source_ref": "fixture",
                "expected_vulnerability_family": "sql_injection" if confirmed else "",
                "compatible_llm_cwe_ids": ("CWE-89",) if confirmed else (),
            }
            for cluster_id, alert_id, confirmed, _origin in cluster_specs
        ]
        diagnostics = {"strategies": {
            strategy: {
                "parse_success_rate": 1.0,
                "initial_parse_success_rate": 2 / 3 if strategy == "zero_shot" else 1.0,
            }
            for strategy in pipeline.STRATEGIES
        }}
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory)
            with (
                patch.object(pipeline, "load_automated_rules", return_value=([], [])),
                patch.object(pipeline, "build_match_audit", return_value=audit),
                patch.object(pipeline, "write_validation_coverage_artifacts", return_value={}),
            ):
                summary = pipeline.evaluate_post_triage(run_dir, records, diagnostics)

            operational = {row["prompt_strategy"]: row for row in summary["metrics"]}
            sensitivity = summary["initial_only_sensitivity"]
            sensitivity_metrics = {
                row["prompt_strategy"]: row for row in sensitivity["metrics"]
            }
            self.assertTrue(all(row["sample_count"] == 3 for row in operational.values()))
            self.assertTrue(all(abs(row["brier_score"] - 0.01) < 1e-12 for row in operational.values()))
            self.assertTrue(all(row["sample_count"] == 2 for row in sensitivity_metrics.values()))
            self.assertEqual(sensitivity["eligible_cluster_count"], 2)
            self.assertEqual(sensitivity["excluded_cluster_count"], 1)
            self.assertEqual(sensitivity["repaired_cluster_count_by_strategy"]["zero_shot"], 1)
            self.assertEqual(summary["probability_contract"]["operational_calibration_status"], "available")
            self.assertEqual(sensitivity["calibration_status"], "available")
            self.assertTrue((run_dir / "initial_only_evaluation_results.csv").is_file())
            self.assertEqual(
                operational["zero_shot"]["semantic_label_universe"],
                sensitivity_metrics["zero_shot"]["semantic_label_universe"],
            )
            self.assertEqual(
                operational["zero_shot"]["semantic_label_universe"],
                ["SAFE", "sql_injection|CWE-89", "OTHER_POSITIVE"],
            )

    def test_legacy_confidence_is_readable_but_excluded_from_calibration(self):
        cluster_specs = [("positive", "0", True), ("negative", "1", False)]
        records = []
        for strategy in pipeline.STRATEGIES:
            for cluster_id, alert_id, confirmed in cluster_specs:
                records.append({
                    "alert_id": alert_id, "cluster_id": cluster_id, "app": "juice_shop",
                    "alert_name": "SQL Injection" if confirmed else "Timestamp Disclosure - Unix",
                    "zap_cwe_id": "CWE-89" if confirmed else "CWE-497",
                    "url": f"http://target.invalid/{cluster_id}", "evidence": "fixture",
                    "pluginid": "40018", "risk": "High" if confirmed else "Low",
                    "prompt_strategy": strategy, "parsed_successfully": True,
                    "assessment_origin": "initial", "confirmed": confirmed,
                    "confidence": 0.99 if confirmed else 0.01,
                })
        audit = [
            {
                "alert_id": alert_id, "cluster_id": cluster_id, "app": "juice_shop",
                "alert_name": "SQL Injection" if confirmed else "Timestamp Disclosure - Unix",
                "zap_cwe_id": "CWE-89" if confirmed else "CWE-497",
                "ground_truth_label": "VULNERABLE" if confirmed else "NOT_VULNERABLE",
                "matched_rule_id": f"rule_{cluster_id}", "rule_status": "validated",
                "provider_key": "provider" if confirmed else "", "rationale": "fixture",
                "validation_basis": "fixture", "source_ref": "fixture",
                "expected_vulnerability_family": "sql_injection" if confirmed else "",
                "compatible_llm_cwe_ids": ("CWE-89",) if confirmed else (),
            }
            for cluster_id, alert_id, confirmed in cluster_specs
        ]
        diagnostics = {"strategies": {
            strategy: {"parse_success_rate": 1.0, "initial_parse_success_rate": 1.0}
            for strategy in pipeline.STRATEGIES
        }}
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory)
            with (
                patch.object(pipeline, "load_automated_rules", return_value=([], [])),
                patch.object(pipeline, "build_match_audit", return_value=audit),
                patch.object(pipeline, "write_validation_coverage_artifacts", return_value={}),
            ):
                summary = pipeline.evaluate_post_triage(run_dir, records, diagnostics)
            triage = pipeline.pd.read_csv(run_dir / "triage_results.csv")
            calibration = (run_dir / "calibration_results.csv").read_text(encoding="utf-8")

        self.assertEqual(
            summary["probability_contract"]["operational_calibration_status"],
            "unavailable_legacy_undefined_confidence",
        )
        self.assertTrue(all(row["brier_score"] is None for row in summary["metrics"]))
        self.assertTrue(all(row["ece"] is None for row in summary["metrics"]))
        self.assertTrue(triage["llm_vulnerability_probability"].isna().all())
        self.assertEqual(set(triage["legacy_llm_confidence"]), {0.99, 0.01})
        self.assertEqual(calibration, "\n")

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
        self.assertTrue(all(row["vulnerability_probability"] is None for row in records))
        self.assertTrue(all(row["assessment_origin"] == "unparsed" for row in records))
        self.assertTrue(all(row["repair_attempted"] for row in records))
        self.assertTrue(all(not row["repaired"] for row in records))
        self.assertEqual(sum(row["unrecoverable_failures"] for row in diagnostics["strategies"].values()), 3)


if __name__ == "__main__":
    unittest.main()
