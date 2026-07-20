import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import zap_scanner


class ZapScannerConfigurationTests(unittest.TestCase):
    def test_thorough_active_scan_configuration_removes_caps(self):
        with patch.object(zap_scanner, "zap_api", return_value={"scanners": []}) as api:
            zap_scanner.configure_active_scan()

        calls = [call.args[:3] + tuple(sorted(call.kwargs.items())) for call in api.call_args_list]
        self.assertIn(
            ("ascan", "action", "setOptionMaxRuleDurationInMins", ("Integer", 0)),
            calls,
        )
        self.assertIn(
            ("ascan", "action", "setOptionMaxScanDurationInMins", ("Integer", 0)),
            calls,
        )
        self.assertIn(
            ("ascan", "action", "setOptionMaxAlertsPerRule", ("Integer", 0)),
            calls,
        )
        self.assertTrue(any(
            call.args[:3] == ("ascan", "action", "enableAllScanners")
            for call in api.call_args_list
        ))
        self.assertTrue(any(
            call.args[:3] == ("ascan", "action", "setOptionAddQueryParam")
            and call.kwargs.get("Boolean") == "true"
            for call in api.call_args_list
        ))

    def test_benchmark_profile_applies_high_low_to_every_non_noise_rule(self):
        scanners = [
            {"id": "6", "name": "Path Traversal"},
            {"id": str(zap_scanner.NOISE_SCANNER_ID), "name": "User Agent Fuzzer"},
        ]
        with patch.object(zap_scanner, "zap_api", return_value={"scanners": scanners}) as api:
            zap_scanner.configure_active_scan("benchmark")
        configured_ids = {
            call.kwargs.get("id") for call in api.call_args_list
            if call.args[:3] == ("ascan", "action", "setScannerAttackStrength")
        }
        threshold_ids = {
            call.kwargs.get("id") for call in api.call_args_list
            if call.args[:3] == ("ascan", "action", "setScannerAlertThreshold")
            and call.kwargs.get("alertThreshold") == "LOW"
        }
        self.assertEqual(configured_ids, {"6"})
        self.assertEqual(threshold_ids, {"6"})
        policy_calls = [
            call for call in api.call_args_list
            if call.args[:3] in {
                ("ascan", "action", "enableAllScanners"),
                ("ascan", "action", "disableScanners"),
                ("ascan", "action", "setScannerAttackStrength"),
                ("ascan", "action", "setScannerAlertThreshold"),
                ("ascan", "view", "scanners"),
            }
        ]
        self.assertTrue(policy_calls)
        self.assertTrue(all(
            call.kwargs.get("scanPolicyName") == zap_scanner.PROFILE_SCAN_POLICIES["benchmark"]
            for call in policy_calls
        ))

    def test_targeted_profile_raises_relevant_rules_and_disables_user_agent_fuzzer(self):
        with patch.object(zap_scanner, "zap_api", return_value={"scanners": []}) as api:
            snapshot = zap_scanner.configure_active_scan("targeted")

        self.assertEqual(snapshot, [])
        calls = [call for call in api.call_args_list]
        self.assertTrue(any(
            call.args[:3] == ("ascan", "action", "disableScanners")
            and call.kwargs.get("ids") == str(zap_scanner.NOISE_SCANNER_ID)
            for call in calls
        ))
        high_rule_ids = {
            call.kwargs.get("id")
            for call in calls
            if call.args[:3] == ("ascan", "action", "setScannerAttackStrength")
            and call.kwargs.get("attackStrength") == "HIGH"
        }
        self.assertEqual(high_rule_ids, {str(value) for value in zap_scanner.TARGETED_SCANNER_IDS})
        policy_calls = [
            call for call in calls
            if call.args[:3] in {
                ("ascan", "action", "enableScanners"),
                ("ascan", "action", "disableScanners"),
                ("ascan", "action", "setScannerAttackStrength"),
                ("ascan", "view", "scanners"),
            }
        ]
        self.assertTrue(all(
            call.kwargs.get("scanPolicyName") == zap_scanner.PROFILE_SCAN_POLICIES["targeted"]
            for call in policy_calls
        ))

    def test_targeted_follow_up_scans_use_the_selected_profile_policy(self):
        with (
            patch.object(zap_scanner, "zap_api", return_value={"scan": "17"}) as api,
            patch.object(zap_scanner, "wait_for_progress"),
        ):
            scans = zap_scanner.run_targeted_active_scans(
                "http://juice-shop:3000",
                "juice_shop",
                {"id": "3"},
                None,
                "Custom Targeted Policy",
            )

        scan_calls = [
            call for call in api.call_args_list
            if call.args[:3] == ("ascan", "action", "scan")
        ]
        self.assertEqual(len(scan_calls), len(zap_scanner.TARGETED_REQUESTS["juice_shop"]))
        self.assertTrue(all(
            call.kwargs.get("scanPolicyName") == "Custom Targeted Policy"
            for call in scan_calls
        ))
        self.assertEqual([scan["scan_id"] for scan in scans], ["17"])

    def test_juice_shop_seed_requests_cover_api_routes(self):
        with patch.object(zap_scanner, "zap_api") as api:
            summary = zap_scanner.seed_juice_shop_requests("http://juice-shop:3000")

        urls = [call.kwargs["url"] for call in api.call_args_list]
        self.assertEqual(len(urls), len(zap_scanner.JUICE_SHOP_SEED_PATHS))
        self.assertIn("http://juice-shop:3000/rest/products/search?q=apple", urls)
        self.assertIn("http://juice-shop:3000/rest/products/1/reviews", urls)
        self.assertIn("http://juice-shop:3000/ftp/legal.md", urls)
        self.assertEqual(summary, {
            "attempted": len(zap_scanner.JUICE_SHOP_SEED_PATHS),
            "seeded": len(zap_scanner.JUICE_SHOP_SEED_PATHS),
            "failed": 0,
            "failed_urls": [],
            "error": "",
        })

    def test_juice_shop_seed_failures_are_reported(self):
        failed_url = "http://juice-shop:3000/ftp/legal.md"

        def access_url(_component, _kind, _endpoint, **params):
            if params["url"] == failed_url:
                raise zap_scanner.requests.RequestException("unavailable")
            return {"Result": "OK"}

        with patch.object(zap_scanner, "zap_api", side_effect=access_url):
            summary = zap_scanner.seed_juice_shop_requests("http://juice-shop:3000")

        self.assertEqual(summary["failed"], 1)
        self.assertEqual(summary["failed_urls"], [failed_url])
        self.assertEqual(summary["seeded"], len(zap_scanner.JUICE_SHOP_SEED_PATHS) - 1)

    def test_juice_shop_ftp_stays_in_context_and_noisy_paths_are_active_scan_exclusions(self):
        def context_api(_component, _kind, endpoint, **_params):
            if endpoint == "contextList":
                return {"contextList": []}
            if endpoint == "newContext":
                return {"contextId": "7"}
            return {"Result": "OK"}

        with patch.object(zap_scanner, "zap_api", side_effect=context_api) as api:
            context = zap_scanner.create_context("http://juice-shop:3000", "juice_shop")

        self.assertEqual(context, {"id": "7", "name": "juice_shop_dast"})
        context_exclusions = [
            call.kwargs["regex"] for call in api.call_args_list
            if call.args[:3] == ("context", "action", "excludeFromContext")
        ]
        self.assertFalse(any("ftp" in pattern for pattern in context_exclusions))
        self.assertTrue(any("/juice-shop/" in pattern for pattern in context_exclusions))

        with patch.object(zap_scanner, "zap_api") as exclusion_api:
            patterns = zap_scanner.configure_active_scan_exclusions("juice_shop")
        self.assertEqual(
            exclusion_api.call_args_list[0].args[:3],
            ("ascan", "action", "clearExcludedFromScan"),
        )
        applied = [
            call.kwargs["regex"] for call in exclusion_api.call_args_list
            if call.args[:3] == ("ascan", "action", "excludeFromScan")
        ]
        self.assertEqual(applied, patterns)
        self.assertTrue(all(pattern.startswith("http://juice-shop:3000/") for pattern in applied))
        self.assertFalse(any("ftp" in pattern for pattern in applied))

    def test_active_scan_exclusions_are_cleared_for_each_target(self):
        with patch.object(zap_scanner, "zap_api") as api:
            patterns = zap_scanner.configure_active_scan_exclusions("vulnerable_app")
        self.assertEqual(patterns, [])
        api.assert_called_once_with("ascan", "action", "clearExcludedFromScan")

    def test_ajax_spider_browser_count_is_configurable_and_positive(self):
        with (
            patch.object(zap_scanner, "AJAX_SPIDER_BROWSERS", 4),
            patch.object(zap_scanner, "AJAX_SPIDER_MAX_DURATION_MINS", 7),
            patch.object(zap_scanner, "zap_api") as api,
        ):
            zap_scanner.configure_ajax_spider()
        self.assertTrue(any(
                call.args[:3] == ("ajaxSpider", "action", "setOptionNumberOfBrowsers")
                and call.kwargs.get("Integer") == 4
            for call in api.call_args_list
        ))
        self.assertTrue(any(
            call.args[:3] == ("ajaxSpider", "action", "setOptionMaxDuration")
            and call.kwargs.get("Integer") == 7
            for call in api.call_args_list
        ))
        with (
            patch.object(zap_scanner, "AJAX_SPIDER_BROWSERS", 0),
            patch.object(zap_scanner, "zap_api") as invalid_api,
        ):
            with self.assertRaisesRegex(ValueError, "must be at least 1"):
                zap_scanner.configure_ajax_spider()
        invalid_api.assert_not_called()
        with (
            patch.object(zap_scanner, "AJAX_SPIDER_MAX_DURATION_MINS", -1),
            patch.object(zap_scanner, "zap_api") as invalid_duration_api,
        ):
            with self.assertRaisesRegex(ValueError, "cannot be negative"):
                zap_scanner.configure_ajax_spider()
        invalid_duration_api.assert_not_called()

    def test_vulnerable_app_targeted_request_does_not_duplicate_context_path(self):
        target_url = "http://vulnerable-app:9090/VulnerableApp"
        request_spec = zap_scanner.TARGETED_REQUESTS["vulnerable_app"][0]
        self.assertEqual(f"{target_url}{request_spec['url']}", target_url + "/")

    def test_missing_required_path_stops_non_comprehensive_scan(self):
        with patch.object(zap_scanner, "get_target_urls", return_value=["http://vulnerable-app:9090/"]):
            with self.assertRaisesRegex(RuntimeError, "required DAST paths were not discovered"):
                zap_scanner.verify_discovery("http://vulnerable-app:9090/VulnerableApp", "vulnerable_app")

    def test_missing_required_juice_shop_route_stops_scan(self):
        urls = [
            f"http://juice-shop:3000{path}"
            for path in zap_scanner.TARGET_PROFILES["juice_shop"]["required_paths"]
            if path != "/ftp/legal.md"
        ]
        with patch.object(zap_scanner, "get_target_urls", return_value=urls):
            with self.assertRaisesRegex(RuntimeError, "/ftp/legal.md"):
                zap_scanner.verify_discovery("http://juice-shop:3000", "juice_shop")

    def test_user_scoped_spider_response_uses_its_action_name(self):
        self.assertEqual(
            zap_scanner.scan_id_from_response({"scanAsUser": "17"}, "scanAsUser", "vulnerable_app"),
            "17",
        )

    def test_missing_scan_identifier_has_a_clear_error(self):
        with self.assertRaisesRegex(RuntimeError, "did not return a scan ID"):
                zap_scanner.scan_id_from_response({"Result": "OK"}, "scanAsUser", "vulnerable_app")

    def test_alert_request_method_is_read_from_zap_history(self):
        with patch.object(
            zap_scanner, "zap_api",
            return_value={"requestHeader": "POST /VulnerableApp/example HTTP/1.1\r\nHost: target"},
        ):
            self.assertEqual(zap_scanner._request_method("12"), "POST")
        with patch.object(
            zap_scanner, "zap_api",
            return_value={"message": {"requestHeader": "GET /rest/products HTTP/1.1\r\nHost: target"}},
        ):
            self.assertEqual(zap_scanner._request_method("13"), "GET")
        with patch.object(zap_scanner, "zap_api", return_value={"message": "malformed"}):
            self.assertEqual(zap_scanner._request_method("14"), "")
        self.assertEqual(zap_scanner._request_method(None), "")
        with patch.object(zap_scanner, "zap_api", side_effect=zap_scanner.requests.RequestException("gone")):
            self.assertEqual(zap_scanner._request_method("12"), "")

    def test_benchmark_payload_preserves_method_and_deduplicates(self):
        alerts = [
            {"app": "vulnerable_app", "url": "http://target/VulnerableApp/a", "cweid": "89", "wascid": "19", "request_method": "POST"},
            {"app": "vulnerable_app", "url": "http://target/VulnerableApp/a", "cweid": "89", "wascid": "19", "request_method": "POST"},
            {"app": "juice_shop", "url": "http://target/", "cweid": "79"},
        ]
        payload = zap_scanner.build_vulnerable_app_benchmark_payload(alerts)
        self.assertEqual(payload["findings"], [{
            "url": "http://target/VulnerableApp/a", "cwe": "CWE-89", "wascId": "19", "method": "POST",
        }])

    def test_vulnerable_app_catalogue_seeds_get_post_and_xml_history(self):
        catalogue = [{
            "Name": "Example",
            "Detailed Information": [
                {"Level": "LEVEL_1", "HttpMethod": "GET"},
                {"Level": "LEVEL_2", "HttpMethod": "POST"},
            ],
        }, {
            "Name": "XXEVulnerability",
            "Detailed Information": [{"Level": "LEVEL_1", "HttpMethod": "POST"}],
        }]
        fake_response = type("Response", (), {"json": lambda self: catalogue, "raise_for_status": lambda self: None})()
        with (
            patch.object(zap_scanner.session, "get", return_value=fake_response),
            patch.object(zap_scanner, "zap_api") as api,
        ):
            summary = zap_scanner.seed_vulnerable_app_requests("http://vulnerable-app:9090/VulnerableApp")
        self.assertEqual(summary, {
            "attempted": 3,
            "seeded": 3,
            "failed": 0,
            "failed_urls": [],
            "error": "",
        })
        raw_requests = [call.kwargs["request"] for call in api.call_args_list]
        self.assertTrue(any("GET /VulnerableApp/Example/LEVEL_1?zap_seed=1" in request for request in raw_requests))
        self.assertTrue(any("POST /VulnerableApp/Example/LEVEL_2" in request and "username=zap_seed" in request for request in raw_requests))
        self.assertTrue(any("Content-Type: application/xml" in request and "<zapSeed>" in request for request in raw_requests))

    def test_scan_report_includes_effective_configuration_and_alerts(self):
        alerts = [{
            "app": "juice_shop",
            "alert_name": "Example Alert",
            "risk": "Low",
            "confidence": "Medium",
            "url": "http://juice-shop:3000/example",
            "cweid": "79",
            "request_method": "GET",
        }]
        with tempfile.TemporaryDirectory() as temporary_directory:
            report_path = Path(temporary_directory) / "zap_scan_report.json"
            zap_scanner.reset_scan_metadata()
            zap_scanner.save_scan_report(alerts, str(report_path))
            report = json.loads(report_path.read_text(encoding="utf-8"))

        self.assertEqual(report["alerts"], alerts)
        self.assertEqual(report["scanner_configuration"]["active_scan_max_alerts_per_rule"], 0)
        self.assertEqual(
            report["scanner_configuration"]["ajax_spider_number_of_browsers"],
            zap_scanner.AJAX_SPIDER_BROWSERS,
        )
        self.assertEqual(report["quality_summary"]["request_method_populated_count"], 1)
        self.assertEqual(report["quality_summary"]["request_method_missing_count"], 0)
        self.assertEqual(report["alert_family_counts"][0]["count"], 1)

    def test_scan_report_preserves_crawler_and_final_coverage_metadata(self):
        metadata = {
            "app": "juice_shop",
            "crawler_discovered_url_count": 1,
            "crawler_discovered_urls": ["http://juice-shop:3000/"],
            "discovered_url_count": 2,
            "discovered_urls": [
                "http://juice-shop:3000/",
                "http://juice-shop:3000/ftp/legal.md",
            ],
            "active_scan_exclusions": ["http://juice-shop:3000/assets(?:/.*)?"],
            "required_paths": ["/ftp/legal.md"],
            "benchmark_route_seeds": {
                "attempted": 1, "seeded": 1, "failed": 0,
                "failed_urls": [], "error": "",
            },
        }
        with tempfile.TemporaryDirectory() as temporary_directory:
            report_path = Path(temporary_directory) / "report.json"
            zap_scanner.reset_scan_metadata()
            zap_scanner.SCAN_METADATA.append(metadata)
            zap_scanner.save_scan_report([], str(report_path), "benchmark")
            report = json.loads(report_path.read_text(encoding="utf-8"))
        self.assertEqual(report["targets"], [metadata])
        self.assertEqual(report["quality_summary"]["request_method_populated_count"], 0)
        self.assertEqual(report["quality_summary"]["request_method_missing_count"], 0)

    def test_scan_report_preserves_raw_noise_but_separates_quality_summary(self):
        alerts = [
            {"app": "vulnerable_app", "alert_name": "User Agent Fuzzer", "pluginid": 10104,
             "risk": "Informational", "evidence": ""},
            {"app": "vulnerable_app", "alert_name": "Path Traversal", "pluginid": 6,
             "risk": "High", "evidence": "root:x:0:0"},
        ]
        with tempfile.TemporaryDirectory() as temporary_directory:
            report_path = Path(temporary_directory) / "report.json"
            zap_scanner.save_scan_report(alerts, str(report_path), "targeted")
            report = json.loads(report_path.read_text(encoding="utf-8"))
        self.assertEqual(report["quality_summary"]["raw_alert_count"], 2)
        self.assertEqual(report["quality_summary"]["noise_alert_count"], 1)
        self.assertEqual(len(report["quality_summary"]["confirmed_evidence_candidates"]), 1)
        self.assertEqual(len(report["alerts"]), 2)


if __name__ == "__main__":
    unittest.main()
