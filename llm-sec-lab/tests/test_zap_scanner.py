import json
import tempfile
import unittest
from pathlib import Path
from urllib.parse import parse_qs
from unittest.mock import patch

import zap_scanner


class ZapScannerConfigurationTests(unittest.TestCase):
    def test_thorough_active_scan_configuration_removes_caps(self):
        with patch.object(zap_scanner, "zap_api") as api:
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
        self.assertIn(
            ("acsrf", "action", "addOptionToken", ("String", "user_token")),
            calls,
        )

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

    def test_juice_shop_seed_requests_cover_api_routes(self):
        with patch.object(zap_scanner, "zap_api") as api:
            zap_scanner.seed_juice_shop_requests("http://juice-shop:3000")

        urls = [call.kwargs["url"] for call in api.call_args_list]
        self.assertEqual(len(urls), 2)
        self.assertIn("http://juice-shop:3000/rest/products/search?q=apple", urls)
        self.assertIn("http://juice-shop:3000/rest/products/1/reviews", urls)

    def test_missing_required_path_stops_non_comprehensive_scan(self):
        with patch.object(zap_scanner, "get_target_urls", return_value=["http://dvwa/login.php"]):
            with self.assertRaisesRegex(RuntimeError, "required DAST paths were not discovered"):
                zap_scanner.verify_discovery("http://dvwa", "dvwa")

    def test_dvwa_login_configuration_includes_the_anti_csrf_token(self):
        responses = [
            {"Result": "OK"}, {"Result": "OK"}, {"Result": "OK"},
            {"Result": "OK"}, {"userId": "7"}, {"Result": "OK"},
            {"Result": "OK"},
        ]
        with patch.object(zap_scanner, "zap_api", side_effect=responses) as api:
            zap_scanner.configure_dvwa_user({"id": "1", "name": "dvwa_dast"}, "http://dvwa")

        authentication_call = api.call_args_list[0]
        parameters = authentication_call.kwargs["authMethodConfigParams"]
        request_data = parse_qs(parameters)["loginRequestData"][0]
        self.assertIn("user_token={%user_token%}", request_data)

    def test_user_scoped_spider_response_uses_its_action_name(self):
        self.assertEqual(
            zap_scanner.scan_id_from_response({"scanAsUser": "17"}, "scanAsUser", "dvwa"),
            "17",
        )

    def test_missing_scan_identifier_has_a_clear_error(self):
        with self.assertRaisesRegex(RuntimeError, "did not return a scan ID"):
            zap_scanner.scan_id_from_response({"Result": "OK"}, "scanAsUser", "dvwa")

    def test_scan_report_includes_effective_configuration_and_alerts(self):
        alerts = [{
            "app": "juice_shop",
            "alert_name": "Example Alert",
            "risk": "Low",
            "confidence": "Medium",
            "url": "http://juice-shop:3000/example",
            "cweid": "79",
        }]
        with tempfile.TemporaryDirectory() as temporary_directory:
            report_path = Path(temporary_directory) / "zap_scan_report.json"
            zap_scanner.reset_scan_metadata()
            zap_scanner.save_scan_report(alerts, str(report_path))
            report = json.loads(report_path.read_text(encoding="utf-8"))

        self.assertEqual(report["alerts"], alerts)
        self.assertEqual(report["scanner_configuration"]["active_scan_max_alerts_per_rule"], 0)
        self.assertEqual(report["alert_family_counts"][0]["count"], 1)

    def test_scan_report_preserves_raw_noise_but_separates_quality_summary(self):
        alerts = [
            {"app": "dvwa", "alert_name": "User Agent Fuzzer", "pluginid": 10104,
             "risk": "Informational", "evidence": ""},
            {"app": "dvwa", "alert_name": "Path Traversal", "pluginid": 6,
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
