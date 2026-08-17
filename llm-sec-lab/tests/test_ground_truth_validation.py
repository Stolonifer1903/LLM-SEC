import csv
import tempfile
import unittest
from pathlib import Path

from evaluator import load_detection_validation, load_ground_truth
from research_pipeline import load_automated_rules


class GroundTruthValidationOverlayTests(unittest.TestCase):
    def test_repository_juice_positive_is_fail_closed_until_version_capture(self):
        validated, provisional = load_automated_rules()

        labels_by_app = {
            app: {rule["ground_truth_label"] for rule in validated if rule["app"] == app}
            for app in ("vulnerable_app", "juice_shop")
        }
        positive_rules = [
            rule for rule in validated if rule["ground_truth_label"] == "VULNERABLE"
        ]

        self.assertEqual(labels_by_app["vulnerable_app"], {"VULNERABLE", "NOT_VULNERABLE"})
        self.assertTrue(all(rule["provider_key"] for rule in positive_rules))
        if "VULNERABLE" in labels_by_app["juice_shop"]:
            self.assertEqual(labels_by_app["juice_shop"], {"VULNERABLE", "NOT_VULNERABLE"})
            self.assertEqual(len(positive_rules), 7)
            self.assertEqual(provisional, [])
        else:
            self.assertEqual(labels_by_app["juice_shop"], {"NOT_VULNERABLE"})
            self.assertEqual(len(positive_rules), 6)
            self.assertEqual(len(provisional), 1)
            self.assertEqual(provisional[0]["rule_status"], "candidate_version_unbound")
        vulnerable_positives = [
            rule for rule in positive_rules if rule["app"] == "vulnerable_app"
        ]
        self.assertEqual(len(vulnerable_positives), 6)
        self.assertTrue(all(
            rule["validation_basis"] == "official_source_and_paired_replay"
            and "vulnerableapp_provenance_20260816T005336Z/verification.json" in rule["source_ref"]
            for rule in vulnerable_positives
        ))

    def test_overlay_defaults_cover_unlisted_catalogue_challenges(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            ground_truth = directory / "ground_truth.csv"
            overlay = directory / "overlay.csv"
            with ground_truth.open("w", newline="", encoding="utf-8") as file:
                writer = csv.DictWriter(file, fieldnames=[
                    "app", "provider_key", "zap_detection_mode", "expected_zap_alert_names",
                    "cwe_id", "ground_truth_label",
                ])
                writer.writeheader()
                writer.writerows([
                    {"app": "vulnerable_app", "provider_key": "VULNERABLE_APP-FI", "zap_detection_mode": "manual",
                     "expected_zap_alert_names": "N/A", "cwe_id": "CWE-98", "ground_truth_label": "VULNERABLE"},
                    {"app": "vulnerable_app", "provider_key": "VULNERABLE_APP-SQLI", "zap_detection_mode": "zap_active",
                     "expected_zap_alert_names": "SQL Injection", "cwe_id": "CWE-89", "ground_truth_label": "VULNERABLE"},
                ])
            with overlay.open("w", newline="", encoding="utf-8") as file:
                writer = csv.DictWriter(file, fieldnames=[
                    "provider_key", "app", "current_detection_mode", "validation_status",
                    "validated_detection_mode", "zap_alert_name", "zap_cwe_id", "url_regex",
                    "evidence_regex", "scan_profile", "validation_run_id", "rationale",
                ])
                writer.writeheader()
                writer.writerow({
                    "provider_key": "VULNERABLE_APP-FI", "app": "vulnerable_app", "current_detection_mode": "manual",
                    "validation_status": "candidate", "validated_detection_mode": "",
                    "zap_alert_name": "Path Traversal", "zap_cwe_id": "CWE-22",
                    "url_regex": "^/vulnerabilities/fi$", "evidence_regex": "root:x:0:0",
                    "scan_profile": "targeted", "validation_run_id": "run-1", "rationale": "candidate",
                })
            validation = load_detection_validation(overlay, load_ground_truth(ground_truth))

        self.assertEqual(set(validation["provider_key"]), {"VULNERABLE_APP-FI", "VULNERABLE_APP-SQLI"})
        statuses = dict(zip(validation["provider_key"], validation["validation_status"]))
        self.assertEqual(statuses["VULNERABLE_APP-FI"], "candidate")
        self.assertEqual(statuses["VULNERABLE_APP-SQLI"], "candidate")


if __name__ == "__main__":
    unittest.main()
