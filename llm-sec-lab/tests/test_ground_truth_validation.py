import csv
import tempfile
import unittest
from pathlib import Path

from evaluator import load_detection_validation, load_ground_truth


class GroundTruthValidationOverlayTests(unittest.TestCase):
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
