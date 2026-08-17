import csv
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import research_pipeline as pipeline


class SemanticEvaluationTests(unittest.TestCase):
    def setUp(self):
        self.taxonomy = pipeline.load_semantic_taxonomy()
        self.positive = {
            "ground_truth_label": "VULNERABLE",
            "expected_vulnerability_family": "sql_injection",
            "compatible_llm_cwe_ids": ("CWE-89",),
        }
        self.negative = {
            "ground_truth_label": "NOT_VULNERABLE",
            "expected_vulnerability_family": "",
            "compatible_llm_cwe_ids": (),
        }

    def assess(self, confirmed, family, cwe, match=None):
        return pipeline._semantic_assessment(
            {"confirmed": confirmed, "vulnerability_type": family, "cwe_id": cwe},
            match or self.positive, self.taxonomy,
        )

    def test_boolean_correct_xss_is_semantically_incorrect(self):
        result = self.assess(True, "XSS", "CWE-79")
        self.assertFalse(result["semantic_correct"])
        self.assertEqual(result["semantic_error_reason"], "unrecognized_family")

    def test_exact_alias_and_cwe_receive_credit_but_wrong_cwe_does_not(self):
        correct = self.assess(True, "Union-Based SQL Injection", "89")
        wrong = self.assess(True, "SQLi", "CWE-79")
        self.assertTrue(correct["semantic_correct"])
        self.assertEqual(correct["semantic_predicted_label"], "sql_injection|CWE-89")
        self.assertEqual(wrong["semantic_error_reason"], "cwe_mismatch")

    def test_negative_prediction_cannot_be_laundered_by_unknown_semantics(self):
        result = self.assess(True, "unknown thing", "bad", self.negative)
        self.assertFalse(result["semantic_correct"])
        self.assertEqual(result["semantic_error_reason"], "false_positive")

    def test_safe_positive_is_false_negative(self):
        result = self.assess(False, "SQL Injection", "CWE-89")
        self.assertEqual(result["semantic_predicted_label"], "SAFE")
        self.assertEqual(result["semantic_error_reason"], "false_negative_verdict")

    def test_taxonomy_alias_collision_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "taxonomy.json"
            path.write_text(json.dumps({
                "version": "fixture", "families": {
                    "first": {"aliases": ["same"]},
                    "second": {"aliases": ["same"]},
                },
            }), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "Duplicate semantic alias"):
                pipeline.load_semantic_taxonomy(path)

    def test_evaluation_fingerprint_changes_with_taxonomy(self):
        original = pipeline._evaluation_protocol()
        with tempfile.TemporaryDirectory() as directory:
            changed = Path(directory) / "taxonomy.json"
            data = json.loads(pipeline.SEMANTIC_TAXONOMY_PATH.read_text(encoding="utf-8"))
            data["families"]["sql_injection"]["aliases"].append("structured query language injection")
            changed.write_text(json.dumps(data), encoding="utf-8")
            modified = pipeline._evaluation_protocol(taxonomy_path=changed)
        self.assertNotEqual(original["fingerprint_sha256"], modified["fingerprint_sha256"])

    def test_evaluation_fingerprint_covers_provenance_matching_policy(self):
        original = pipeline._evaluation_protocol()
        with patch.object(
            pipeline,
            "PROVENANCE_MATCHING_POLICY",
            {"unknown_target_version": "different fixture policy"},
        ):
            modified = pipeline._evaluation_protocol()
        self.assertNotEqual(original["fingerprint_sha256"], modified["fingerprint_sha256"])

    def test_primary_statistics_use_semantic_not_boolean_correctness(self):
        clusters = {"positive", "negative"}
        labels = {"positive": True, "negative": False}
        apps = {cluster: "fixture" for cluster in clusters}
        records = {strategy: {} for strategy in pipeline.STRATEGIES}
        semantics = {strategy: {} for strategy in pipeline.STRATEGIES}
        for strategy in pipeline.STRATEGIES:
            for cluster in clusters:
                positive = cluster == "positive"
                record = {
                    "confirmed": positive,
                    "vulnerability_probability": 0.9 if positive else 0.1,
                    "probability_contract_version": pipeline.PROBABILITY_CONTRACT_VERSION,
                    "vulnerability_type": (
                        "XSS" if positive and strategy == "cot" else "SQL Injection"
                    ),
                    "cwe_id": "CWE-79" if positive and strategy == "cot" else "CWE-89",
                }
                records[strategy][cluster] = record
                semantics[strategy][cluster] = pipeline._semantic_assessment(
                    record, self.positive if positive else self.negative, self.taxonomy,
                )
        result = pipeline._evaluate_cluster_population(
            {"fixture"}, clusters, labels, apps, records,
            {strategy: 1.0 for strategy in pipeline.STRATEGIES}, semantics,
        )
        semantic_stats, boolean_stats = result[3], result[5]
        semantic_primary = next(row for row in semantic_stats if row["test"] == "mcnemar_primary")
        boolean_cot = next(row for row in boolean_stats if row["comparison"] == "zero_shot vs cot")
        self.assertNotEqual(semantic_primary["table"], boolean_cot["table"])

    def test_cwe_equivalence_parser_rejects_malformed_and_duplicate_values(self):
        with self.assertRaisesRegex(ValueError, "Invalid or duplicate"):
            pipeline._compatible_cwes("CWE-89|89")
        with self.assertRaisesRegex(ValueError, "Invalid or duplicate"):
            pipeline._compatible_cwes("not-a-cwe")


if __name__ == "__main__":
    unittest.main()
