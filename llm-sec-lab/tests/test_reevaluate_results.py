import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import reevaluate_results


class ReevaluateResultsTests(unittest.TestCase):
    def _source_run(self, root: Path) -> Path:
        source = root / "source-run"
        source.mkdir()
        records = [
            {
                "alert_id": "0", "cluster_id": "cluster", "prompt_strategy": strategy,
                "parsed_successfully": True,
            }
            for strategy in reevaluate_results.STRATEGIES
        ]
        artifacts = {
            "manifest.json": {"run_id": "source-run"},
            "pipeline_results.json": records,
            "parse_diagnostics.json": {
                "strategies": {strategy: {} for strategy in reevaluate_results.STRATEGIES},
            },
            "evaluation_summary.json": {"evaluation_status": "complete"},
        }
        for name, value in artifacts.items():
            (source / name).write_text(json.dumps(value), encoding="utf-8")
        return source

    def test_derived_evaluation_records_hashes_and_preserves_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = self._source_run(root)
            output = root / "derived"
            before = {
                path.name: path.read_bytes()
                for path in source.iterdir()
            }

            def fake_evaluate(run_dir, _records, _diagnostics):
                (run_dir / "evaluation_summary.json").write_text(
                    json.dumps({"evaluation_status": "complete"}), encoding="utf-8",
                )
                return {
                    "evaluation_status": "complete",
                    "evaluation_protocol": {"version": "semantic-v2"},
                }

            with (
                patch.object(reevaluate_results, "evaluate_post_triage", side_effect=fake_evaluate),
                patch.object(
                    reevaluate_results,
                    "_evaluation_protocol",
                    return_value={"version": "semantic-v2", "fingerprint_sha256": "fixture"},
                ),
            ):
                result = reevaluate_results.reevaluate_saved_run(source, output)

            derivation = json.loads(
                (output / "evaluation_derivation.json").read_text(encoding="utf-8")
            )
            self.assertEqual(result["evaluation_status"], "complete")
            self.assertEqual(derivation["source_run_id"], "source-run")
            self.assertEqual(derivation["network_activity"], "none; saved assessment evaluation only")
            self.assertEqual(set(derivation["source_artifact_sha256"]), set(reevaluate_results.REQUIRED_SOURCE_FILES))
            self.assertEqual(
                before,
                {path.name: path.read_bytes() for path in source.iterdir()},
            )

    def test_refuses_existing_or_incomplete_destination(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = self._source_run(root)
            output = root / "derived"
            output.mkdir()
            with self.assertRaises(FileExistsError):
                reevaluate_results.reevaluate_saved_run(source, output)
            (source / "parse_diagnostics.json").unlink()
            with self.assertRaisesRegex(ValueError, "incomplete"):
                reevaluate_results.reevaluate_saved_run(source, root / "new-derived")


if __name__ == "__main__":
    unittest.main()
