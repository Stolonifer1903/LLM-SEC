import json
import tempfile
import unittest
from pathlib import Path

import environment_lock


class EnvironmentLockTests(unittest.TestCase):
    def test_only_digest_references_are_accepted(self):
        digest = "a" * 64
        self.assertTrue(environment_lock.is_pinned_image_ref(f"repo/app:1.2.3@sha256:{digest}"))
        self.assertTrue(environment_lock.is_pinned_image_ref(f"repo/app@sha256:{digest}"))
        self.assertFalse(environment_lock.is_pinned_image_ref("repo/app:latest"))
        self.assertFalse(environment_lock.is_pinned_image_ref("repo/app:1.2.3"))

    def test_uncaptured_and_floating_locks_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "lock.json"
            path.write_text('{"status":"uncaptured"}', encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "not captured"):
                environment_lock.load_environment_lock(path)
            lock = {
                "status": "captured",
                "images": {key: {"pinned_reference": "repo:latest"}
                           for key in environment_lock.BOOTSTRAP_IMAGES},
            }
            path.write_text(json.dumps(lock), encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "floating"):
                environment_lock.load_environment_lock(path)

    def test_redaction_removes_nested_credentials(self):
        value = environment_lock.redact_secrets({
            "password": "secret", "nested": {"authorization": "Bearer token"},
            "safe": "retained",
        })
        self.assertEqual(value["password"], "<redacted>")
        self.assertEqual(value["nested"]["authorization"], "<redacted>")
        self.assertEqual(value["safe"], "retained")


if __name__ == "__main__":
    unittest.main()
