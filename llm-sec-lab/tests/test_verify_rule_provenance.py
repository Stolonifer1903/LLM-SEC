import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import verify_rule_provenance as verifier


class FakeResponse:
    def __init__(self, body):
        self._body = body
        self.content = json.dumps(body).encode()
        self.status_code = 200
        self.headers = {"content-type": "application/json"}

    def json(self):
        return self._body

    def raise_for_status(self):
        return None


class FakeSession:
    def __init__(self):
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        value = kwargs["params"]["id"]
        route = url.split("/VulnerableApp/")[1]
        if route.startswith("Blind"):
            body = {"isCarPresent": "1=2" not in value and "'1'='2'" not in value}
        elif value == "3-2" or "'1'='1'" in value:
            body = {"id": 1, "name": "Audi"}
        elif value == "3-1":
            body = {"id": 2, "name": "BMW"}
        elif route.startswith("Error"):
            body = {"isCarPresent": False}
        else:
            body = {"id": 0}
        return FakeResponse(body)


class ProvenanceVerifierTests(unittest.TestCase):
    def test_bounded_replay_sends_exactly_six_get_pairs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run = root / "run"
            run.mkdir()
            (run / "raw_alerts.json").write_text("[]", encoding="utf-8")
            lock = {
                "images": {"vulnerable_app": {
                    "oci_version": verifier.RELEASE,
                    "image_id": verifier.IMAGE_DIGEST,
                    "container_name": "vulnerable-app",
                }}
            }
            lock_path = root / "environment-lock.json"
            lock_path.write_text(json.dumps(lock), encoding="utf-8")
            session = FakeSession()
            with patch.object(verifier, "inspect_container", return_value={
                "container": "vulnerable-app", "image_id": verifier.IMAGE_DIGEST,
                "image_reference": "pinned",
            }):
                destination = verifier.verify(run, lock_path, root / "out", session=session)
            artifact = json.loads(destination.read_text(encoding="utf-8"))
        self.assertEqual(len(session.calls), 12)
        self.assertTrue(all(call[1]["params"].keys() == {"id"} for call in session.calls))
        self.assertTrue(all(call[1]["allow_redirects"] is False for call in session.calls))
        self.assertEqual(artifact["verification_status"], "validated")
        self.assertEqual(len(artifact["cases"]), 6)

    def test_refuses_nonlocal_target_and_wrong_container_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run = root / "run"
            run.mkdir()
            (run / "raw_alerts.json").write_text("[]", encoding="utf-8")
            lock_path = root / "lock.json"
            lock_path.write_text(json.dumps({"images": {"vulnerable_app": {
                "oci_version": verifier.RELEASE, "image_id": verifier.IMAGE_DIGEST,
            }}}), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "only permits local"):
                verifier.verify(run, lock_path, root / "out", "https://example.com")
            with patch.object(verifier, "inspect_container", return_value={"image_id": "wrong"}):
                with self.assertRaisesRegex(ValueError, "pinned image digest"):
                    verifier.verify(run, lock_path, root / "out")


if __name__ == "__main__":
    unittest.main()
