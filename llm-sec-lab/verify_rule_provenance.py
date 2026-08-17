"""Bounded, allow-listed VulnerableApp SQL-injection provenance replay."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import requests

from environment_lock import lock_sha256

RELEASE = "26.04"
IMAGE_DIGEST = "sha256:75695010f1b622493716f7843acd7d6d1f68f90d866491c0ebdb028b39412d5f"
SOURCE_REVISION = "5b2810f88c48ee0823213e3e2e08161abf2866d6"
SOURCE_ROOT = f"https://github.com/SasanLabs/VulnerableApp/blob/{SOURCE_REVISION}"
SOURCE_REFS = {
    "blind": f"{SOURCE_ROOT}/src/main/java/org/sasanlabs/service/vulnerability/sqlInjection/BlindSQLInjectionVulnerability.java",
    "error": f"{SOURCE_ROOT}/src/main/java/org/sasanlabs/service/vulnerability/sqlInjection/ErrorBasedSQLInjectionVulnerability.java",
    "union": f"{SOURCE_ROOT}/src/main/java/org/sasanlabs/service/vulnerability/sqlInjection/UnionBasedSQLInjectionVulnerability.java",
}
CASES = (
    ("blind_level_1", "BlindSQLInjectionVulnerability/LEVEL_1", "1 AND 1=1 --", "1 AND 1=2 --", "blind", "blind"),
    ("blind_level_2", "BlindSQLInjectionVulnerability/LEVEL_2", "1' AND '1'='1' --", "1' AND '1'='2' --", "blind", "blind"),
    ("error_level_1", "ErrorBasedSQLInjectionVulnerability/LEVEL_1", "3-2", "3-1", "id_1_vs_2", "error"),
    ("error_level_2", "ErrorBasedSQLInjectionVulnerability/LEVEL_2", "1' AND '1'='1' --", "1' AND '1'='2' --", "present_vs_absent", "error"),
    ("union_level_1", "UnionBasedSQLInjectionVulnerability/LEVEL_1", "3-2", "3-1", "id_1_vs_2", "union"),
    ("union_level_2", "UnionBasedSQLInjectionVulnerability/LEVEL_2", "1' AND '1'='1' --", "1' AND '1'='2' --", "id_1_vs_null", "union"),
)


def _json_value(body: object, key: str):
    if isinstance(body, dict):
        if key in body:
            return body[key]
        for value in body.values():
            found = _json_value(value, key)
            if found is not None:
                return found
    if isinstance(body, list):
        for value in body:
            found = _json_value(value, key)
            if found is not None:
                return found
    return None


def evaluate_oracle(kind: str, payload_json: object, control_json: object) -> bool:
    if kind == "blind":
        return _json_value(payload_json, "isCarPresent") is True and _json_value(control_json, "isCarPresent") is False
    payload_id, control_id = _json_value(payload_json, "id"), _json_value(control_json, "id")
    if kind == "id_1_vs_2":
        return str(payload_id) == "1" and str(control_id) == "2"
    if kind == "present_vs_absent":
        return str(payload_id) == "1" and (
            _json_value(control_json, "isCarPresent") is False or control_id in {None, 0, "0"}
        )
    if kind == "id_1_vs_null":
        return str(payload_id) == "1" and control_id in {None, 0, "0"}
    raise ValueError(f"Unknown oracle: {kind}")


def inspect_container(container: str = "vulnerable-app") -> dict:
    completed = subprocess.run(
        ["docker", "inspect", container], check=True, capture_output=True, text=True,
    )
    item = json.loads(completed.stdout)[0]
    return {
        "container": container,
        "image_id": item.get("Image", ""),
        "image_reference": item.get("Config", {}).get("Image", ""),
    }


def _response_record(response) -> dict:
    content = response.content[:65536]
    try:
        parsed = response.json()
    except ValueError:
        parsed = None
    return {
        "status": response.status_code,
        "content_type": response.headers.get("content-type", ""),
        "body_sha256": hashlib.sha256(response.content).hexdigest(),
        "body_bytes": len(response.content),
        "bounded_body": content.decode("utf-8", errors="replace")[:2048],
        "json": parsed,
    }


def verify(run_dir: Path, environment_lock: Path, output_root: Path,
           base_url: str = "http://localhost:9090/VulnerableApp",
           session=requests) -> Path:
    parsed_url = urlsplit(base_url)
    if parsed_url.scheme != "http" or parsed_url.hostname not in {"localhost", "127.0.0.1"} or parsed_url.port != 9090:
        raise ValueError("The bounded verifier only permits local HTTP port 9090")
    if not (run_dir / "raw_alerts.json").is_file():
        raise ValueError("Frozen run directory must contain raw_alerts.json")
    lock = json.loads(environment_lock.read_text(encoding="utf-8"))
    locked = lock["images"]["vulnerable_app"]
    if locked.get("oci_version") != RELEASE or locked.get("image_id") != IMAGE_DIGEST:
        raise ValueError("Environment lock does not match VulnerableApp release 26.04 and pinned digest")
    environment_sha = lock_sha256(lock)
    container = inspect_container(locked.get("container_name", "vulnerable-app"))
    if container["image_id"] != IMAGE_DIGEST:
        raise ValueError("Active VulnerableApp container does not match the pinned image digest")

    rows = []
    for case_id, route, payload, control, oracle, source_key in CASES:
        exchanges = []
        json_bodies = []
        for role, value in (("payload", payload), ("control", control)):
            response = session.get(
                f"{base_url}/{route}", params={"id": value}, timeout=(3.05, 10),
                allow_redirects=False,
            )
            response.raise_for_status()
            record = _response_record(response)
            exchanges.append({"role": role, "method": "GET", "parameter": "id", "value": value, **record})
            json_bodies.append(record["json"])
        rows.append({
            "case_id": case_id, "route": f"/VulnerableApp/{route}",
            "oracle": oracle, "oracle_result": evaluate_oracle(oracle, *json_bodies),
            "source_ref": SOURCE_REFS[source_key], "exchanges": exchanges,
        })
    verified = all(row["oracle_result"] for row in rows)
    timestamp = datetime.now(timezone.utc)
    artifact = {
        "schema_version": 1, "verification_status": "validated" if verified else "failed",
        "timestamp_utc": timestamp.isoformat(), "frozen_run": str(run_dir.resolve()),
        "request_policy": "six allow-listed GET payload/control pairs; no discovery, spider, or ZAP",
        "release": RELEASE, "image_digest": IMAGE_DIGEST,
        "environment_lock_sha256": environment_sha, "container": container,
        "source_revision": SOURCE_REVISION, "source_refs": SOURCE_REFS, "cases": rows,
    }
    output_dir = output_root / timestamp.strftime("vulnerableapp_provenance_%Y%m%dT%H%M%SZ")
    output_dir.mkdir(parents=True, exist_ok=False)
    destination = output_dir / "verification.json"
    destination.write_text(json.dumps(artifact, indent=2) + "\n", encoding="utf-8")
    if not verified:
        raise RuntimeError(f"One or more bounded provenance oracles failed; see {destination}")
    return destination


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", required=True, type=Path)
    parser.add_argument("--environment-lock", required=True, type=Path)
    parser.add_argument("--output-root", type=Path, default=Path("results/provenance_verifications"))
    parser.add_argument("--base-url", default="http://localhost:9090/VulnerableApp")
    args = parser.parse_args()
    print(verify(args.run_dir, args.environment_lock, args.output_root, args.base_url))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
