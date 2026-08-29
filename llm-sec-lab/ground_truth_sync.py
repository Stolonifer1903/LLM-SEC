"""Synchronize and report the pinned Juice Shop challenge catalogue conservatively."""

from __future__ import annotations

import csv
import json
import hashlib
import re
from pathlib import Path


def challenge_keys_from_yaml(path: Path) -> set[str]:
    keys = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        match = re.match(r"^\s*-?\s*key:\s*['\"]?([^'\"#\s]+)", line)
        if match:
            keys.add(match.group(1).strip())
    if not keys:
        raise ValueError(f"No Juice Shop challenge keys found in {path}")
    return keys


def catalogue_sync_report(ground_truth_path: Path, challenge_path: Path) -> dict:
    with ground_truth_path.open(newline="", encoding="utf-8") as file:
        rows = list(csv.DictReader(file))
    local = {
        str(row.get("provider_key", "")).strip()
        for row in rows
        if str(row.get("app", "")).strip().lower() == "juice_shop"
    }
    official = challenge_keys_from_yaml(challenge_path)
    return {
        "official_challenge_count": len(official),
        "local_juice_shop_challenge_count": len(local),
        "retained_provider_keys": sorted(official.intersection(local)),
        "new_unreviewed_provider_keys": sorted(official.difference(local)),
        "retired_provider_keys": sorted(local.difference(official)),
        "annotation_policy": (
            "Existing analyst annotations are retained by provider_key. New official keys remain "
            "unreviewed and retired keys remain archived; neither becomes a primary alert label."
        ),
    }


def bind_juice_shop_provenance(paths: list[Path], lock: dict) -> None:
    """Bind already-reviewed Juice Shop rows to the captured immutable release."""
    lock_hash = hashlib.sha256(
        json.dumps(lock, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()
    juice = lock["images"]["juice_shop"]
    digest = juice["pinned_reference"].split("@", 1)[1]
    for path in paths:
        with path.open(newline="", encoding="utf-8") as file:
            reader = csv.DictReader(file)
            rows = list(reader)
            fields = list(reader.fieldnames or [])
        for field in ("target_version", "target_image_digest", "environment_lock_sha256"):
            if field not in fields:
                fields.append(field)
        for row in rows:
            if str(row.get("app", "")).strip().lower() != "juice_shop":
                continue
            if str(row.get("provider_key", "")).strip() != "dbSchemaChallenge":
                continue
            row["target_version"] = juice.get("application_version", "")
            row["target_image_digest"] = digest
            row["environment_lock_sha256"] = lock_hash
        temporary = path.with_name(f".{path.name}.tmp")
        with temporary.open("w", newline="", encoding="utf-8") as file:
            writer = csv.DictWriter(file, fieldnames=fields, lineterminator="\n")
            writer.writeheader()
            writer.writerows(rows)
        temporary.replace(path)
