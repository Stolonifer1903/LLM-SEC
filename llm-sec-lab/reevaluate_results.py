"""Re-evaluate completed saved assessments without contacting ZAP or an LLM."""

from __future__ import annotations

import argparse
import hashlib
import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from research_pipeline import (
    STRATEGIES,
    _evaluation_protocol,
    _load_json,
    _validate_pairs,
    _write_json,
    evaluate_post_triage,
)

DERIVATION_VERSION = "evaluation-derivation-v1"
REQUIRED_SOURCE_FILES = (
    "manifest.json",
    "pipeline_results.json",
    "parse_diagnostics.json",
    "evaluation_summary.json",
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _is_within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def reevaluate_saved_run(source_run: Path, output_dir: Path) -> dict:
    source_run = source_run.resolve()
    output_dir = output_dir.resolve()
    if not source_run.is_dir():
        raise FileNotFoundError(f"Source run directory does not exist: {source_run}")
    missing = [name for name in REQUIRED_SOURCE_FILES if not (source_run / name).is_file()]
    if missing:
        raise ValueError(f"Source run is incomplete; missing saved artifacts: {missing}")
    if output_dir.exists():
        raise FileExistsError(f"Evaluation output already exists: {output_dir}")
    if _is_within(output_dir, source_run) or _is_within(source_run, output_dir):
        raise ValueError("Source run and derived evaluation output must be separate directories")

    manifest = _load_json(source_run / "manifest.json")
    records = _load_json(source_run / "pipeline_results.json")
    diagnostics = _load_json(source_run / "parse_diagnostics.json")
    source_summary = _load_json(source_run / "evaluation_summary.json")
    if not isinstance(manifest, dict) or not isinstance(source_summary, dict):
        raise ValueError("Source manifest or evaluation summary is malformed")
    if not isinstance(records, list) or not isinstance(diagnostics, dict):
        raise ValueError("Source assessment or parse-diagnostics artifact is malformed")
    _validate_pairs(records)
    if set(diagnostics.get("strategies", {})) != set(STRATEGIES):
        raise ValueError("Source parse diagnostics do not cover the configured strategies")

    source_hashes = {
        name: _sha256(source_run / name)
        for name in REQUIRED_SOURCE_FILES
    }
    output_dir.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix=f".{output_dir.name}-", dir=output_dir.parent,
    ) as temporary:
        temporary_dir = Path(temporary)
        summary = evaluate_post_triage(temporary_dir, records, diagnostics)
        derivation = {
            "version": DERIVATION_VERSION,
            "created_at_utc": datetime.now(timezone.utc).isoformat(),
            "source_run_id": str(manifest.get("run_id", source_run.name)),
            "source_run": str(source_run),
            "source_evaluation_status": source_summary.get("evaluation_status", ""),
            "source_artifact_sha256": source_hashes,
            "derived_evaluation_protocol": _evaluation_protocol(),
            "network_activity": "none; saved assessment evaluation only",
        }
        _write_json(temporary_dir / "evaluation_derivation.json", derivation)
        if any(_sha256(source_run / name) != digest for name, digest in source_hashes.items()):
            raise RuntimeError("A source artifact changed during derived evaluation")
        temporary_dir.replace(output_dir)
    return {
        "source_run": str(source_run),
        "output_dir": str(output_dir),
        "evaluation_status": summary["evaluation_status"],
        "evaluation_protocol": summary["evaluation_protocol"],
    }


def main(argv=None) -> dict:
    parser = argparse.ArgumentParser(
        description="Re-evaluate completed saved assessments without ZAP or LLM inference",
    )
    parser.add_argument("--source-run", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    result = reevaluate_saved_run(args.source_run, args.output_dir)
    print(json.dumps(result, indent=2))
    return result


if __name__ == "__main__":
    main()
