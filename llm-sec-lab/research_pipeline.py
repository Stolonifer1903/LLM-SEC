"""Automated, blinded DAST triage and post-triage rule evaluation."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from http.client import RemoteDisconnected
from itertools import combinations
from pathlib import Path
from statistics import mean
from urllib.parse import urlsplit

import numpy as np
import pandas as pd
from scipy.stats import friedmanchisquare, wilcoxon
from sklearn.metrics import (
    accuracy_score,
    brier_score_loss,
    classification_report,
    cohen_kappa_score,
    f1_score,
    precision_score,
    recall_score,
)
from statsmodels.stats.contingency_tables import mcnemar

from dotenv import load_dotenv
from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import ChatPromptTemplate
from langchain_nvidia_ai_endpoints import ChatNVIDIA
from requests.exceptions import ConnectionError as RequestsConnectionError
from urllib3.exceptions import ProtocolError

from environment_lock import DEFAULT_LOCK_PATH, capture_environment_lock, verify_environment_lock
from evaluator import (
    ACCEPTED_VERSION_MATCH_BASES,
    RULE_PROVENANCE_COLUMNS,
    load_detection_validation,
    load_ground_truth,
    normalize_cwe_id,
    normalize_text,
    target_version_match_basis,
)
from zap_scanner import (
    build_vulnerable_app_benchmark_payload,
    collect_alerts,
    reset_scan_metadata,
    run_scan,
    save_scan_report,
    start_fresh_zap_session,
    submit_vulnerable_app_benchmark,
    wait_for_zap,
)
from ground_truth_sync import bind_juice_shop_provenance, catalogue_sync_report

load_dotenv()

TARGETS = {
    "vulnerable_app": "http://vulnerable-app:9090/VulnerableApp",
    "juice_shop": "http://juice-shop:3000",
}
STRATEGIES = ("zero_shot", "few_shot", "cot")
MODEL = os.getenv("NIM_MODEL", "meta/llama-3.1-8b-instruct")
NIM_BASE_URL = os.getenv("NIM_BASE_URL", "https://integrate.api.nvidia.com/v1")
TEMPERATURE = 0.0
MAX_COMPLETION_TOKENS = 1024
NVIDIA_API_TIMEOUT_SECONDS = float(os.getenv("NVIDIA_API_TIMEOUT_SECONDS", "300"))
NVIDIA_MAX_RETRIES = int(os.getenv("NVIDIA_MAX_RETRIES", "6"))
NVIDIA_RETRY_BASE_SECONDS = float(os.getenv("NVIDIA_RETRY_BASE_SECONDS", "5"))
NVIDIA_RETRY_MAX_SECONDS = float(os.getenv("NVIDIA_RETRY_MAX_SECONDS", "60"))
PARSE_SUCCESS_THRESHOLD = 0.98
TARGET_RETRIES = int(os.getenv("ZAP_TARGET_RETRIES", "1"))

LAB_DIR = Path(__file__).resolve().parent
GROUND_TRUTH_PATH = LAB_DIR / "ground_truth.csv"
RULES_PATH = LAB_DIR / "ground_truth_match_rules.csv"
VALIDATION_PATH = LAB_DIR / "ground_truth_detection_validation.csv"
EXAMPLES_PATH = LAB_DIR / "few_shot_examples.json"
SEMANTIC_TAXONOMY_PATH = LAB_DIR / "semantic_taxonomy.json"
GROUND_TRUTH_CANDIDATE_COLUMNS = (
    "zap_alert_name", "zap_cwe_id", "app", "route_pattern", "evidence_pattern",
    "status", "provider_key", "request_method", "plugin_id", "evidence_source",
)
TRIAGE_RESULT_COLUMNS = (
    "zap_alert_name", "app", "url", "cwe", "strategy", "llm_verdict",
    "llm_vulnerability_probability", "probability_contract_version",
    "verdict_threshold", "legacy_llm_confidence", "assessment_origin",
    "repair_attempted", "repaired",
    "raw_model_family", "canonical_model_family", "raw_model_cwe",
    "canonical_model_cwe", "expected_vulnerability_family",
    "compatible_llm_cwe_ids", "family_compatible", "cwe_compatible",
    "semantic_ground_truth_label", "semantic_predicted_label",
    "semantic_evaluation_predicted_label", "semantic_label_universe",
    "semantic_correct", "semantic_error_reason",
    "ground_truth_label", "matched_rule", "duplicate_count",
)
TRIAGE_CHECKPOINT_VERSION = 3
TRIAGE_CHECKPOINT_FILE = "triage_checkpoint.jsonl"
TRIAGE_CHECKPOINT_STATE_FILE = "triage_checkpoint_state.json"

PROBABILITY_CONTRACT_VERSION = "vulnerability-probability-v1"
VERDICT_THRESHOLD = 0.5
PROBABILITY_EVENT = (
    "the supplied alert represents a real, exploitable vulnerability in the target"
)
PROBABILITY_CONTRACT = {
    "version": PROBABILITY_CONTRACT_VERSION,
    "field": "vulnerability_probability",
    "event": PROBABILITY_EVENT,
    "conditioning": "only the supplied alert fields",
    "derived_verdict": f"confirmed = vulnerability_probability >= {VERDICT_THRESHOLD}",
    "threshold": VERDICT_THRESHOLD,
}
EVALUATION_PROTOCOL_VERSION = "semantic-v2"
OTHER_POSITIVE_LABEL = "OTHER_POSITIVE"
SEMANTIC_LABEL_UNIVERSE_POLICY = {
    "version": "fixed-validated-ground-truth-v1",
    "scope": "one ordered universe per application, shared by every strategy and population",
    "source": "validated mapped ground-truth labels present in the run",
    "order": "SAFE, sorted canonical positive labels, OTHER_POSITIVE",
    "prediction_mapping": (
        "SAFE and in-universe canonical positive predictions are retained; all other "
        "confirmed diagnoses map to OTHER_POSITIVE for classification reporting"
    ),
    "macro_average": "all ordered labels are always averaged with zero_division=0",
    "score_ceiling_note": (
        "When SAFE and one canonical positive are the only ground-truth labels, a perfect "
        "classifier scores 2/3 because OTHER_POSITIVE has zero support."
    ),
}
SEMANTIC_SCORING_POLICY = {
    "prediction": "confirmed=false=>SAFE; confirmed=true=>canonical_family|normalized_CWE",
    "positive_correctness": "verdict and exact family alias and compatible CWE",
    "negative_correctness": "only confirmed=false is SAFE",
    "unknown_family": "UNRECOGNIZED",
    "invalid_cwe": "INVALID_CWE",
    "macro_f1_label_universe": SEMANTIC_LABEL_UNIVERSE_POLICY,
}
PROVENANCE_MATCHING_POLICY = {
    "explicit_target_version": "exact_match_required",
    "unknown_target_version": (
        "accepted_only_when_rule_image_digest_and_environment_lock_sha256_are_present_and_match_exactly"
    ),
    "explicit_target_version_conflict": "reject",
}

CVSS_CHOICES = {
    "av": {"N", "A", "L", "P"},
    "ac": {"L", "H"},
    "pr": {"N", "L", "H"},
    "ui": {"N", "R"},
    "s": {"U", "C"},
}
ASSESSMENT_SCHEMA = {
    "type": "object",
    "properties": {
        "vulnerability_probability": {"type": "number", "minimum": 0.0, "maximum": 1.0},
        "vulnerability_type": {"type": "string"},
        "cwe_id": {"type": "string"},
        "severity": {"type": "string"},
        "rationale": {"type": "string"},
        "recommended_action": {"type": "string"},
        "cvss_av": {"type": "string", "enum": sorted(CVSS_CHOICES["av"])},
        "cvss_ac": {"type": "string", "enum": sorted(CVSS_CHOICES["ac"])},
        "cvss_pr": {"type": "string", "enum": sorted(CVSS_CHOICES["pr"])},
        "cvss_ui": {"type": "string", "enum": sorted(CVSS_CHOICES["ui"])},
        "cvss_s": {"type": "string", "enum": sorted(CVSS_CHOICES["s"])},
    },
    "required": [
        "vulnerability_probability", "vulnerability_type", "cwe_id", "severity",
        "rationale", "recommended_action", "cvss_av", "cvss_ac", "cvss_pr",
        "cvss_ui", "cvss_s",
    ],
    "additionalProperties": False,
}
RESPONSE_FORMAT = {
    "type": "json_schema",
    "json_schema": {"name": "dast_triage_assessment", "schema": ASSESSMENT_SCHEMA, "strict": True},
}
BASE_INSTRUCTION = (
    f"Set vulnerability_probability to P({PROBABILITY_EVENT} | only the supplied alert fields). "
    "It is not confidence in your explanation, vulnerability type, CWE, severity, or in ZAP itself. "
    "Do not use ground truth, study-target knowledge, or evidence that was not supplied in this alert. "
    "Return exactly one JSON object with the required fields. Do not include Markdown or prose. "
    "Always provide CVSS v3.1 AV, AC, PR, UI, and Scope metrics for the finding, even when "
    f"vulnerability_probability is below {VERDICT_THRESHOLD}. The pipeline derives the Boolean "
    "confirmed verdict; do not return a confirmed or confidence field."
)
STRATEGY_INSTRUCTIONS = {
    "zero_shot": "Assess the ZAP alert directly using the supplied evidence.",
    "few_shot": "Use the labelled generic ZAP examples as guidance, then assess the new alert independently.",
    "cot": "Reason through vulnerability type, exploit evidence, and false-positive alternatives internally, then return only the concise JSON result.",
}
REPAIR_INSTRUCTION = (
    "The response above failed strict parsing with this error: {parse_error}\n"
    "Repair the response while preserving every recoverable substantive assessment value. "
    "Do not replace a recoverable vulnerability probability, vulnerability type, CWE, severity, rationale, "
    "recommended action, or CVSS value with a different assessment. If the response ended before all "
    "required fields were emitted, complete only the missing or invalid fields from the same supplied "
    "alert using the same strategy. Return exactly one schema-valid JSON object with no Markdown or prose."
)
ALERT_NAME_ALIASES: dict[str, set[str]] = {}
_PROMPT_CACHE: dict[tuple[str, str], ChatPromptTemplate] = {}
_REPAIR_PROMPT_CACHE: dict[tuple[str, str], ChatPromptTemplate] = {}


def _prompt(strategy: str, examples: str = "") -> ChatPromptTemplate:
    key = (strategy, examples)
    if key in _PROMPT_CACHE:
        return _PROMPT_CACHE[key]
    strategy_text = STRATEGY_INSTRUCTIONS[strategy]
    # Keep JSON examples as a partial value. Interpolating them directly into
    # the template would make LangChain interpret JSON braces as variables.
    examples_text = "\nGeneric development examples:\n{examples}\n" if strategy == "few_shot" else ""
    human = (
        f"{strategy_text}{examples_text}\nAlert name: {{alert_name}}\nRisk: {{risk}}\n"
        f"ZAP confidence: {{zap_confidence}}\nURL: {{url}}\nDescription: {{description}}\n"
        f"Evidence: {{evidence}}\nParameter: {{param}}\nAttack: {{attack}}\n\n{BASE_INSTRUCTION}"
    )
    prompt = ChatPromptTemplate.from_messages([
        ("system", "You are a security analyst triaging an OWASP ZAP DAST finding."),
        ("human", human),
    ])
    _PROMPT_CACHE[key] = prompt.partial(examples=examples) if strategy == "few_shot" else prompt
    return _PROMPT_CACHE[key]


def _repair_prompt(strategy: str, examples: str = "") -> ChatPromptTemplate:
    key = (strategy, examples)
    if key not in _REPAIR_PROMPT_CACHE:
        continuation = ChatPromptTemplate.from_messages([
            ("assistant", "{malformed_response}"),
            ("human", REPAIR_INSTRUCTION),
        ])
        _REPAIR_PROMPT_CACHE[key] = _prompt(strategy, examples) + continuation
    return _REPAIR_PROMPT_CACHE[key]


def _trim(value, limit=1000) -> str:
    return str(value or "").strip()[:limit]


def normalize_url_path(value) -> str:
    path = urlsplit(str(value or "")).path or "/"
    path = re.sub(r"/{2,}", "/", path)
    return path.rstrip("/") or "/"


def canonical_alert(alert: dict, alert_id: int) -> dict:
    row = dict(alert)
    row["alert_id"] = str(alert_id)
    row["app"] = normalize_text(row.get("app", ""))
    row["alert_name"] = _trim(row.get("alert_name", row.get("alert", "")))
    row["zap_cwe_id"] = normalize_cwe_id(row.get("cweid", row.get("zap_cwe_id", "")))
    for field in ("risk", "confidence", "url", "description", "evidence", "param", "attack", "other", "pluginid", "plugin_id", "evidence_source"):
        row[field] = _trim(row.get(field), 2000 if field in {"description", "evidence", "other"} else 500)
    row["plugin_id"] = _trim(row.get("plugin_id") or row.get("pluginid", ""))
    row["pluginid"] = row["plugin_id"]
    row["request_method"] = _trim(row.get("request_method", "")).upper()
    for field in (
        "authentication_context", "target_version", "target_image_digest",
        "environment_lock_sha256", "zap_version",
    ):
        row[field] = _trim(row.get(field, ""))
    if not row["target_version"]:
        row["target_version"] = "unknown"
    if not row["authentication_context"]:
        row["authentication_context"] = "unknown"
    return row


def dedup_key(alert: dict) -> dict:
    return {
        "app": alert.get("app", ""), "alert_name": alert.get("alert_name", ""),
        "zap_cwe_id": normalize_cwe_id(alert.get("zap_cwe_id", alert.get("cweid", ""))),
        "risk": alert.get("risk", ""), "confidence": alert.get("confidence", ""),
        "url": alert.get("url", ""), "description": alert.get("description", ""),
        "evidence": alert.get("evidence", ""), "param": alert.get("param", ""),
        "attack": alert.get("attack", ""),
        "plugin_id": _trim(alert.get("plugin_id") or alert.get("pluginid", "")),
        "request_method": _trim(alert.get("request_method", "")).upper(),
        "authentication_context": _trim(alert.get("authentication_context", "")),
        "target_version": _trim(alert.get("target_version", "")),
        "target_image_digest": _trim(alert.get("target_image_digest", "")),
        "environment_lock_sha256": _trim(alert.get("environment_lock_sha256", "")),
    }


def cluster_token(key: dict) -> str:
    return hashlib.sha256(json.dumps(key, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def deduplicate_alerts(alerts: list[dict]) -> list[dict]:
    by_token: dict[str, dict] = {}
    ordered: list[dict] = []
    for alert in alerts:
        key = dedup_key(alert)
        token = cluster_token(key)
        if token not in by_token:
            by_token[token] = {"cluster_id": token, "dedup_key": key, "members": [], "representative": alert}
            ordered.append(by_token[token])
        by_token[token]["members"].append(alert)
    for cluster in ordered:
        cluster["dedup_cluster_size"] = len(cluster["members"])
        cluster["alert_ids"] = [member["alert_id"] for member in cluster["members"]]
    return ordered


def build_ground_truth_candidates(
    alerts: list[dict], ground_truth_path: Path = GROUND_TRUTH_PATH,
) -> list[dict]:
    """Return strict, review-only candidates supported by official VulnerableApp rows."""
    ground_truth = load_ground_truth(ground_truth_path)
    comparators = []
    for _, row in ground_truth.iterrows():
        if normalize_text(row.get("app", "")) != "vulnerable_app":
            continue
        match = re.fullmatch(
            r"(?P<route>/.*?)\s+\[(?P<method>[A-Za-z]+)\]\s*",
            str(row.get("endpoint_or_feature", "")).strip(),
        )
        if not match:
            continue
        route = normalize_url_path(match.group("route"))
        if not route.startswith("/VulnerableApp"):
            route = normalize_url_path(f"/VulnerableApp{route}")
        comparators.append({
            "provider_key": str(row.get("challenge_id", row.get("provider_key", ""))).strip(),
            "route": route,
            "method": match.group("method").upper(),
            "cwe": normalize_cwe_id(row.get("cwe_id", "")),
        })

    candidates, seen = [], set()
    for alert in alerts:
        if normalize_text(alert.get("app", "")) != "vulnerable_app":
            continue
        attack = str(alert.get("attack", "")).strip()
        evidence = str(alert.get("evidence", "")).strip()
        if not attack or not evidence:
            continue
        route = normalize_url_path(alert.get("url", ""))
        method = str(alert.get("request_method", "")).strip().upper()
        cwe = normalize_cwe_id(alert.get("zap_cwe_id", alert.get("cweid", "")))
        for comparator in comparators:
            if (route, method, cwe) != (
                comparator["route"], comparator["method"], comparator["cwe"],
            ):
                continue
            candidate = {
                "zap_alert_name": str(alert.get("alert_name", alert.get("alert", ""))).strip(),
                "zap_cwe_id": cwe,
                "app": "vulnerable_app",
                "route_pattern": f"^{re.escape(route)}$",
                "evidence_pattern": re.escape(evidence),
                "status": "candidate",
                "provider_key": comparator["provider_key"],
                "request_method": method,
                "plugin_id": str(alert.get("plugin_id") or alert.get("pluginid", "")).strip(),
                "evidence_source": str(alert.get("evidence_source", "")).strip(),
            }
            key = tuple(candidate[column] for column in GROUND_TRUTH_CANDIDATE_COLUMNS)
            if key not in seen:
                seen.add(key)
                candidates.append(candidate)
    return sorted(
        candidates,
        key=lambda row: (
            row["app"], row["route_pattern"], row["zap_alert_name"],
            row["zap_cwe_id"], row["evidence_pattern"], row["provider_key"],
        ),
    )


def write_ground_truth_candidates(alerts: list[dict], path: Path) -> list[dict]:
    candidates = build_ground_truth_candidates(alerts)
    pd.DataFrame(candidates, columns=GROUND_TRUTH_CANDIDATE_COLUMNS).to_csv(path, index=False)
    return candidates


def _write_json(path: Path, value: dict | list) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(json.dumps(value, indent=2, ensure_ascii=False), encoding="utf-8")
    temporary.replace(path)


def _load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def latest_raw_alerts_path(output_root: Path) -> Path:
    """Return the newest complete DAST raw-alert artifact for reuse."""
    candidates = sorted(
        (
            path for path in output_root.glob("*/raw_alerts.json")
            if path.is_file() and _reuse_rejection_reason(path) is None
        ),
        key=lambda path: path.parent.name,
        reverse=True,
    )
    if not candidates:
        raise FileNotFoundError(f"No raw_alerts.json artifacts found under {output_root}")
    return candidates[0]


def _reuse_rejection_reason(path: Path) -> str | None:
    run_dir = path.parent
    if (run_dir / "salvage_manifest.json").exists() or run_dir.name.endswith("_salvaged"):
        return "salvaged runs are incomplete"
    status_path = run_dir / "scan_status.json"
    if status_path.exists():
        try:
            status = _load_json(status_path).get("status")
        except (OSError, ValueError, AttributeError) as exc:
            return f"scan_status.json is unreadable: {exc}"
        if status not in {"completed", "completed_with_warnings"}:
            return f"scan status is {status!r}"
        if status_path.exists() and _load_json(status_path).get("scan_profile") == "final":
            eligibility_path = run_dir / "triage_eligibility.json"
            if not eligibility_path.is_file():
                return "final-profile run has no triage eligibility artifact"
            if not _load_json(eligibility_path).get("triage_eligible"):
                return "final-profile run is not triage eligible"
    return None


def resolve_reuse_source(output_root: Path, source: str | None = None) -> Path:
    if not source:
        return latest_raw_alerts_path(output_root)
    candidate = Path(source)
    if candidate.is_dir():
        candidate = candidate / "raw_alerts.json"
    if not candidate.is_file():
        raise FileNotFoundError(f"Reuse source does not contain raw_alerts.json: {candidate}")
    rejection = _reuse_rejection_reason(candidate)
    if rejection:
        raise ValueError(f"Reuse source is not a complete two-app run: {candidate} ({rejection})")
    return candidate


def _run_id() -> str:
    return datetime.now(timezone.utc).strftime("run_%Y%m%dT%H%M%SZ")


def _git_revision() -> str:
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], text=True, stderr=subprocess.DEVNULL).strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def _is_transient(error: Exception) -> bool:
    pending = [error]
    seen: set[int] = set()
    transient_types = (
        TimeoutError,
        ConnectionError,
        RemoteDisconnected,
        RequestsConnectionError,
        ProtocolError,
    )
    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        if isinstance(current, transient_types):
            return True
        pending.extend(
            nested for nested in (current.__cause__, current.__context__)
            if isinstance(nested, BaseException)
        )
        pending.extend(nested for nested in current.args if isinstance(nested, BaseException))

    text = " ".join(str(item).lower() for item in _exception_chain(error))
    markers = (
        "429", "500", "502", "503", "504", "timeout", "rate limit",
        "resourceexhausted", "remote end closed connection", "connection aborted",
        "connection reset", "connection refused", "broken pipe", "protocolerror",
        "temporarily unavailable",
    )
    return any(marker in text for marker in markers)


def _exception_chain(error: BaseException) -> list[BaseException]:
    pending = [error]
    ordered: list[BaseException] = []
    seen: set[int] = set()
    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        ordered.append(current)
        pending.extend(
            nested for nested in (current.__cause__, current.__context__)
            if isinstance(nested, BaseException)
        )
        pending.extend(nested for nested in current.args if isinstance(nested, BaseException))
    return ordered


def _format_duration(seconds: float) -> str:
    seconds = max(0, round(seconds))
    minutes, seconds = divmod(seconds, 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{hours}h {minutes:02d}m {seconds:02d}s"
    if minutes:
        return f"{minutes}m {seconds:02d}s"
    return f"{seconds}s"


class NimProgress:
    """Report deterministic progress around sequential hosted NIM requests."""

    def __init__(self, total_assessments: int, completed_assessments: int = 0):
        self.total = total_assessments
        self.completed = completed_assessments
        self.session_completed = 0
        self.api_requests = 0
        self.started_at = time.perf_counter()
        self.assessment_started_at = self.started_at
        self.current_number = 0
        self.current_strategy = ""
        self.current_cluster = ""
        if completed_assessments:
            print(
                f"[nim] Resuming from checkpoint: {completed_assessments}/{total_assessments} "
                "assessments already complete.",
                flush=True,
            )

    def start_assessment(self, strategy: str, cluster_index: int, cluster_id: str) -> None:
        self.current_number = self.completed + 1
        self.current_strategy = strategy
        self.current_cluster = cluster_id
        self.assessment_started_at = time.perf_counter()
        print(
            f"[nim] Assessment {self.current_number}/{self.total} started "
            f"({self._percentage():.1f}%) | strategy={strategy} | "
            f"cluster={cluster_index}",
            flush=True,
        )

    def request_started(self, request_kind: str, attempt: int) -> None:
        self.api_requests += 1
        print(
            f"[nim]   Request #{self.api_requests}: {request_kind} "
            f"(attempt {attempt}) | cluster_id={self.current_cluster}",
            flush=True,
        )

    def retry_scheduled(self, error: Exception, retry_number: int, delay: float) -> None:
        error_summary = " ".join(str(error).split())[:240]
        print(
            f"[nim]   Transient failure; retry {retry_number}/{NVIDIA_MAX_RETRIES} "
            f"in {delay:.1f}s: {error_summary}",
            flush=True,
        )

    def complete_assessment(self, parsed: bool, repaired: bool) -> None:
        self.completed += 1
        self.session_completed += 1
        now = time.perf_counter()
        assessment_seconds = now - self.assessment_started_at
        elapsed_seconds = now - self.started_at
        mean_seconds = elapsed_seconds / self.session_completed
        eta_seconds = mean_seconds * (self.total - self.completed)
        status = "parsed after repair" if repaired else "parsed" if parsed else "parse failed"
        print(
            f"[nim] Assessment {self.completed}/{self.total} complete "
            f"({self._percentage():.1f}%) | {status} | "
            f"call={_format_duration(assessment_seconds)} | "
            f"elapsed={_format_duration(elapsed_seconds)} | "
            f"avg={mean_seconds:.1f}s | eta={_format_duration(eta_seconds)} | "
            f"requests={self.api_requests}",
            flush=True,
        )

    def fail_assessment(self, error: Exception) -> None:
        elapsed = time.perf_counter() - self.assessment_started_at
        error_summary = " ".join(str(error).split())[:240]
        print(
            f"[nim] Assessment {self.current_number}/{self.total} failed after "
            f"{_format_duration(elapsed)} | strategy={self.current_strategy} | "
            f"cluster_id={self.current_cluster}: {error_summary}",
            flush=True,
        )

    def _percentage(self) -> float:
        return (self.completed / self.total * 100) if self.total else 100.0


def _invoke(chain, payload: dict, *, progress: NimProgress | None = None, request_kind: str = "primary") -> str:
    for attempt in range(NVIDIA_MAX_RETRIES + 1):
        if progress is not None:
            progress.request_started(request_kind, attempt + 1)
        try:
            return str(chain.invoke(payload))
        except Exception as error:
            if not _is_transient(error) or attempt >= NVIDIA_MAX_RETRIES:
                raise
            delay = min(NVIDIA_RETRY_BASE_SECONDS * (2 ** attempt), NVIDIA_RETRY_MAX_SECONDS)
            if progress is not None:
                progress.retry_scheduled(error, attempt + 1, delay)
            time.sleep(delay)
    raise RuntimeError("NIM retry loop exited unexpectedly")


def _parse_json(raw: str) -> dict:
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", raw, re.DOTALL)
        if not match:
            raise ValueError("No JSON object found")
        value = json.loads(match.group(0))
    if not isinstance(value, dict):
        raise ValueError("Assessment must be a JSON object")
    unexpected = set(value).difference(ASSESSMENT_SCHEMA["properties"])
    if unexpected:
        raise ValueError(f"Unexpected assessment fields: {sorted(unexpected)}")
    for field in ASSESSMENT_SCHEMA["required"]:
        if field not in value:
            raise ValueError(f"Missing assessment field: {field}")
    probability = value["vulnerability_probability"]
    if (
        isinstance(probability, bool)
        or not isinstance(probability, (int, float))
        or not np.isfinite(probability)
        or not 0 <= probability <= 1
    ):
        raise ValueError("Invalid vulnerability_probability; expected a finite number from 0 to 1")
    value["vulnerability_probability"] = float(probability)
    for field in ASSESSMENT_SCHEMA["properties"]:
        if field != "vulnerability_probability" and not isinstance(value[field], str):
            raise ValueError(f"Invalid assessment field type for {field}; expected string")
    for field, choices in CVSS_CHOICES.items():
        key = f"cvss_{field}"
        if str(value[key]).upper() not in choices:
            raise ValueError(f"Invalid CVSS value for {key}")
        value[key] = str(value[key]).upper()
    value["confirmed"] = value["vulnerability_probability"] >= VERDICT_THRESHOLD
    value["verdict_threshold"] = VERDICT_THRESHOLD
    value["probability_contract_version"] = PROBABILITY_CONTRACT_VERSION
    return value


def _model(model: str):
    return ChatNVIDIA(
        model=model, api_key=os.environ["NVIDIA_API_KEY"], base_url=NIM_BASE_URL,
        temperature=TEMPERATURE, max_completion_tokens=MAX_COMPLETION_TOKENS,
        timeout=NVIDIA_API_TIMEOUT_SECONDS,
    ).bind(response_format=RESPONSE_FORMAT)


def _load_examples(path: Path = EXAMPLES_PATH) -> str:
    rows = _load_json(path)
    if not isinstance(rows, list) or len(rows) != 4:
        raise ValueError("few_shot_examples.json must contain exactly four examples")
    labels = []
    target_tokens = {"juice shop", "juice_shop", "vulnerableapp", "vulnerable app", "vulnerable_app"}
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("Every few-shot example must be a JSON object")
        if "confidence" in row or "confirmed" in row:
            raise ValueError("Few-shot examples must use vulnerability_probability without confidence or confirmed")
        assessment = {
            field: row[field]
            for field in ASSESSMENT_SCHEMA["required"]
            if field in row
        }
        if len(assessment) != len(ASSESSMENT_SCHEMA["required"]):
            missing = sorted(set(ASSESSMENT_SCHEMA["required"]).difference(row))
            raise ValueError(f"Few-shot example is missing assessment fields: {missing}")
        parsed = _parse_json(json.dumps(assessment, ensure_ascii=False))
        labels.append(parsed["confirmed"])
        if not str(row.get("source_url", "")).strip():
            raise ValueError("Every few-shot example must include a source_url")
        text = json.dumps(row).lower()
        if any(token in text for token in target_tokens):
            raise ValueError("Few-shot examples must not identify a study application")
    if labels.count(True) != 2 or labels.count(False) != 2:
        raise ValueError(
            "few_shot_examples.json must contain two probabilities at or above the verdict "
            "threshold and two below it"
        )
    return json.dumps(rows, ensure_ascii=False)


def _examples_metadata(path: Path = EXAMPLES_PATH) -> dict:
    content = path.read_bytes()
    rows = _load_json(path)
    return {
        "file": path.name,
        "sha256": hashlib.sha256(content).hexdigest(),
        "sources": sorted({str(row["source_url"]) for row in rows}),
    }


def _triage_protocol_sha256(examples_metadata: dict | None = None) -> str:
    metadata = examples_metadata or _examples_metadata()
    payload = {
        "checkpoint_version": TRIAGE_CHECKPOINT_VERSION,
        "strategies": list(STRATEGIES),
        "strategy_instructions": STRATEGY_INSTRUCTIONS,
        "base_instruction": BASE_INSTRUCTION,
        "repair_instruction": REPAIR_INSTRUCTION,
        "probability_contract": PROBABILITY_CONTRACT,
        "assessment_schema": ASSESSMENT_SCHEMA,
        "few_shot_examples_sha256": metadata["sha256"],
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def cvss31_exploitability(assessment: dict) -> float:
    av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}[assessment["cvss_av"]]
    ac = {"L": 0.77, "H": 0.44}[assessment["cvss_ac"]]
    ui = {"N": 0.85, "R": 0.62}[assessment["cvss_ui"]]
    pr = ({"N": 0.85, "L": 0.62, "H": 0.27} if assessment["cvss_s"] == "U" else {"N": 0.85, "L": 0.68, "H": 0.50})[assessment["cvss_pr"]]
    return round(8.22 * av * ac * pr * ui, 4)


def _repair_chain(llm, strategy: str, examples: str = ""):
    return _repair_prompt(strategy, examples) | llm | StrOutputParser()


def _cluster_ids_sha256(clusters: list[dict]) -> str:
    payload = json.dumps(
        [cluster["cluster_id"] for cluster in clusters],
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _checkpoint_paths(checkpoint_dir: Path) -> tuple[Path, Path]:
    return (
        checkpoint_dir / TRIAGE_CHECKPOINT_FILE,
        checkpoint_dir / TRIAGE_CHECKPOINT_STATE_FILE,
    )


def _checkpoint_state(
    clusters: list[dict],
    run_id: str,
    model: str,
    completed: int,
    protocol_sha256: str,
) -> dict:
    total = len(clusters) * len(STRATEGIES)
    return {
        "version": TRIAGE_CHECKPOINT_VERSION,
        "status": "in_progress",
        "run_id": run_id,
        "model": model,
        "triage_protocol_sha256": protocol_sha256,
        "strategies": list(STRATEGIES),
        "cluster_count": len(clusters),
        "cluster_ids_sha256": _cluster_ids_sha256(clusters),
        "completed_assessment_count": completed,
        "total_assessment_count": total,
        "updated_at_utc": datetime.now(timezone.utc).isoformat(),
    }


def _validate_checkpoint_state(
    state: dict,
    clusters: list[dict],
    run_id: str,
    model: str,
    protocol_sha256: str,
) -> None:
    expected = _checkpoint_state(clusters, run_id, model, 0, protocol_sha256)
    if (
        state.get("version") != TRIAGE_CHECKPOINT_VERSION
        or state.get("triage_protocol_sha256") != protocol_sha256
    ):
        raise ValueError(
            "Incompatible triage checkpoint protocol; start a new triage run from the "
            "saved raw alerts with --reuse-from."
        )
    for field in (
        "version", "run_id", "model", "strategies", "cluster_count",
        "cluster_ids_sha256", "total_assessment_count", "triage_protocol_sha256",
    ):
        if state.get(field) != expected[field]:
            raise ValueError(
                f"Triage checkpoint {field} mismatch: "
                f"expected {expected[field]!r}, found {state.get(field)!r}"
            )


def _write_checkpoint_records(path: Path, records: dict[tuple[str, str], dict]) -> None:
    temporary = path.with_name(f".{path.name}.tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as file:
        for record in records.values():
            file.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")
        file.flush()
        os.fsync(file.fileno())
    temporary.replace(path)


def _load_triage_checkpoint(
    checkpoint_dir: Path,
    clusters: list[dict],
    run_id: str,
    model: str,
    protocol_sha256: str,
) -> dict[tuple[str, str], dict]:
    checkpoint_path, state_path = _checkpoint_paths(checkpoint_dir)
    checkpoint_dir.mkdir(parents=True, exist_ok=True)
    if state_path.exists():
        state = _load_json(state_path)
        if not isinstance(state, dict):
            raise ValueError(f"Triage checkpoint state must be an object: {state_path}")
        _validate_checkpoint_state(state, clusters, run_id, model, protocol_sha256)
    elif checkpoint_path.exists() and checkpoint_path.stat().st_size:
        raise ValueError(f"Triage checkpoint data exists without state metadata: {checkpoint_path}")
    else:
        _write_json(
            state_path,
            _checkpoint_state(clusters, run_id, model, 0, protocol_sha256),
        )

    known_clusters = {cluster["cluster_id"] for cluster in clusters}
    records: dict[tuple[str, str], dict] = {}
    repair_needed = False
    if checkpoint_path.exists():
        lines = checkpoint_path.read_bytes().splitlines()
        for index, raw_line in enumerate(lines):
            try:
                line = raw_line.decode("utf-8")
            except UnicodeDecodeError as exc:
                if index != len(lines) - 1:
                    raise ValueError(
                        f"Invalid UTF-8 in triage checkpoint line {index + 1}: {checkpoint_path}"
                    ) from exc
                repair_needed = True
                continue
            if not line.strip():
                repair_needed = True
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                if index != len(lines) - 1:
                    raise ValueError(
                        f"Malformed triage checkpoint record at line {index + 1}: {checkpoint_path}"
                    ) from exc
                repair_needed = True
                continue
            if not isinstance(record, dict):
                raise ValueError(f"Triage checkpoint line {index + 1} must contain an object")
            if record.get("version") != TRIAGE_CHECKPOINT_VERSION:
                raise ValueError(
                    "Incompatible triage checkpoint protocol; start a new triage run from the "
                    "saved raw alerts with --reuse-from."
                )
            if record.get("triage_protocol_sha256") != protocol_sha256:
                raise ValueError(
                    "Incompatible triage checkpoint protocol; start a new triage run from the "
                    "saved raw alerts with --reuse-from."
                )
            strategy = str(record.get("prompt_strategy", ""))
            cluster_id = str(record.get("cluster_id", ""))
            if strategy not in STRATEGIES or cluster_id not in known_clusters:
                raise ValueError(f"Unknown strategy or cluster in triage checkpoint line {index + 1}")
            if record.get("run_id") != run_id or record.get("model") != model:
                raise ValueError(f"Run or model mismatch in triage checkpoint line {index + 1}")
            if not isinstance(record.get("output"), dict):
                raise ValueError(f"Missing output in triage checkpoint line {index + 1}")
            key = (strategy, cluster_id)
            if key in records:
                if records[key] != record:
                    raise ValueError(f"Conflicting duplicate triage checkpoint record for {key}")
                repair_needed = True
                continue
            records[key] = record

    if repair_needed:
        _write_checkpoint_records(checkpoint_path, records)
    elif not checkpoint_path.exists():
        _write_checkpoint_records(checkpoint_path, records)
    _write_json(
        state_path,
        _checkpoint_state(clusters, run_id, model, len(records), protocol_sha256),
    )
    return records


def _append_triage_checkpoint(
    checkpoint_dir: Path,
    clusters: list[dict],
    run_id: str,
    model: str,
    records: dict[tuple[str, str], dict],
    strategy: str,
    cluster_id: str,
    output: dict,
    protocol_sha256: str,
) -> None:
    checkpoint_path, state_path = _checkpoint_paths(checkpoint_dir)
    key = (strategy, cluster_id)
    record = {
        "version": TRIAGE_CHECKPOINT_VERSION,
        "run_id": run_id,
        "model": model,
        "triage_protocol_sha256": protocol_sha256,
        "prompt_strategy": strategy,
        "cluster_id": cluster_id,
        "completed_at_utc": datetime.now(timezone.utc).isoformat(),
        "output": output,
    }
    existing = records.get(key)
    if existing is not None:
        if existing != record:
            raise ValueError(f"Triage checkpoint already contains a conflicting result for {key}")
        return
    with checkpoint_path.open("a", encoding="utf-8", newline="\n") as file:
        file.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")
        file.flush()
        os.fsync(file.fileno())
    records[key] = record
    _write_json(
        state_path,
        _checkpoint_state(clusters, run_id, model, len(records), protocol_sha256),
    )


def _remove_triage_checkpoint(checkpoint_dir: Path) -> None:
    for path in _checkpoint_paths(checkpoint_dir):
        try:
            path.unlink()
        except FileNotFoundError:
            pass


def _update_triage_stats(stats: dict, output: dict) -> None:
    stats["attempted_calls"] += 1
    stats["latencies"].append(float(output.get("inference_latency_seconds", 0.0)))
    initial_parsed = output.get("initial_parsed_successfully")
    if initial_parsed is None:
        initial_parsed = not bool(output.get("initial_parse_error"))
    repair_attempted = output.get("repair_attempted")
    if repair_attempted is None:
        repair_attempted = bool(output.get("initial_parse_error"))
    if not initial_parsed:
        stats["initial_failures"] += 1
    if repair_attempted:
        stats["repair_attempts"] += 1
    if output.get("repaired"):
        stats["repair_successes"] += 1
    if not output.get("parsed_successfully"):
        stats["unrecoverable_failures"] += 1


def triage_clusters(
    clusters: list[dict],
    run_id: str,
    model: str = MODEL,
    *,
    checkpoint_dir: Path | None = None,
    protocol_sha256: str | None = None,
) -> tuple[list[dict], dict]:
    """Perform blinded inference. This function deliberately has no ground-truth inputs."""
    examples = _load_examples()
    protocol_sha256 = protocol_sha256 or _triage_protocol_sha256()
    outputs: dict[str, dict[str, dict]] = {strategy: {} for strategy in STRATEGIES}
    checkpoint_records: dict[tuple[str, str], dict] = {}
    if checkpoint_dir is not None:
        checkpoint_records = _load_triage_checkpoint(
            checkpoint_dir,
            clusters,
            run_id,
            model,
            protocol_sha256,
        )
        for (strategy, cluster_id), record in checkpoint_records.items():
            outputs[strategy][cluster_id] = record["output"]
    llm = _model(model)
    diagnostics = {
        "metadata": {
            "run_id": run_id,
            "model": model,
            "triage_protocol_sha256": protocol_sha256,
            "probability_contract": PROBABILITY_CONTRACT,
            "resumed_assessment_count": len(checkpoint_records),
        },
        "strategies": {},
        "failures": [],
    }
    progress = NimProgress(
        len(clusters) * len(STRATEGIES),
        completed_assessments=len(checkpoint_records),
    )
    for strategy in STRATEGIES:
        chain = _prompt(strategy, examples) | llm | StrOutputParser()
        repair_chain = _repair_chain(llm, strategy, examples)
        stats = {
            "attempted_calls": 0,
            "resumed_calls": 0,
            "initial_failures": 0,
            "repair_attempts": 0,
            "repair_successes": 0,
            "unrecoverable_failures": 0,
            "latencies": [],
        }
        for cluster in clusters:
            resumed_output = outputs[strategy].get(cluster["cluster_id"])
            if resumed_output is None:
                continue
            stats["resumed_calls"] += 1
            _update_triage_stats(stats, resumed_output)
            if not resumed_output.get("parsed_successfully"):
                diagnostics["failures"].append({
                    "prompt_strategy": strategy,
                    "cluster_id": cluster["cluster_id"],
                    "initial_error": resumed_output.get("initial_parse_error", ""),
                    "repair_error": resumed_output.get("repair_parse_error", ""),
                    "initial_response": resumed_output.get("initial_response", ""),
                    "repair_response": resumed_output.get("repair_response", ""),
                })
        for cluster_index, cluster in enumerate(clusters, start=1):
            if cluster["cluster_id"] in outputs[strategy]:
                continue
            alert = cluster["representative"]
            payload = {field: alert.get(field, "") for field in ("alert_name", "risk", "url", "description", "evidence", "param", "attack")}
            payload["zap_confidence"] = alert.get("confidence", "")
            progress.start_assessment(strategy, cluster_index, cluster["cluster_id"])
            started = time.perf_counter()
            try:
                initial_raw = _invoke(chain, payload, progress=progress, request_kind="primary")
            except Exception as error:
                progress.fail_assessment(error)
                raise
            latency = time.perf_counter() - started
            assessment, repair_raw, initial_error, repair_error, repaired = None, "", "", "", False
            try:
                assessment = _parse_json(initial_raw)
            except Exception as error:
                initial_error = str(error)
                print(
                    "[nim]   Invalid JSON response; requesting strategy-preserving format repair.",
                    flush=True,
                )
                repair_payload = {
                    **payload,
                    "malformed_response": initial_raw,
                    "parse_error": initial_error,
                }
                try:
                    repair_raw = _invoke(
                        repair_chain,
                        repair_payload,
                        progress=progress,
                        request_kind="strategy-preserving format repair",
                    )
                except Exception as repair_request_error:
                    progress.fail_assessment(repair_request_error)
                    repair_error = f"Repair request failed: {repair_request_error}"
                else:
                    try:
                        assessment = _parse_json(repair_raw)
                        repaired = True
                    except Exception as parse_error:
                        repair_error = str(parse_error)
            initial_parsed_successfully = not bool(initial_error)
            repair_attempted = bool(initial_error)
            if initial_parsed_successfully:
                assessment_origin = "initial"
            elif repaired:
                assessment_origin = "strategy_preserving_repair"
            else:
                assessment_origin = "unparsed"
            output = {
                "initial_response": initial_raw, "repair_response": repair_raw,
                "initial_parse_error": initial_error, "repair_parse_error": repair_error,
                "initial_parsed_successfully": initial_parsed_successfully,
                "repair_attempted": repair_attempted,
                "repaired": repaired,
                "assessment_origin": assessment_origin,
                "parsed_successfully": assessment is not None, "inference_latency_seconds": latency,
            }
            if assessment is None:
                output.update({
                    "confirmed": None,
                    "vulnerability_probability": None,
                    "verdict_threshold": VERDICT_THRESHOLD,
                    "probability_contract_version": PROBABILITY_CONTRACT_VERSION,
                    "cvss_exploitability": None,
                })
            else:
                output.update(assessment)
                output["cvss_exploitability"] = cvss31_exploitability(assessment)
            outputs[strategy][cluster["cluster_id"]] = output
            _update_triage_stats(stats, output)
            if assessment is None:
                diagnostics["failures"].append({
                    "prompt_strategy": strategy, "cluster_id": cluster["cluster_id"],
                    "initial_error": initial_error, "repair_error": repair_error,
                    "initial_response": initial_raw, "repair_response": repair_raw,
                })
            if checkpoint_dir is not None:
                _append_triage_checkpoint(
                    checkpoint_dir,
                    clusters,
                    run_id,
                    model,
                    checkpoint_records,
                    strategy,
                    cluster["cluster_id"],
                    output,
                    protocol_sha256,
                )
            progress.complete_assessment(assessment is not None, repaired)
        diagnostics["strategies"][strategy] = {
            **stats,
            "initial_parse_success_rate": (stats["attempted_calls"] - stats["initial_failures"]) / stats["attempted_calls"] if stats["attempted_calls"] else 0.0,
            "repair_success_rate": stats["repair_successes"] / stats["repair_attempts"] if stats["repair_attempts"] else None,
            "final_parse_success_rate": (stats["attempted_calls"] - stats["unrecoverable_failures"]) / stats["attempted_calls"] if stats["attempted_calls"] else 0.0,
            "parse_success_rate": (stats["attempted_calls"] - stats["unrecoverable_failures"]) / stats["attempted_calls"] if stats["attempted_calls"] else 0.0,
            "mean_latency_seconds": mean(stats["latencies"]) if stats["latencies"] else 0.0,
        }

    expanded = []
    for strategy in STRATEGIES:
        for cluster in clusters:
            output = outputs[strategy][cluster["cluster_id"]]
            for alert in cluster["members"]:
                expanded.append({
                    "run_id": run_id, "alert_id": alert["alert_id"], "cluster_id": cluster["cluster_id"],
                    "dedup_key": cluster["dedup_key"], "dedup_cluster_size": cluster["dedup_cluster_size"],
                    "prompt_strategy": strategy, "model": model, "app": alert.get("app", ""),
                    "alert_name": alert.get("alert_name", ""), "zap_cwe_id": alert.get("zap_cwe_id", ""),
                    "cweid": alert.get("cweid", ""), "pluginid": alert.get("pluginid", ""),
                    "risk": alert.get("risk", ""), "zap_confidence": alert.get("confidence", ""),
                    "url": alert.get("url", ""), "description": alert.get("description", ""),
                    "evidence": alert.get("evidence", ""), "param": alert.get("param", ""),
                    "attack": alert.get("attack", ""), "other": alert.get("other", ""),
                    "request_method": alert.get("request_method", ""),
                    "plugin_id": alert.get("plugin_id", ""),
                    "authentication_context": alert.get("authentication_context", ""),
                    "target_version": alert.get("target_version", ""),
                    "target_image_digest": alert.get("target_image_digest", ""),
                    "environment_lock_sha256": alert.get("environment_lock_sha256", ""),
                    **output,
                })
    expected = len(clusters) and sum(cluster["dedup_cluster_size"] for cluster in clusters) * len(STRATEGIES)
    if len(expanded) != expected:
        raise ValueError(f"Dedup re-expansion mismatch: expected {expected}, got {len(expanded)}")
    return expanded, diagnostics


def _normalised_alert_name(value: str) -> str:
    return normalize_text(value)


def _name_matches(rule_name: str, alert_name: str) -> bool:
    normalized_rule = _normalised_alert_name(rule_name)
    normalized_alert = _normalised_alert_name(alert_name)
    return normalized_alert == normalized_rule or normalized_alert in ALERT_NAME_ALIASES.get(normalized_rule, set())


def _evidence_bundle(alert: dict) -> str:
    return "\n".join(str(alert.get(field, "")) for field in ("evidence", "attack", "description"))


def load_semantic_taxonomy(path: Path = SEMANTIC_TAXONOMY_PATH) -> dict:
    data = _load_json(path)
    if not isinstance(data.get("version"), str) or not data["version"].strip():
        raise ValueError("Semantic taxonomy requires a version")
    families = data.get("families")
    if not isinstance(families, dict) or not families:
        raise ValueError("Semantic taxonomy requires canonical families")
    aliases: dict[str, str] = {}
    for family, definition in families.items():
        canonical = normalize_text(family).replace(" ", "_")
        if canonical != family or not re.fullmatch(r"[a-z][a-z0-9_]*", family):
            raise ValueError(f"Invalid canonical vulnerability family: {family}")
        values = [family.replace("_", " "), *(definition.get("aliases") or [])]
        for value in values:
            alias = normalize_text(value)
            if not alias:
                raise ValueError(f"Blank alias in semantic family {family}")
            if alias in aliases:
                raise ValueError(
                    f"Duplicate semantic alias {alias!r} in {family} and {aliases[alias]}"
                )
            aliases[alias] = family
    return {"version": data["version"], "families": families, "aliases": aliases}


def _strict_cwe(value) -> str:
    normalized = normalize_cwe_id(value)
    return normalized if re.fullmatch(r"CWE-[1-9][0-9]*", normalized) else ""


def _compatible_cwes(value: str) -> tuple[str, ...]:
    raw = [item.strip() for item in str(value or "").split("|") if item.strip()]
    normalized = tuple(_strict_cwe(item) for item in raw)
    if not raw or any(not item for item in normalized) or len(set(normalized)) != len(normalized):
        raise ValueError(f"Invalid or duplicate compatible_llm_cwe_ids: {value!r}")
    return normalized


def _semantic_ground_truth_label(match: dict) -> str:
    if match["ground_truth_label"] == "NOT_VULNERABLE":
        return "SAFE"
    expected_family = match.get("expected_vulnerability_family", "")
    expected_cwes = tuple(match.get("compatible_llm_cwe_ids", ()))
    if expected_family and expected_cwes:
        return f"{expected_family}|{expected_cwes[0]}"
    return "UNRESOLVED_GROUND_TRUTH"


def _semantic_label_universes(audit: list[dict]) -> dict[str, list[str]]:
    """Build one stable application label universe before population filtering."""
    applications = sorted({str(row.get("app", "")) for row in audit})
    positive_labels = {app: set() for app in applications}
    for row in audit:
        if row.get("ground_truth_label") != "VULNERABLE":
            continue
        label = _semantic_ground_truth_label(row)
        if label == "UNRESOLVED_GROUND_TRUTH":
            raise ValueError(
                "Validated vulnerable matches require a resolved canonical semantic label"
            )
        positive_labels[str(row.get("app", ""))].add(label)
    return {
        app: ["SAFE", *sorted(positive_labels[app]), OTHER_POSITIVE_LABEL]
        for app in applications
    }


def _semantic_evaluation_prediction(predicted: str, label_universe: list[str]) -> str:
    if predicted == "SAFE" or predicted in label_universe[1:-1]:
        return predicted
    return OTHER_POSITIVE_LABEL


def _semantic_assessment(record: dict, match: dict, taxonomy: dict) -> dict:
    confirmed = record.get("confirmed")
    raw_family = str(record.get("vulnerability_type", "")).strip()
    raw_cwe = str(record.get("cwe_id", "")).strip()
    canonical_family = taxonomy["aliases"].get(normalize_text(raw_family), "UNRECOGNIZED")
    canonical_cwe = _strict_cwe(raw_cwe) or "INVALID_CWE"
    expected_family = match.get("expected_vulnerability_family", "")
    expected_cwes = tuple(match.get("compatible_llm_cwe_ids", ()))
    truth = _semantic_ground_truth_label(match)
    predicted = "SAFE" if confirmed is False else f"{canonical_family}|{canonical_cwe}"
    family_ok = bool(expected_family and canonical_family == expected_family)
    cwe_ok = bool(expected_cwes and canonical_cwe in expected_cwes)
    if match["ground_truth_label"] == "NOT_VULNERABLE":
        correct = confirmed is False
        reason = "correct_safe" if correct else "false_positive"
    elif confirmed is not True:
        correct, reason = False, "false_negative_verdict"
    elif canonical_family == "UNRECOGNIZED":
        correct, reason = False, "unrecognized_family"
    elif canonical_cwe == "INVALID_CWE":
        correct, reason = False, "invalid_cwe"
    elif family_ok and cwe_ok:
        correct, reason = True, "correct_semantic_positive"
        predicted = f"{expected_family}|{expected_cwes[0]}"
        truth = predicted
    elif not family_ok and not cwe_ok:
        correct, reason = False, "family_and_cwe_mismatch"
    elif not family_ok:
        correct, reason = False, "family_mismatch"
    else:
        correct, reason = False, "cwe_mismatch"
    return {
        "raw_model_family": raw_family,
        "canonical_model_family": canonical_family,
        "raw_model_cwe": raw_cwe,
        "canonical_model_cwe": canonical_cwe,
        "expected_vulnerability_family": expected_family,
        "compatible_llm_cwe_ids": "|".join(expected_cwes),
        "family_compatible": family_ok,
        "cwe_compatible": cwe_ok,
        "semantic_ground_truth_label": truth,
        "semantic_predicted_label": predicted,
        "semantic_correct": correct,
        "semantic_error_reason": reason,
    }


def _evaluation_protocol(taxonomy_path=SEMANTIC_TAXONOMY_PATH, rules_path=RULES_PATH,
                         validation_path=VALIDATION_PATH) -> dict:
    taxonomy = load_semantic_taxonomy(taxonomy_path)
    components = {
        "version": EVALUATION_PROTOCOL_VERSION,
        "scoring_policy": SEMANTIC_SCORING_POLICY,
        "taxonomy_sha256": hashlib.sha256(Path(taxonomy_path).read_bytes()).hexdigest(),
        "match_rules_sha256": hashlib.sha256(Path(rules_path).read_bytes()).hexdigest(),
        "validation_overlay_sha256": hashlib.sha256(Path(validation_path).read_bytes()).hexdigest(),
        "taxonomy_version": taxonomy["version"],
        "semantic_rule_fields": ["expected_vulnerability_family", "compatible_llm_cwe_ids"],
        "semantic_label_universe_policy": SEMANTIC_LABEL_UNIVERSE_POLICY,
        "provenance_matching_policy": PROVENANCE_MATCHING_POLICY,
    }
    encoded = json.dumps(components, sort_keys=True, separators=(",", ":")).encode()
    return {**components, "fingerprint_sha256": hashlib.sha256(encoded).hexdigest()}


def load_automated_rules(
    rules_path: Path = RULES_PATH,
    ground_truth_path: Path = GROUND_TRUTH_PATH,
    validation_path: Path = VALIDATION_PATH,
) -> tuple[list[dict], list[dict]]:
    """Load validated metric rules and candidate/supporting audit-only rules."""
    gt = load_ground_truth(ground_truth_path)
    validation = load_detection_validation(validation_path, gt)
    known_providers = set(gt["challenge_id"])
    required = {
        "rule_id", "rule_status", "app", "zap_alert_name", "zap_cwe_id", "url_regex",
        "evidence_regex", "negative_evidence_regex", "ground_truth_label", "provider_key", "rationale",
        "expected_vulnerability_family", "compatible_llm_cwe_ids",
    }
    rules_df = pd.read_csv(rules_path, dtype=str).fillna("")
    missing = required.difference(rules_df.columns)
    if missing:
        raise ValueError(f"Ground-truth rules are missing columns: {sorted(missing)}")
    for column in RULE_PROVENANCE_COLUMNS:
        if column not in rules_df.columns:
            rules_df[column] = ""
    if rules_df["rule_id"].str.strip().duplicated().any():
        raise ValueError("Ground-truth rule IDs must be unique")
    taxonomy = load_semantic_taxonomy()
    validated, provisional = [], []
    for _, row in rules_df.iterrows():
        rule_id = row["rule_id"].strip()
        status = row["rule_status"].strip().lower()
        label = row["ground_truth_label"].strip().upper()
        provider_key = row["provider_key"].strip()
        expected_family = ""
        compatible_cwes: tuple[str, ...] = ()
        if not rule_id or status not in {"validated", "candidate", "supporting_only"}:
            raise ValueError(f"Rule {rule_id or '<blank>'} has invalid rule_status")
        if label not in {"VULNERABLE", "NOT_VULNERABLE"}:
            raise ValueError(f"Rule {rule_id} has invalid ground_truth_label")
        if not all(row[field].strip() for field in ("app", "zap_alert_name", "zap_cwe_id")):
            raise ValueError(f"Rule {rule_id} must define app, zap_alert_name, and zap_cwe_id")
        if provider_key and provider_key not in known_providers:
            raise ValueError(f"Rule {rule_id} references unknown provider_key {provider_key}")
        if label == "VULNERABLE":
            expected_family = row["expected_vulnerability_family"].strip()
            if expected_family not in taxonomy["families"]:
                raise ValueError(f"Vulnerable rule {rule_id} has unknown canonical family {expected_family!r}")
            compatible_cwes = _compatible_cwes(row["compatible_llm_cwe_ids"])
            if not provider_key:
                raise ValueError(f"Vulnerable rule {rule_id} must define provider_key")
            matching_validation = validation[
                (validation["provider_key"] == provider_key)
                & (validation["validation_status"] == "validated")
                & (validation["app"] == normalize_text(row["app"]))
                & (validation["zap_alert_name"].map(normalize_text) == normalize_text(row["zap_alert_name"]))
                & (validation["zap_cwe_id"].map(normalize_cwe_id) == normalize_cwe_id(row["zap_cwe_id"]))
                & (validation["url_regex"].str.strip() == row["url_regex"].strip())
                & (validation["evidence_regex"].str.strip() == row["evidence_regex"].strip())
            ]
            for field in RULE_PROVENANCE_COLUMNS:
                if row[field].strip():
                    matching_validation = matching_validation[
                        matching_validation[field].str.strip() == row[field].strip()
                    ]
            if status == "validated" and len(matching_validation) != 1:
                raise ValueError(f"Vulnerable rule {rule_id} must exactly match one validated overlay row")
        try:
            rule = {
                "rule_id": rule_id, "rule_status": status, "app": normalize_text(row["app"]),
                "zap_alert_name": normalize_text(row["zap_alert_name"]),
                "zap_cwe_id": normalize_cwe_id(row["zap_cwe_id"]),
                "url_pattern": re.compile(row["url_regex"], re.IGNORECASE) if row["url_regex"] else None,
                "evidence_pattern": re.compile(row["evidence_regex"], re.IGNORECASE | re.DOTALL) if row["evidence_regex"] else None,
                "negative_evidence_pattern": re.compile(row["negative_evidence_regex"], re.IGNORECASE | re.DOTALL) if row["negative_evidence_regex"] else None,
                "param_pattern": re.compile(row["param_regex"], re.IGNORECASE) if row["param_regex"] else None,
                "plugin_id": row["plugin_id"].strip(),
                "request_method": row["request_method"].strip().upper(),
                "authentication_context": row["authentication_context"].strip().lower(),
                "target_version": row["target_version"].strip(),
                "target_image_digest": row["target_image_digest"].strip(),
                "environment_lock_sha256": row["environment_lock_sha256"].strip(),
                "validation_basis": row["validation_basis"].strip().lower(),
                "source_ref": row["source_ref"].strip(),
                "expected_vulnerability_family": expected_family if label == "VULNERABLE" else "",
                "compatible_llm_cwe_ids": compatible_cwes if label == "VULNERABLE" else (),
                "ground_truth_label": label, "provider_key": provider_key, "rationale": row["rationale"].strip(),
            }
        except re.error as error:
            raise ValueError(f"Rule {rule_id} contains an invalid regex: {error}") from error
        if label == "NOT_VULNERABLE" and (
            row["expected_vulnerability_family"].strip()
            or row["compatible_llm_cwe_ids"].strip()
        ):
            raise ValueError(f"Not-vulnerable rule {rule_id} must leave semantic fields blank")
        juice_provenance_missing = (
            label == "VULNERABLE"
            and rule["app"] == "juice_shop"
            and status == "validated"
            and any(not rule[field] for field in (
                "target_version", "target_image_digest", "environment_lock_sha256",
            ))
        )
        if juice_provenance_missing:
            rule["rule_status"] = "candidate_version_unbound"
            rule["rationale"] = (
                rule["rationale"] + " Exact Juice Shop environment provenance has not "
                "been captured; this rule is audit-only until --capture-environment-lock binds it."
            )
            provisional.append(rule)
        else:
            (validated if status == "validated" else provisional).append(rule)

    represented_providers = {rule["provider_key"] for rule in provisional if rule.get("provider_key")}
    for _, row in validation[validation["validation_status"].isin({"candidate", "supporting_only"})].iterrows():
        if row["provider_key"] in represented_providers:
            continue
        if not all(str(row[field]).strip() for field in ("zap_alert_name", "zap_cwe_id", "url_regex")):
            continue
        try:
            provisional.append({
                "rule_id": f"validation_{row['provider_key']}", "rule_status": row["validation_status"],
                "app": normalize_text(row["app"]), "zap_alert_name": normalize_text(row["zap_alert_name"]),
                "zap_cwe_id": normalize_cwe_id(row["zap_cwe_id"]),
                "url_pattern": re.compile(row["url_regex"], re.IGNORECASE),
                "evidence_pattern": re.compile(row["evidence_regex"], re.IGNORECASE | re.DOTALL) if str(row["evidence_regex"]).strip() else None,
                "negative_evidence_pattern": None, "ground_truth_label": "VULNERABLE",
                "param_pattern": re.compile(row["param_regex"], re.IGNORECASE) if str(row["param_regex"]).strip() else None,
                "plugin_id": str(row["plugin_id"]).strip(),
                "request_method": str(row["request_method"]).strip().upper(),
                "authentication_context": str(row["authentication_context"]).strip().lower(),
                "target_version": str(row["target_version"]).strip(),
                "target_image_digest": str(row["target_image_digest"]).strip(),
                "environment_lock_sha256": str(row["environment_lock_sha256"]).strip(),
                "validation_basis": str(row["validation_basis"]).strip().lower(),
                "source_ref": str(row["source_ref"]).strip(),
                "expected_vulnerability_family": "",
                "compatible_llm_cwe_ids": (),
                "provider_key": row["provider_key"], "rationale": row["rationale"],
            })
        except re.error as error:
            raise ValueError(f"Validation row {row['provider_key']} contains invalid regex: {error}") from error
    return validated, provisional


def _rule_matches(rule: dict, alert: dict) -> bool:
    if rule["app"] != normalize_text(alert.get("app", "")):
        return False
    if not _name_matches(rule["zap_alert_name"], alert.get("alert_name", "")):
        return False
    if rule["zap_cwe_id"] != normalize_cwe_id(alert.get("zap_cwe_id", alert.get("cweid", ""))):
        return False
    if rule["url_pattern"] and not rule["url_pattern"].search(normalize_url_path(alert.get("url", ""))):
        return False
    evidence = _evidence_bundle(alert)
    if rule["evidence_pattern"] and not rule["evidence_pattern"].search(evidence):
        return False
    if rule.get("plugin_id") and rule["plugin_id"] != str(alert.get("plugin_id", alert.get("pluginid", ""))).strip():
        return False
    if rule.get("request_method") and rule["request_method"] != str(alert.get("request_method", "")).strip().upper():
        return False
    if rule.get("param_pattern") and not rule["param_pattern"].search(str(alert.get("param", ""))):
        return False
    authentication = str(alert.get("authentication_context", "")).strip().lower()
    if (rule.get("authentication_context") or "") not in {"", "any", authentication}:
        return False
    for field in ("target_image_digest", "environment_lock_sha256"):
        if rule.get(field) and rule[field] != str(alert.get(field, "")).strip():
            return False
    if target_version_match_basis(rule, alert) not in ACCEPTED_VERSION_MATCH_BASES:
        return False
    return not (rule["negative_evidence_pattern"] and rule["negative_evidence_pattern"].search(evidence))


def _unmatched_version_basis(alert: dict, rules: list[dict]) -> str:
    """Expose an otherwise matching rule rejected by an explicit version conflict."""
    for rule in rules:
        if target_version_match_basis(rule, alert) != "conflict":
            continue
        rule_without_version = {**rule, "target_version": ""}
        if _rule_matches(rule_without_version, alert):
            return "conflict"
    return ""


def build_match_audit(alerts: list[dict], validated_rules: list[dict], provisional_rules: list[dict]) -> list[dict]:
    family_counts = Counter(f"{alert.get('app', '')}|{alert.get('alert_name', '')}|{alert.get('zap_cwe_id', '')}" for alert in alerts)
    audit = []
    for alert in alerts:
        matches = [rule for rule in validated_rules if _rule_matches(rule, alert)]
        if len(matches) > 1:
            raise ValueError(f"Alert {alert['alert_id']} matches overlapping validated rules: {[rule['rule_id'] for rule in matches]}")
        provisional_matches = [rule for rule in provisional_rules if _rule_matches(rule, alert)]
        family = f"{alert.get('app', '')}|{alert.get('alert_name', '')}|{alert.get('zap_cwe_id', '')}"
        if matches:
            rule = matches[0]
            match = {"ground_truth_label": rule["ground_truth_label"], "ground_truth": rule["ground_truth_label"] == "VULNERABLE", "matched_rule_id": rule["rule_id"], "rule_status": rule["rule_status"], "provider_key": rule["provider_key"], "rationale": rule["rationale"], "validation_basis": rule.get("validation_basis", ""), "source_ref": rule.get("source_ref", ""), "version_match_basis": target_version_match_basis(rule, alert), "expected_vulnerability_family": rule.get("expected_vulnerability_family", ""), "compatible_llm_cwe_ids": rule.get("compatible_llm_cwe_ids", ()), "provisional_rule_ids": ""}
        elif provisional_matches:
            match = {"ground_truth_label": "PROVISIONAL", "ground_truth": None, "matched_rule_id": "", "rule_status": "provisional", "provider_key": "|".join(rule["provider_key"] for rule in provisional_matches), "rationale": " | ".join(rule["rationale"] for rule in provisional_matches), "validation_basis": "|".join(sorted({rule.get("validation_basis", "") for rule in provisional_matches if rule.get("validation_basis")})), "source_ref": "|".join(sorted({rule.get("source_ref", "") for rule in provisional_matches if rule.get("source_ref")})), "version_match_basis": "|".join(sorted({target_version_match_basis(rule, alert) for rule in provisional_matches})), "expected_vulnerability_family": "", "compatible_llm_cwe_ids": (), "provisional_rule_ids": "|".join(rule["rule_id"] for rule in provisional_matches)}
        else:
            match = {"ground_truth_label": "UNMAPPED", "ground_truth": None, "matched_rule_id": "", "rule_status": "", "provider_key": "", "rationale": "No validated or provisional ground-truth rule matched this alert.", "validation_basis": "", "source_ref": "", "version_match_basis": _unmatched_version_basis(alert, validated_rules + provisional_rules), "expected_vulnerability_family": "", "compatible_llm_cwe_ids": (), "provisional_rule_ids": ""}
        audit.append({
            "alert_id": alert["alert_id"], "cluster_id": alert["cluster_id"], "app": alert.get("app", ""),
            "alert_name": alert.get("alert_name", ""), "zap_cwe_id": alert.get("zap_cwe_id", ""),
            "pluginid": alert.get("pluginid", ""), "risk": alert.get("risk", ""), "url": alert.get("url", ""),
            "evidence": alert.get("evidence", ""), "param": alert.get("param", ""),
            "request_method": alert.get("request_method", ""),
            "authentication_context": alert.get("authentication_context", ""),
            "target_version": alert.get("target_version", ""),
            "target_image_digest": alert.get("target_image_digest", ""),
            "environment_lock_sha256": alert.get("environment_lock_sha256", ""),
            "alert_family": family,
            "alert_family_frequency": family_counts[family], **match,
        })
    return audit


def _ece(y_true, probability, bins=10):
    y_true, probability = np.asarray(y_true, dtype=float), np.asarray(probability, dtype=float)
    edges, rows = np.linspace(0.0, 1.0, bins + 1), []
    for index in range(bins):
        mask = (probability >= edges[index]) & ((probability < edges[index + 1]) if index < bins - 1 else (probability <= edges[index + 1]))
        if mask.any():
            rows.append({"bin": index, "count": int(mask.sum()), "mean_vulnerability_probability": float(probability[mask].mean()), "observed_rate": float(y_true[mask].mean()), "absolute_gap": float(abs(probability[mask].mean() - y_true[mask].mean()))})
    return (float(sum(row["absolute_gap"] * row["count"] for row in rows) / len(y_true)) if len(y_true) else 0.0), rows


def _mcnemar(correct_a, correct_b) -> dict:
    table = [[0, 0], [0, 0]]
    for left, right in zip(correct_a, correct_b):
        table[int(left)][int(right)] += 1
    if table[0][1] == table[1][0] == 0:
        return {"statistic": 0.0, "p_value": 1.0, "table": table}
    result = mcnemar(table, exact=True)
    return {"statistic": float(result.statistic), "p_value": float(result.pvalue), "table": table}


def _wilcoxon(correctness: dict[str, list[int]]) -> list[dict]:
    rows = []
    for first, second in combinations(STRATEGIES, 2):
        left, right = correctness[first], correctness[second]
        if np.array_equal(left, right):
            statistic, p_value = 0.0, 1.0
        else:
            result = wilcoxon(left, right, zero_method="wilcox", alternative="two-sided")
            statistic, p_value = float(result.statistic), float(result.pvalue)
        rows.append({"comparison": f"{first} vs {second}", "statistic": statistic, "raw_p_value": p_value, "bonferroni_p_value": min(1.0, p_value * 3)})
    return rows


def _validate_pairs(records: list[dict]) -> dict[str, dict[str, dict]]:
    by_strategy = {strategy: {} for strategy in STRATEGIES}
    for record in records:
        strategy, alert_id = record.get("prompt_strategy"), str(record.get("alert_id", ""))
        if strategy not in by_strategy or not alert_id:
            raise ValueError("Every pipeline record requires a known prompt_strategy and alert_id")
        if alert_id in by_strategy[strategy]:
            raise ValueError(f"Duplicate alert_id {alert_id} for {strategy}")
        by_strategy[strategy][alert_id] = record
    expected = set(by_strategy[STRATEGIES[0]])
    for strategy in STRATEGIES:
        if set(by_strategy[strategy]) != expected:
            raise ValueError(f"Paired design violation for {strategy}")
    return by_strategy


def write_validation_coverage_artifacts(run_dir: Path, audit: list[dict]) -> dict:
    gt = load_ground_truth(GROUND_TRUTH_PATH)
    validation = load_detection_validation(VALIDATION_PATH, gt)
    detected_providers = {
        provider
        for row in audit if row["ground_truth_label"] == "VULNERABLE"
        for provider in str(row.get("provider_key", "")).split("|") if provider
    }
    automatable_rows = []
    manual_rows = []
    for _, row in validation.iterrows():
        record = {column: row.get(column, "") for column in validation.columns}
        mode = str(row.get("validated_detection_mode") or row.get("current_detection_mode", "")).lower()
        if row.get("validation_status") == "validated" and mode in {"zap_active", "zap_passive"}:
            record["coverage_status"] = (
                "detected" if row["provider_key"] in detected_providers else "missed"
            )
            automatable_rows.append(record)
        else:
            record["coverage_status"] = "excluded_from_primary_alert_metrics"
            manual_rows.append(record)
    negatives = [row for row in audit if row["ground_truth_label"] == "NOT_VULNERABLE"]
    pd.DataFrame(automatable_rows).to_csv(
        run_dir / "automatable_expected_findings.csv", index=False,
    )
    pd.DataFrame(manual_rows).to_csv(
        run_dir / "manual_unsupported_catalogue.csv", index=False,
    )
    pd.DataFrame(negatives).to_csv(
        run_dir / "validated_negative_controls.csv", index=False,
    )
    summary = {
        "automatable_expected_count": len(automatable_rows),
        "automatable_detected_count": sum(
            row["coverage_status"] == "detected" for row in automatable_rows
        ),
        "automatable_missed_count": sum(
            row["coverage_status"] == "missed" for row in automatable_rows
        ),
        "manual_or_unsupported_count": len(manual_rows),
        "validated_negative_alert_count": len(negatives),
        "primary_denominator_policy": (
            "Only exact validated ZAP-automatable alert matches enter primary metrics."
        ),
    }
    _write_json(run_dir / "validation_coverage_summary.json", summary)
    return summary


def _assessment_origin(record: dict) -> str:
    origin = str(record.get("assessment_origin", "")).strip()
    if origin in {"initial", "strategy_preserving_repair", "legacy_repair", "unparsed"}:
        return origin
    if record.get("repaired"):
        return "legacy_repair"
    return "initial" if record.get("parsed_successfully") else "unparsed"


def _cluster_records(by_strategy: dict[str, dict[str, dict]]) -> dict[str, dict[str, dict]]:
    clustered = {strategy: {} for strategy in STRATEGIES}
    for strategy in STRATEGIES:
        for record in by_strategy[strategy].values():
            cluster_id = str(record.get("cluster_id", ""))
            existing = clustered[strategy].setdefault(cluster_id, record)
            if _assessment_origin(existing) != _assessment_origin(record):
                raise ValueError(
                    f"Cluster {cluster_id} has inconsistent assessment provenance for {strategy}"
                )
    return clustered


def _record_vulnerability_probability(record: dict) -> float | None:
    if record.get("probability_contract_version") != PROBABILITY_CONTRACT_VERSION:
        return None
    value = record.get("vulnerability_probability")
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not np.isfinite(value)
        or not 0 <= value <= 1
    ):
        return None
    return float(value)


def _calibration_contract_status(
    population_clusters: set[str],
    records_by_cluster: dict[str, dict[str, dict]],
) -> str:
    if not population_clusters:
        return "unavailable_no_eligible_clusters"
    records = [
        records_by_cluster[strategy][cluster_id]
        for strategy in STRATEGIES
        for cluster_id in population_clusters
    ]
    if all(_record_vulnerability_probability(record) is not None for record in records):
        return "available"
    if all("vulnerability_probability" not in record for record in records):
        return "unavailable_legacy_undefined_confidence"
    return "unavailable_missing_or_mixed_probability_contract"


def _evaluate_cluster_population(
    apps: set[str],
    population_clusters: set[str],
    cluster_labels: dict[str, bool],
    cluster_apps: dict[str, str],
    records_by_cluster: dict[str, dict[str, dict]],
    parse_rates: dict[str, float],
    semantic_by_cluster: dict[str, dict[str, dict]],
    semantic_label_universes: dict[str, list[str]],
) -> tuple[dict, list[dict], list[dict], list[dict], list[dict], list[dict]]:
    app_status = {}
    metrics_rows, calibration_rows, stats_rows = [], [], []
    boolean_metrics_rows, boolean_stats_rows = [], []
    for app in sorted(apps):
        semantic_labels = semantic_label_universes[app]
        app_clusters = {
            cluster_id
            for cluster_id in population_clusters
            if cluster_apps.get(cluster_id) == app
        }
        positives = sum(cluster_labels[cluster_id] for cluster_id in app_clusters)
        negatives = len(app_clusters) - positives
        if not positives:
            app_status[app] = "insufficient_validated_positives"
            continue
        if not negatives:
            app_status[app] = "insufficient_validated_negatives"
            continue
        app_status[app] = "complete"
        correctness, boolean_correctness = {}, {}
        for strategy in STRATEGIES:
            rows = []
            for cluster_id in sorted(app_clusters):
                record = records_by_cluster[strategy][cluster_id]
                rows.append(
                    (
                        cluster_labels[cluster_id],
                        bool(record["confirmed"]),
                        _record_vulnerability_probability(record),
                    )
                )
            y_true = np.array([row[0] for row in rows], dtype=int)
            y_pred = np.array([row[1] for row in rows], dtype=int)
            semantic_rows = [semantic_by_cluster[strategy][cluster_id] for cluster_id in sorted(app_clusters)]
            semantic_true = [row["semantic_ground_truth_label"] for row in semantic_rows]
            semantic_pred = [row["semantic_predicted_label"] for row in semantic_rows]
            semantic_evaluation_pred = [
                _semantic_evaluation_prediction(label, semantic_labels)
                for label in semantic_pred
            ]
            if any(label not in semantic_labels for label in semantic_true):
                raise ValueError(
                    f"Semantic ground truth for {app} is outside its fixed label universe"
                )
            semantic_correct = [int(row["semantic_correct"]) for row in semantic_rows]
            probabilities = [row[2] for row in rows]
            probability_available = all(value is not None for value in probabilities)
            if probability_available:
                probability = np.array(probabilities, dtype=float)
                ece, bins = _ece(y_true, probability)
                brier = brier_score_loss(y_true, probability)
                signed_gap = float((probability - y_true).mean())
                calibration_status = "available"
            else:
                ece, bins, brier, signed_gap = None, [], None, None
                calibration_status = (
                    "unavailable_legacy_undefined_confidence"
                    if all("vulnerability_probability" not in records_by_cluster[strategy][cluster_id] for cluster_id in app_clusters)
                    else "unavailable_missing_or_mixed_probability_contract"
                )
            report = classification_report(
                y_true,
                y_pred,
                labels=[0, 1],
                target_names=["SAFE", "VULNERABLE"],
                output_dict=True,
                zero_division=0,
            )
            boolean_metrics_rows.append({
                "app": app, "prompt_strategy": strategy,
                "precision": precision_score(y_true, y_pred, zero_division=0),
                "recall": recall_score(y_true, y_pred, zero_division=0),
                "f1_macro": f1_score(y_true, y_pred, average="macro", zero_division=0),
                "f1_weighted": f1_score(y_true, y_pred, average="weighted", zero_division=0),
                "kappa": cohen_kappa_score(y_true, y_pred),
                "brier_score": brier, "ece": ece,
                "signed_calibration_gap": signed_gap,
                "calibration_status": calibration_status,
                "probability_contract_version": (
                    PROBABILITY_CONTRACT_VERSION if probability_available else ""
                ),
                "sample_count": len(rows), "positive_count": int(y_true.sum()),
                "negative_count": int((y_true == 0).sum()),
                "parse_success_rate": parse_rates[strategy],
                "false_negative_count": int(((y_true == 1) & (y_pred == 0)).sum()),
                "prediction_distribution": json.dumps({
                    "predicted_vulnerable": int(y_pred.sum()),
                    "predicted_safe": int((y_pred == 0).sum()),
                    "actual_vulnerable": int(y_true.sum()),
                    "actual_safe": int((y_true == 0).sum()),
                }),
                "classification_report": json.dumps({
                    label: report[label] for label in ("SAFE", "VULNERABLE")
                }),
            })
            semantic_report = classification_report(
                semantic_true, semantic_evaluation_pred, labels=semantic_labels,
                output_dict=True, zero_division=0,
            )
            positive_mask = np.array(y_true, dtype=bool)
            metrics_rows.append({
                "evaluation_contract": EVALUATION_PROTOCOL_VERSION,
                "app": app, "prompt_strategy": strategy,
                "semantic_exact_match_accuracy": accuracy_score(semantic_true, semantic_pred),
                "semantic_macro_f1": f1_score(
                    semantic_true, semantic_evaluation_pred, labels=semantic_labels,
                    average="macro", zero_division=0,
                ),
                "validated_positive_semantic_recall": (
                    float(np.array(semantic_correct)[positive_mask].mean())
                    if positive_mask.any() else 0.0
                ),
                "brier_score": brier, "ece": ece,
                "signed_calibration_gap": signed_gap,
                "calibration_status": calibration_status,
                "probability_contract_version": (
                    PROBABILITY_CONTRACT_VERSION if probability_available else ""
                ),
                "sample_count": len(rows), "positive_count": int(y_true.sum()),
                "negative_count": int((y_true == 0).sum()),
                "parse_success_rate": parse_rates[strategy],
                "semantic_label_universe_policy": SEMANTIC_LABEL_UNIVERSE_POLICY["version"],
                "semantic_label_universe": json.dumps(semantic_labels),
                "error_reason_distribution": json.dumps(dict(Counter(
                    row["semantic_error_reason"] for row in semantic_rows
                )), sort_keys=True),
                "classification_report": json.dumps({
                    label: semantic_report[label] for label in semantic_labels
                }, sort_keys=True),
            })
            calibration_rows.extend([
                {
                    **bin_row,
                    "app": app,
                    "prompt_strategy": strategy,
                    "probability_contract_version": PROBABILITY_CONTRACT_VERSION,
                }
                for bin_row in bins
            ])
            correctness[strategy] = semantic_correct
            boolean_correctness[strategy] = (y_true == y_pred).astype(int).tolist()
        primary = _mcnemar(correctness["zero_shot"], correctness["cot"])
        stats_rows.append({
            "app": app, "test": "mcnemar_primary", "comparison": "cot vs zero_shot",
            **primary,
        })
        for first, second in combinations(STRATEGIES, 2):
            result = _mcnemar(correctness[first], correctness[second])
            stats_rows.append({
                "app": app, "test": "mcnemar_secondary",
                "comparison": f"{first} vs {second}", **result,
            })
        if len(next(iter(correctness.values()))) >= 2 and not (
            np.array_equal(correctness["zero_shot"], correctness["few_shot"])
            and np.array_equal(correctness["zero_shot"], correctness["cot"])
        ):
            friedman = friedmanchisquare(*[correctness[strategy] for strategy in STRATEGIES])
            stats_rows.append({
                "app": app, "test": "friedman", "comparison": "all strategies",
                "statistic": float(friedman.statistic), "p_value": float(friedman.pvalue),
            })
        stats_rows.extend(
            {"app": app, "test": "wilcoxon_secondary", **row}
            for row in _wilcoxon(correctness)
        )
        for first, second in combinations(STRATEGIES, 2):
            result = _mcnemar(boolean_correctness[first], boolean_correctness[second])
            boolean_stats_rows.append({
                "app": app,
                "test": "mcnemar_primary" if (first, second) == ("zero_shot", "cot") else "mcnemar_secondary",
                "comparison": f"{first} vs {second}", **result,
            })
        if len(next(iter(boolean_correctness.values()))) >= 2 and not (
            np.array_equal(boolean_correctness["zero_shot"], boolean_correctness["few_shot"])
            and np.array_equal(boolean_correctness["zero_shot"], boolean_correctness["cot"])
        ):
            friedman = friedmanchisquare(*[boolean_correctness[s] for s in STRATEGIES])
            boolean_stats_rows.append({
                "app": app, "test": "friedman", "comparison": "all strategies",
                "statistic": float(friedman.statistic), "p_value": float(friedman.pvalue),
            })
        boolean_stats_rows.extend(
            {"app": app, "test": "wilcoxon_secondary", **row}
            for row in _wilcoxon(boolean_correctness)
        )
    return (app_status, metrics_rows, calibration_rows, stats_rows,
            boolean_metrics_rows, boolean_stats_rows)


def _population_status(app_status: dict, positive_count: int) -> str:
    if not positive_count:
        return "insufficient_validated_positives"
    if any(value == "complete" for value in app_status.values()):
        return (
            "complete"
            if all(value == "complete" for value in app_status.values())
            else "complete_partial"
        )
    return "insufficient_validated_labels"


def evaluate_post_triage(run_dir: Path, records: list[dict], diagnostics: dict) -> dict:
    """Apply independent rules only after pipeline results have been persisted."""
    taxonomy = load_semantic_taxonomy()
    evaluation_protocol = _evaluation_protocol()
    by_strategy = _validate_pairs(records)
    base_alerts = [by_strategy[STRATEGIES[0]][alert_id] for alert_id in sorted(by_strategy[STRATEGIES[0]], key=lambda value: int(value))]
    validated, provisional = load_automated_rules()
    audit = build_match_audit(base_alerts, validated, provisional)
    semantic_label_universes = _semantic_label_universes(audit)
    pd.DataFrame(audit).to_csv(run_dir / "ground_truth_match_audit.csv", index=False)
    unmapped = [row for row in audit if row["ground_truth_label"] in {"UNMAPPED", "PROVISIONAL"}]
    _write_json(run_dir / "unmapped_alerts.json", unmapped)
    validation_coverage = write_validation_coverage_artifacts(run_dir, audit)

    audit_by_id = {row["alert_id"]: row for row in audit}
    triage_rows, seen_cluster_strategies = [], set()
    for strategy in STRATEGIES:
        for record in records:
            if record.get("prompt_strategy") != strategy:
                continue
            key = (str(record.get("cluster_id", "")), strategy)
            if key in seen_cluster_strategies:
                continue
            seen_cluster_strategies.add(key)
            match = audit_by_id[str(record["alert_id"])]
            semantic = _semantic_assessment(record, match, taxonomy)
            label_universe = semantic_label_universes[str(record.get("app", ""))]
            triage_rows.append({
                "zap_alert_name": record.get("alert_name", ""),
                "app": record.get("app", ""),
                "url": record.get("url", ""),
                "cwe": record.get("zap_cwe_id", record.get("cweid", "")),
                "strategy": strategy,
                "llm_verdict": record.get("confirmed", ""),
                "llm_vulnerability_probability": (
                    _record_vulnerability_probability(record)
                    if _record_vulnerability_probability(record) is not None
                    else ""
                ),
                "probability_contract_version": record.get(
                    "probability_contract_version", "legacy_undefined"
                ),
                "verdict_threshold": record.get("verdict_threshold", ""),
                "legacy_llm_confidence": (
                    record.get("confidence", "")
                    if "vulnerability_probability" not in record
                    else ""
                ),
                "assessment_origin": _assessment_origin(record),
                "repair_attempted": bool(
                    record.get("repair_attempted", record.get("initial_parse_error"))
                ),
                "repaired": bool(record.get("repaired", False)),
                **semantic,
                "semantic_evaluation_predicted_label": (
                    _semantic_evaluation_prediction(
                        semantic["semantic_predicted_label"], label_universe,
                    )
                    if isinstance(record.get("confirmed"), bool) else ""
                ),
                "semantic_label_universe": json.dumps(label_universe),
                "ground_truth_label": match["ground_truth_label"],
                "matched_rule": match["matched_rule_id"],
                "duplicate_count": record.get("dedup_cluster_size", 1),
            })
    pd.DataFrame(triage_rows, columns=TRIAGE_RESULT_COLUMNS).to_csv(
        run_dir / "triage_results.csv", index=False,
    )
    parsed_rates = {strategy: diagnostics["strategies"][strategy]["parse_success_rate"] for strategy in STRATEGIES}
    initial_parsed_rates = {}
    for strategy in STRATEGIES:
        strategy_diagnostics = diagnostics["strategies"][strategy]
        if "initial_parse_success_rate" in strategy_diagnostics:
            initial_parsed_rates[strategy] = strategy_diagnostics["initial_parse_success_rate"]
        else:
            attempted = int(strategy_diagnostics.get("attempted_calls", 0))
            failures = int(strategy_diagnostics.get("initial_failures", 0))
            initial_parsed_rates[strategy] = (
                (attempted - failures) / attempted if attempted else parsed_rates[strategy]
            )
    parse_blocked = [strategy for strategy, rate in parsed_rates.items() if rate < PARSE_SUCCESS_THRESHOLD]
    cluster_labels: dict[str, bool] = {}
    for row in audit:
        if row["ground_truth_label"] in {"VULNERABLE", "NOT_VULNERABLE"}:
            label = row["ground_truth_label"] == "VULNERABLE"
            if row["cluster_id"] in cluster_labels and cluster_labels[row["cluster_id"]] != label:
                raise ValueError(f"Cluster {row['cluster_id']} has inconsistent post-triage labels")
            cluster_labels[row["cluster_id"]] = label
    complete_clusters = {
        cluster_id for cluster_id in cluster_labels
        if all(by_strategy[strategy][alert_id]["parsed_successfully"] for strategy in STRATEGIES for alert_id, row in by_strategy[strategy].items() if row["cluster_id"] == cluster_id)
    }
    mapped_clusters = set(cluster_labels)
    records_by_cluster = _cluster_records(by_strategy)
    semantic_by_cluster = {strategy: {} for strategy in STRATEGIES}
    for strategy in STRATEGIES:
        for cluster_id, record in records_by_cluster[strategy].items():
            match = audit_by_id[str(record["alert_id"])]
            if match["ground_truth_label"] in {"VULNERABLE", "NOT_VULNERABLE"}:
                semantic_by_cluster[strategy][cluster_id] = _semantic_assessment(
                    record, match, taxonomy
                )
    cluster_apps = {
        row["cluster_id"]: row["app"]
        for row in audit
        if row["cluster_id"] in mapped_clusters
    }
    apps = {row["app"] for row in audit}
    eligible_clusters = complete_clusters if not parse_blocked else set()
    if parse_blocked:
        app_status = {app: "insufficient_parse_quality" for app in sorted(apps)}
        metrics_rows, calibration_rows, stats_rows = [], [], []
        boolean_metrics_rows, boolean_stats_rows = [], []
    else:
        (app_status, metrics_rows, calibration_rows, stats_rows,
         boolean_metrics_rows, boolean_stats_rows) = _evaluate_cluster_population(
            apps,
            eligible_clusters,
            cluster_labels,
            cluster_apps,
            records_by_cluster,
            parsed_rates,
            semantic_by_cluster,
            semantic_label_universes,
        )

    repair_free_clusters = {
        cluster_id
        for cluster_id in complete_clusters
        if all(
            _assessment_origin(records_by_cluster[strategy][cluster_id]) == "initial"
            for strategy in STRATEGIES
        )
    }
    repaired_cluster_counts = {
        strategy: sum(
            _assessment_origin(records_by_cluster[strategy][cluster_id])
            in {"strategy_preserving_repair", "legacy_repair"}
            for cluster_id in mapped_clusters
            if cluster_id in records_by_cluster[strategy]
        )
        for strategy in STRATEGIES
    }
    (
        sensitivity_app_status,
        sensitivity_metrics_rows,
        sensitivity_calibration_rows,
        sensitivity_stats_rows,
        sensitivity_boolean_metrics_rows,
        sensitivity_boolean_stats_rows,
    ) = _evaluate_cluster_population(
        apps,
        repair_free_clusters,
        cluster_labels,
        cluster_apps,
        records_by_cluster,
        initial_parsed_rates,
        semantic_by_cluster,
        semantic_label_universes,
    )

    total_validated_positive = sum(row["ground_truth_label"] == "VULNERABLE" for row in audit)
    if parse_blocked:
        status = "insufficient_parse_quality"
    elif not total_validated_positive:
        status = "insufficient_validated_positives"
    else:
        status = _population_status(app_status, total_validated_positive)
    sensitivity_positive_count = sum(
        cluster_labels[cluster_id] for cluster_id in repair_free_clusters
    )
    sensitivity_status = _population_status(
        sensitivity_app_status,
        sensitivity_positive_count,
    )
    operational_calibration_status = _calibration_contract_status(
        eligible_clusters,
        records_by_cluster,
    )
    sensitivity_calibration_status = _calibration_contract_status(
        repair_free_clusters,
        records_by_cluster,
    )
    serialized_sensitivity_metrics = [
        {
            **row,
            "classification_report": json.loads(row["classification_report"]),
            "error_reason_distribution": json.loads(row["error_reason_distribution"]),
            "semantic_label_universe": json.loads(row["semantic_label_universe"]),
        }
        for row in sensitivity_metrics_rows
    ]
    summary = {
        "evaluation_status": status, "app_status": app_status,
        "evaluation_protocol": evaluation_protocol,
        "semantic_label_universe": {
            "policy": SEMANTIC_LABEL_UNIVERSE_POLICY,
            "by_app": semantic_label_universes,
        },
        "probability_contract": {
            **PROBABILITY_CONTRACT,
            "operational_calibration_status": operational_calibration_status,
            "initial_only_calibration_status": sensitivity_calibration_status,
            "legacy_policy": (
                "Legacy confidence is retained only as legacy_llm_confidence and is never "
                "used for vulnerability-probability calibration."
            ),
        },
        "coverage": {"raw_alert_count": len(audit), "validated_mapped_alert_count": sum(row["ground_truth_label"] in {"VULNERABLE", "NOT_VULNERABLE"} for row in audit), "validated_positive_alert_count": total_validated_positive, "unmapped_alert_count": sum(row["ground_truth_label"] == "UNMAPPED" for row in audit), "provisional_alert_count": sum(row["ground_truth_label"] == "PROVISIONAL" for row in audit)},
        "parse_quality": {"threshold": PARSE_SUCCESS_THRESHOLD, "strategies": parsed_rates, "below_threshold_strategies": parse_blocked, "complete_mapped_cluster_count": len(complete_clusters), "excluded_mapped_cluster_count": len(mapped_clusters - complete_clusters)},
        "metrics": [{
            **row,
            "classification_report": json.loads(row["classification_report"]),
            "error_reason_distribution": json.loads(row["error_reason_distribution"]),
            "semantic_label_universe": json.loads(row["semantic_label_universe"]),
        } for row in metrics_rows],
        "statistics": stats_rows,
        "boolean_verdict_sensitivity": {
            "contract": "binary-vulnerability-existence-sensitivity",
            "metrics": [{
                **row,
                "prediction_distribution": json.loads(row["prediction_distribution"]),
                "classification_report": json.loads(row["classification_report"]),
            } for row in boolean_metrics_rows],
            "statistics": boolean_stats_rows,
        },
        "initial_only_sensitivity": {
            "evaluation_status": sensitivity_status,
            "policy": (
                "Exclude a mapped cluster from every strategy when any strategy used repair "
                "or failed initial parsing."
            ),
            "mapped_cluster_count": len(mapped_clusters),
            "eligible_cluster_count": len(repair_free_clusters),
            "excluded_cluster_count": len(mapped_clusters - repair_free_clusters),
            "repaired_cluster_count_by_strategy": repaired_cluster_counts,
            "initial_parse_success_rate_by_strategy": initial_parsed_rates,
            "calibration_status": sensitivity_calibration_status,
            "app_status": sensitivity_app_status,
            "metrics": serialized_sensitivity_metrics,
            "statistics": sensitivity_stats_rows,
            "boolean_verdict_sensitivity": {
                "metrics": [{
                    **row,
                    "prediction_distribution": json.loads(row["prediction_distribution"]),
                    "classification_report": json.loads(row["classification_report"]),
                } for row in sensitivity_boolean_metrics_rows],
                "statistics": sensitivity_boolean_stats_rows,
            },
        },
        "validation_coverage": validation_coverage,
    }
    _write_json(run_dir / "evaluation_summary.json", summary)
    _write_json(run_dir / "evaluation_protocol.json", evaluation_protocol)
    pd.DataFrame(metrics_rows).to_csv(run_dir / "evaluation_results.csv", index=False)
    pd.DataFrame(stats_rows).to_csv(run_dir / "statistical_results.csv", index=False)
    pd.DataFrame(boolean_metrics_rows).to_csv(
        run_dir / "boolean_verdict_evaluation_results.csv", index=False,
    )
    pd.DataFrame(boolean_stats_rows).to_csv(
        run_dir / "boolean_verdict_statistical_results.csv", index=False,
    )
    pd.DataFrame(calibration_rows).to_csv(run_dir / "calibration_results.csv", index=False)
    pd.DataFrame(sensitivity_metrics_rows).to_csv(
        run_dir / "initial_only_evaluation_results.csv", index=False,
    )
    pd.DataFrame(sensitivity_stats_rows).to_csv(
        run_dir / "initial_only_statistical_results.csv", index=False,
    )
    pd.DataFrame(sensitivity_boolean_metrics_rows).to_csv(
        run_dir / "initial_only_boolean_verdict_evaluation_results.csv", index=False,
    )
    pd.DataFrame(sensitivity_boolean_stats_rows).to_csv(
        run_dir / "initial_only_boolean_verdict_statistical_results.csv", index=False,
    )
    pd.DataFrame(sensitivity_calibration_rows).to_csv(
        run_dir / "initial_only_calibration_results.csv", index=False,
    )
    return summary


def run_automated(
    alerts: list[dict], run_dir: Path, scan_profile: str, model: str = MODEL, *, create_run_dir: bool = True,
    source_raw_alerts: Path | None = None, resume: bool = False,
) -> dict:
    run_id = run_dir.name
    canonical = [canonical_alert(alert, index) for index, alert in enumerate(alerts)]
    clusters = deduplicate_alerts(canonical)
    examples_metadata = _examples_metadata()
    protocol_sha256 = _triage_protocol_sha256(examples_metadata)
    if create_run_dir:
        run_dir.mkdir(parents=True, exist_ok=False)
    elif not run_dir.is_dir():
        raise ValueError(f"Run directory does not exist: {run_dir}")
    if resume:
        manifest = _load_json(run_dir / "manifest.json")
        expected = {
            "run_id": run_id,
            "scan_profile": scan_profile,
            "model": model,
            "source_alert_count": len(canonical),
            "cluster_count": len(clusters),
        }
        for field, value in expected.items():
            if manifest.get(field) != value:
                raise ValueError(
                    f"Resume manifest {field} mismatch: expected {value!r}, "
                    f"found {manifest.get(field)!r}"
                )
        if manifest.get("triage_protocol_sha256") != protocol_sha256:
            raise ValueError(
                "Incompatible triage checkpoint protocol; start a new triage run from the "
                "saved raw alerts with --reuse-from."
            )
        saved_clusters = _load_json(run_dir / "clusters.json")
        if not isinstance(saved_clusters, list) or _cluster_ids_sha256(saved_clusters) != _cluster_ids_sha256(clusters):
            raise ValueError("Resume source does not match the saved triage clusters")
    else:
        manifest = {
            "run_id": run_id, "created_at_utc": datetime.now(timezone.utc).isoformat(), "git_revision": _git_revision(),
            "scan_profile": scan_profile, "targets": TARGETS, "model": model, "nim_base_url": NIM_BASE_URL,
            "temperature": TEMPERATURE, "max_completion_tokens": MAX_COMPLETION_TOKENS, "strategies": STRATEGIES,
            "prompt_template_version": "automated-post-triage-v3-vulnerability-probability",
            "triage_protocol_sha256": protocol_sha256,
            "probability_contract": PROBABILITY_CONTRACT,
            "few_shot_examples": examples_metadata,
            "source_alert_count": len(canonical), "cluster_count": len(clusters),
        }
        if source_raw_alerts is not None:
            manifest["source_raw_alerts"] = str(source_raw_alerts.resolve())
        _write_json(run_dir / "manifest.json", manifest)
        _write_json(run_dir / "raw_alerts.json", canonical)
        _write_json(run_dir / "clusters.json", clusters)
    print(f"[nim] Triaging {len(clusters)} unique alert clusters with {model}.", flush=True)
    try:
        records, diagnostics = triage_clusters(
            clusters,
            run_id,
            model,
            checkpoint_dir=run_dir,
            protocol_sha256=protocol_sha256,
        )
    except (Exception, KeyboardInterrupt):
        checkpoint_path, state_path = _checkpoint_paths(run_dir)
        completed = 0
        if state_path.is_file():
            try:
                completed = int(_load_json(state_path).get("completed_assessment_count", 0))
            except (OSError, ValueError, AttributeError, TypeError):
                completed = 0
        if checkpoint_path.is_file() and state_path.is_file():
            print(
                f"[nim] Triage checkpoint preserved ({completed}/{len(clusters) * len(STRATEGIES)} complete).",
                flush=True,
            )
            print(
                f'[nim] Resume with: python -B run_pipeline.py --resume-from "{run_dir}"',
                flush=True,
            )
        raise
    _write_json(run_dir / "pipeline_results.json", records)
    _write_json(run_dir / "parse_diagnostics.json", diagnostics)
    _remove_triage_checkpoint(run_dir)
    print("[evaluation] Applying ground-truth rules and calculating metrics.", flush=True)
    summary = evaluate_post_triage(run_dir, records, diagnostics)
    return {**manifest, "evaluation_status": summary["evaluation_status"], "run_dir": str(run_dir)}


def _checkpoint_target_attempt(
    attempt_dir: Path,
    raw_zap_alerts: list[dict],
    alerts: list[dict],
    metadata: dict,
) -> None:
    attempt_dir.mkdir(parents=True, exist_ok=True)
    canonical = [canonical_alert(alert, index) for index, alert in enumerate(alerts)]
    _write_json(attempt_dir / "raw_zap_alerts.json", raw_zap_alerts)
    _write_json(attempt_dir / "raw_alerts.json", canonical)
    _write_json(attempt_dir / "scan_metadata.json", metadata)


def _recover_target_alerts(target_url: str, app: str, scan_profile: str) -> tuple[list[dict], list[dict], str]:
    try:
        raw_zap_alerts, alerts = collect_alerts(target_url, app, scan_profile)
        return raw_zap_alerts, alerts, ""
    except Exception as exc:  # Recovery must not hide the original scan failure.
        return [], [], f"{type(exc).__name__}: {exc}"


def _partial_alert_rows(alerts_by_app: dict[str, list[dict]]) -> list[dict]:
    alerts = [alert for app in TARGETS for alert in alerts_by_app.get(app, [])]
    return [canonical_alert(alert, index) for index, alert in enumerate(alerts)]


def _latest_auth_pilot_decision(output_root: Path) -> Path:
    candidates = sorted(
        output_root.glob("*/authentication_pilot_decision.json"),
        key=lambda path: path.parent.name,
        reverse=True,
    )
    if not candidates:
        raise FileNotFoundError(
            "No authentication pilot decision exists. Run --juice-auth-pilot first "
            "or select --juice-auth off explicitly."
        )
    return candidates[0]


def resolve_juice_auth_mode(
    requested: str,
    output_root: Path,
    decision_path: str | None = None,
) -> tuple[str, dict | None]:
    if requested in {"on", "off"}:
        return requested, None
    path = Path(decision_path) if decision_path else _latest_auth_pilot_decision(output_root)
    decision = _load_json(path)
    if not isinstance(decision, dict) or decision.get("decision") not in {
        "authenticated", "unauthenticated",
    }:
        raise ValueError(f"Authentication pilot decision is malformed: {path}")
    return ("on" if decision["decision"] == "authenticated" else "off"), {
        **decision, "decision_file": str(path.resolve()),
    }


def _alert_comparison_key(alert: dict) -> tuple:
    return (
        normalize_text(alert.get("alert_name", "")),
        normalize_cwe_id(alert.get("zap_cwe_id", alert.get("cweid", ""))),
        normalize_url_path(alert.get("url", "")),
        str(alert.get("request_method", "")).strip().upper(),
        str(alert.get("param", "")).strip(),
        str(alert.get("plugin_id", alert.get("pluginid", ""))).strip(),
    )


def authentication_pilot_decision(
    unauthenticated_alerts: list[dict],
    authenticated_alerts: list[dict],
    validated_rules: list[dict],
    provisional_rules: list[dict],
) -> dict:
    unauthenticated_keys = {_alert_comparison_key(alert) for alert in unauthenticated_alerts}
    audit = build_match_audit(authenticated_alerts, validated_rules, provisional_rules)
    authenticated_alert_by_id = {str(alert["alert_id"]): alert for alert in authenticated_alerts}
    new_validated = []
    for row in audit:
        alert = authenticated_alert_by_id[str(row["alert_id"])]
        if _alert_comparison_key(alert) in unauthenticated_keys:
            continue
        if row["ground_truth_label"] != "VULNERABLE":
            continue
        new_validated.append({
            "alert_id": row["alert_id"], "provider_key": row.get("provider_key", ""),
            "matched_rule_id": row.get("matched_rule_id", ""),
            "alert_family": row.get("alert_family", ""),
            "validation_basis": row.get("validation_basis", ""),
            "source_ref": row.get("source_ref", ""),
        })
    return {
        "decision": "authenticated" if new_validated else "unauthenticated",
        "gate_passed": bool(new_validated),
        "new_source_validated_positives": new_validated,
        "authenticated_audit": audit,
    }


def _load_authentication_pilot_attempt(
    attempt_dir: Path,
    auth_mode: str,
    environment: dict,
    validated_rules: list[dict],
    provisional_rules: list[dict],
) -> dict | None:
    """Load a completed pilot attempt after validating its immutable provenance."""
    if not attempt_dir.exists():
        return None
    required = (
        attempt_dir / "raw_zap_alerts.json",
        attempt_dir / "raw_alerts.json",
        attempt_dir / "scan_metadata.json",
        attempt_dir / "ground_truth_match_audit.json",
    )
    missing = [path.name for path in required if not path.is_file()]
    if missing:
        raise RuntimeError(
            f"Cannot resume incomplete authentication pilot attempt {attempt_dir}: "
            + ", ".join(missing)
        )
    raw_zap_alerts = _load_json(required[0])
    alerts = _load_json(required[1])
    metadata = _load_json(required[2])
    if not isinstance(raw_zap_alerts, list) or not isinstance(alerts, list) or not isinstance(metadata, dict):
        raise RuntimeError(f"Malformed authentication pilot artifacts in {attempt_dir}")
    target = metadata.get("target", {})
    expected_authenticated = auth_mode == "on"
    if (
        target.get("app") != "juice_shop"
        or target.get("scan_profile") != "final"
        or target.get("target_status") not in {"completed", "completed_with_warnings"}
        or bool(target.get("authentication", {}).get("enabled")) != expected_authenticated
    ):
        raise RuntimeError(f"Authentication pilot metadata is not reusable: {attempt_dir}")
    expected_context = "authenticated" if expected_authenticated else "unauthenticated"
    if any(alert.get("authentication_context") != expected_context for alert in alerts):
        raise RuntimeError(f"Authentication context mismatch in saved pilot attempt: {attempt_dir}")
    expected_lock = str(environment.get("environment_lock_sha256", ""))
    observed_locks = {str(alert.get("environment_lock_sha256", "")) for alert in alerts}
    if not expected_lock or (alerts and observed_locks != {expected_lock}):
        raise RuntimeError(f"Environment lock mismatch in saved pilot attempt: {attempt_dir}")
    audit = build_match_audit(alerts, validated_rules, provisional_rules)
    return {
        "result": {"raw_zap_alerts": raw_zap_alerts, "alerts": alerts, "metadata": target},
        "alerts": alerts,
        "audit": audit,
    }


def run_authentication_pilot(run_dir: Path, environment: dict, *, resume: bool = False) -> dict:
    """Run matched focused Juice Shop pilots and select auth only for validated gain."""
    if resume:
        if not run_dir.is_dir():
            raise ValueError(f"Authentication pilot run directory does not exist: {run_dir}")
    else:
        run_dir.mkdir(parents=True, exist_ok=False)
    validated_rules, provisional_rules = load_automated_rules()
    pilot_results = {}
    for attempt, auth_mode in enumerate(("off", "on"), start=1):
        attempt_dir = run_dir / f"attempt_{attempt}_{'authenticated' if auth_mode == 'on' else 'unauthenticated'}"
        if resume:
            saved = _load_authentication_pilot_attempt(
                attempt_dir, auth_mode, environment, validated_rules, provisional_rules,
            )
            if saved is not None:
                print(f"[juice_shop] Reusing completed pilot attempt {attempt}: {attempt_dir}", flush=True)
                pilot_results[auth_mode] = saved
                continue
        wait_for_zap()
        start_fresh_zap_session()
        reset_scan_metadata()
        result = run_scan(
            TARGETS["juice_shop"], "juice_shop", scan_profile="final",
            auth_mode=auth_mode, focused_only=True, return_details=True,
            environment=environment,
        )
        canonical = [canonical_alert(alert, index) for index, alert in enumerate(result["alerts"])]
        for alert in canonical:
            alert["cluster_id"] = cluster_token(dedup_key(alert))
        audit = build_match_audit(canonical, validated_rules, provisional_rules)
        _checkpoint_target_attempt(
            attempt_dir, result["raw_zap_alerts"], canonical,
            {"attempt": attempt, "target": result["metadata"], "audit": audit},
        )
        _write_json(attempt_dir / "ground_truth_match_audit.json", audit)
        pilot_results[auth_mode] = {"result": result, "alerts": canonical, "audit": audit}

    gate_result = authentication_pilot_decision(
        pilot_results["off"]["alerts"], pilot_results["on"]["alerts"],
        validated_rules, provisional_rules,
    )
    new_validated = gate_result["new_source_validated_positives"]
    decision = {
        "schema_version": 1,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "environment_lock_sha256": environment.get("environment_lock_sha256", ""),
        "decision": gate_result["decision"],
        "gate_passed": gate_result["gate_passed"],
        "gate": (
            "At least one authenticated-only alert must be an exact validated positive; "
            "route growth, passive alerts, and provisional matches do not count."
        ),
        "new_source_validated_positives": new_validated,
        "unauthenticated_alert_count": len(pilot_results["off"]["alerts"]),
        "authenticated_alert_count": len(pilot_results["on"]["alerts"]),
        "pilot_evidence_excluded_from_primary_metrics": True,
    }
    _write_json(run_dir / "authentication_pilot_decision.json", decision)
    _write_json(run_dir / "run_environment.json", environment)
    return {**decision, "run_id": run_dir.name, "run_dir": str(run_dir), "exit_code": 0}


def final_scan_eligibility(scan_status: dict) -> dict:
    reasons = []
    for app, target in scan_status["targets"].items():
        if target.get("status") not in {"completed", "completed_with_warnings"}:
            reasons.append(f"{app}:target_status={target.get('status')}")
            continue
        selected = target.get("selected_attempt")
        attempt = next(
            (row for row in target.get("attempts", []) if row.get("attempt") == selected),
            None,
        )
        stages = (attempt or {}).get("stages", {})
        if stages.get("broad_active_scan", {}).get("status") != "completed":
            reasons.append(f"{app}:broad_active_scan_not_completed")
        if stages.get("discovery_validation", {}).get("status") != "completed":
            reasons.append(f"{app}:required_routes_not_validated")
    return {
        "triage_eligible": not reasons,
        "reasons": reasons,
        "requirements": [
            "environment lock verified", "both targets finalized",
            "broad active scan reached 100 percent", "required routes validated",
        ],
    }


def scan_and_run(
    run_dir: Path,
    scan_profile: str,
    model: str = MODEL,
    *,
    scan_only: bool = False,
    environment: dict | None = None,
    juice_auth_mode: str = "off",
    auth_decision: dict | None = None,
) -> dict:
    if TARGET_RETRIES < 0:
        raise ValueError("ZAP_TARGET_RETRIES cannot be negative")
    target_retries = 0 if scan_profile == "final" else TARGET_RETRIES
    if scan_profile == "final" and not environment:
        raise ValueError("The final profile requires a verified environment lock")
    run_dir.mkdir(parents=True, exist_ok=False)
    status_path = run_dir / "scan_status.json"
    started_at = datetime.now(timezone.utc).isoformat()
    scan_status = {
        "schema_version": 1,
        "run_id": run_dir.name,
        "status": "in_progress",
        "scan_profile": scan_profile,
        "started_at_utc": started_at,
        "completed_at_utc": "",
        "target_retries": target_retries,
        "juice_shop_authentication": juice_auth_mode,
        "authentication_pilot_decision": auth_decision or {},
        "targets": {
            app: {
                "url": url, "status": "pending", "selected_attempt": None,
                "attempts": [], "alert_count": 0, "warnings": [],
            }
            for app, url in TARGETS.items()
        },
    }
    _write_json(status_path, scan_status)
    if environment:
        _write_json(run_dir / "run_environment.json", environment)
    print("[zap] Checking ZAP availability.", flush=True)
    reset_scan_metadata()
    selected_alerts: dict[str, list[dict]] = {}
    partial_alerts: dict[str, list[dict]] = {}
    target_items = list(TARGETS.items())
    for index, (app, url) in enumerate(target_items, start=1):
        target_status = scan_status["targets"][app]
        for attempt_number in range(1, target_retries + 2):
            attempt_dir = run_dir / "targets" / app / f"attempt_{attempt_number}"
            attempt = {
                "attempt": attempt_number,
                "status": "running",
                "started_at_utc": datetime.now(timezone.utc).isoformat(),
                "completed_at_utc": "",
                "stages": {},
                "alert_count": 0,
                "error": "",
                "recovery_error": "",
                "artifact_dir": str(attempt_dir),
            }
            target_status["status"] = "running" if attempt_number == 1 else "retrying"
            target_status["attempts"].append(attempt)
            _write_json(status_path, scan_status)

            def stage_callback(stage: str, outcome: dict) -> None:
                attempt["stages"][stage] = outcome
                _write_json(status_path, scan_status)

            print(
                f"[zap] Target {index}/{len(target_items)}: {app} ({url}); "
                f"attempt {attempt_number}/{target_retries + 1}",
                flush=True,
            )
            try:
                wait_for_zap()
                print(f"[zap] Creating isolated ZAP session for {app}.", flush=True)
                start_fresh_zap_session()
                result = run_scan(
                    url, app, scan_profile=scan_profile,
                    stage_callback=stage_callback, return_details=True,
                    auth_mode=juice_auth_mode if app == "juice_shop" else "off",
                    environment=environment,
                )
                attempt["status"] = result["status"]
                attempt["completed_at_utc"] = datetime.now(timezone.utc).isoformat()
                attempt["alert_count"] = len(result["alerts"])
                _checkpoint_target_attempt(
                    attempt_dir, result["raw_zap_alerts"], result["alerts"],
                    {"attempt": attempt, "target": result["metadata"]},
                )
                selected_alerts[app] = result["alerts"]
                partial_alerts[app] = result["alerts"]
                target_status["status"] = result["status"]
                target_status["selected_attempt"] = attempt_number
                target_status["alert_count"] = len(result["alerts"])
                target_status["warnings"] = result["metadata"].get("warnings", [])
                _write_json(status_path, scan_status)
                print(
                    f"[zap] Target complete: {app}; status={result['status']}; "
                    f"alerts={len(result['alerts'])}.",
                    flush=True,
                )
                break
            except KeyboardInterrupt:
                raw_zap_alerts, recovered, recovery_error = _recover_target_alerts(url, app, scan_profile)
                partial_alerts[app] = recovered
                attempt.update({
                    "status": "interrupted",
                    "completed_at_utc": datetime.now(timezone.utc).isoformat(),
                    "alert_count": len(recovered),
                    "error": "KeyboardInterrupt",
                    "recovery_error": recovery_error,
                })
                for stage in attempt["stages"].values():
                    if stage.get("status") == "running":
                        stage["status"] = "interrupted"
                _checkpoint_target_attempt(
                    attempt_dir, raw_zap_alerts, recovered,
                    {"attempt": attempt, "target": {"app": app, "target_url": url}},
                )
                target_status["status"] = "failed"
                scan_status["status"] = "interrupted"
                scan_status["completed_at_utc"] = datetime.now(timezone.utc).isoformat()
                _write_json(run_dir / "partial_raw_alerts.json", _partial_alert_rows(partial_alerts))
                _write_json(status_path, scan_status)
                print(f"[zap] Interrupted artifacts saved to {run_dir}.", flush=True)
                raise
            except Exception as exc:
                raw_zap_alerts, recovered, recovery_error = _recover_target_alerts(url, app, scan_profile)
                partial_alerts[app] = recovered
                attempt.update({
                    "status": "failed",
                    "completed_at_utc": datetime.now(timezone.utc).isoformat(),
                    "alert_count": len(recovered),
                    "error": f"{type(exc).__name__}: {exc}",
                    "recovery_error": recovery_error,
                })
                for stage in attempt["stages"].values():
                    if stage.get("status") == "running":
                        stage["status"] = "failed"
                _checkpoint_target_attempt(
                    attempt_dir, raw_zap_alerts, recovered,
                    {"attempt": attempt, "target": {"app": app, "target_url": url}},
                )
                _write_json(status_path, scan_status)
                print(f"[zap] {app} attempt {attempt_number} failed: {exc}", flush=True)
                if attempt_number <= target_retries:
                    print(f"[zap] Retrying {app} in a fresh ZAP session.", flush=True)
                    continue
                target_status["status"] = "failed"
                target_status["alert_count"] = len(recovered)
                _write_json(status_path, scan_status)
        else:  # Defensive; the bounded attempt loop always exits through break or exhaustion.
            target_status["status"] = "failed"

    failed_targets = [
        app for app, value in scan_status["targets"].items()
        if value["status"] in {"failed", "incomplete"}
    ]
    if failed_targets:
        scan_status["status"] = "partial_failed"
        scan_status["completed_at_utc"] = datetime.now(timezone.utc).isoformat()
        _write_json(run_dir / "partial_raw_alerts.json", _partial_alert_rows(partial_alerts))
        _write_json(status_path, scan_status)
        print(
            f"[zap] Partial run saved to {run_dir}; failed targets: {', '.join(failed_targets)}.",
            flush=True,
        )
        return {
            "run_id": run_dir.name,
            "run_dir": str(run_dir),
            "scan_profile": scan_profile,
            "targets": TARGETS,
            "source_alert_count": sum(len(rows) for rows in partial_alerts.values()),
            "scan_only": scan_only,
            "scan_status": "partial_failed",
            "failed_targets": failed_targets,
            "exit_code": 1,
        }

    alerts = [alert for app in TARGETS for alert in selected_alerts[app]]
    canonical = [canonical_alert(alert, index) for index, alert in enumerate(alerts)]
    _write_json(run_dir / "raw_alerts.json", canonical)
    write_ground_truth_candidates(canonical, run_dir / "ground_truth_candidates.csv")
    save_scan_report(alerts, str(run_dir / "zap_scan_report.json"), scan_profile=scan_profile)
    has_warnings = any(value["status"] == "completed_with_warnings" for value in scan_status["targets"].values())
    scan_status["status"] = "completed_with_warnings" if has_warnings else "completed"
    if scan_profile == "final":
        eligibility = final_scan_eligibility(scan_status)
        _write_json(run_dir / "triage_eligibility.json", eligibility)
        if not eligibility["triage_eligible"]:
            scan_status["status"] = "incomplete_not_triage_eligible"
            scan_status["completed_at_utc"] = datetime.now(timezone.utc).isoformat()
            _write_json(status_path, scan_status)
            _write_json(run_dir / "partial_raw_alerts.json", canonical)
            try:
                (run_dir / "raw_alerts.json").unlink()
            except FileNotFoundError:
                pass
            return {
                "run_id": run_dir.name, "run_dir": str(run_dir),
                "scan_profile": scan_profile, "targets": TARGETS,
                "source_alert_count": len(alerts), "scan_only": scan_only,
                "scan_status": scan_status["status"], "failed_targets": [],
                "exit_code": 1,
            }
    scan_status["completed_at_utc"] = datetime.now(timezone.utc).isoformat()
    _write_json(status_path, scan_status)
    print(
        f"[zap] Scan complete: {len(alerts)} raw alerts across {len(target_items)} targets.",
        flush=True,
    )
    print(f"[zap] Artifacts: {run_dir}", flush=True)
    if scan_only:
        return {
            "run_id": run_dir.name,
            "run_dir": str(run_dir),
            "scan_profile": scan_profile,
            "targets": TARGETS,
            "source_alert_count": len(alerts),
            "scan_only": True,
            "scan_status": scan_status["status"],
            "exit_code": 0,
        }
    print("[nim] Scan-only mode disabled; continuing to blinded triage.", flush=True)
    result = run_automated(alerts, run_dir, scan_profile, model, create_run_dir=False)
    return {**result, "scan_status": scan_status["status"], "exit_code": 0}


def benchmark_vulnerable_app(run_dir: Path, scan_profile: str = "benchmark") -> dict:
    """Run a scanner-only, official-ground-truth validation for VulnerableApp."""
    print("[zap] Checking ZAP availability.", flush=True)
    wait_for_zap()
    start_fresh_zap_session()
    reset_scan_metadata()
    target_url = TARGETS["vulnerable_app"]
    alerts = run_scan(target_url, "vulnerable_app", scan_profile=scan_profile)
    run_dir.mkdir(parents=True, exist_ok=False)
    canonical = [canonical_alert(alert, index) for index, alert in enumerate(alerts)]
    _write_json(run_dir / "raw_alerts.json", canonical)
    save_scan_report(alerts, str(run_dir / "zap_scan_report.json"), scan_profile=scan_profile)
    payload = build_vulnerable_app_benchmark_payload(alerts)
    _write_json(run_dir / "vulnerable_app_benchmark_request.json", payload)
    response = submit_vulnerable_app_benchmark(payload)
    _write_json(run_dir / "vulnerable_app_benchmark_response.json", response)
    return {
        "run_id": run_dir.name, "run_dir": str(run_dir), "scan_profile": scan_profile,
        "targets": {"vulnerable_app": target_url}, "source_alert_count": len(alerts),
        "benchmark": response,
    }


def reuse_and_run(run_dir: Path, scan_profile: str, model: str, output_root: Path, source: str | None = None) -> dict:
    source_path = resolve_reuse_source(output_root, source)
    alerts = _load_json(source_path)
    if not isinstance(alerts, list):
        raise ValueError(f"Reuse source must contain a JSON array: {source_path}")
    return run_automated(
        alerts, run_dir, scan_profile, model,
        source_raw_alerts=source_path,
    )


def resume_and_run(run_dir: Path) -> dict:
    if not run_dir.is_dir():
        raise FileNotFoundError(f"Resume run directory does not exist: {run_dir}")
    manifest_path = run_dir / "manifest.json"
    raw_alerts_path = run_dir / "raw_alerts.json"
    if not manifest_path.is_file() or not raw_alerts_path.is_file():
        raise ValueError(f"Resume run is missing manifest.json or raw_alerts.json: {run_dir}")
    manifest = _load_json(manifest_path)
    alerts = _load_json(raw_alerts_path)
    if not isinstance(manifest, dict) or not isinstance(alerts, list):
        raise ValueError(f"Resume artifacts are malformed: {run_dir}")

    results_path = run_dir / "pipeline_results.json"
    diagnostics_path = run_dir / "parse_diagnostics.json"
    if results_path.is_file() and diagnostics_path.is_file():
        records = _load_json(results_path)
        diagnostics = _load_json(diagnostics_path)
        if not isinstance(records, list) or not isinstance(diagnostics, dict):
            raise ValueError(f"Completed triage artifacts are malformed: {run_dir}")
        _remove_triage_checkpoint(run_dir)
        print("[nim] Triage artifacts already complete; resuming evaluation only.", flush=True)
        summary = evaluate_post_triage(run_dir, records, diagnostics)
        return {
            **manifest,
            "evaluation_status": summary["evaluation_status"],
            "run_dir": str(run_dir),
            "resumed": True,
        }

    checkpoint_path, state_path = _checkpoint_paths(run_dir)
    if not checkpoint_path.is_file() or not state_path.is_file():
        raise ValueError(
            f"Run has no resumable triage checkpoint: {run_dir}. "
            "Runs created before checkpoint support must restart from raw alerts."
        )
    return {
        **run_automated(
            alerts,
            run_dir,
            str(manifest.get("scan_profile", "benchmark")),
            str(manifest.get("model", MODEL)),
            create_run_dir=False,
            resume=True,
        ),
        "resumed": True,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description="Automated post-triage DAST evaluation pipeline")
    parser.add_argument("--scan", action="store_true", help="Run a fresh ZAP scan before triage")
    parser.add_argument(
        "--scan-only",
        action="store_true",
        help="Run ZAP against the webapps, save scan artifacts, and skip all NIM/LLM calls",
    )
    parser.add_argument(
        "--benchmark", action="store_true",
        help="Run VulnerableApp-only ZAP validation and submit it to its official benchmark endpoint",
    )
    parser.add_argument(
        "--reuse-from", metavar="RUN_OR_ALERTS",
        help="Run triage/evaluation from a previous run directory or raw_alerts.json without contacting ZAP",
    )
    parser.add_argument(
        "--capture-environment-lock", action="store_true",
        help="Capture immutable image digests, runtime versions, add-ons, and Juice Shop catalogue",
    )
    parser.add_argument(
        "--juice-auth-pilot", action="store_true",
        help="Run matched unauthenticated/authenticated focused Juice Shop pilots and save the gate decision",
    )
    parser.add_argument(
        "--resume-auth-pilot", metavar="RUN_DIR",
        help="Resume an interrupted authentication pilot, reusing completed lock-matched attempts",
    )
    parser.add_argument(
        "--juice-auth", choices=("auto", "on", "off"), default="auto",
        help="Final Juice Shop auth mode; auto consumes the latest pilot decision",
    )
    parser.add_argument(
        "--auth-decision", metavar="FILE",
        help="Explicit authentication_pilot_decision.json for --juice-auth auto",
    )
    parser.add_argument(
        "--resume-from", metavar="RUN_DIR",
        help="Resume an interrupted checkpointed triage run in place without repeating completed assessments",
    )
    parser.add_argument("--scan-profile", choices=("benchmark", "baseline", "targeted", "final"), default="benchmark")
    parser.add_argument("--model", default=MODEL)
    parser.add_argument("--output-root", default="results/runs")
    args = parser.parse_args(argv)
    requested_actions = sum(bool(value) for value in (
        args.scan, args.scan_only, args.benchmark, args.resume_from,
        args.capture_environment_lock, args.juice_auth_pilot, args.resume_auth_pilot,
    ))
    if requested_actions > 1:
        parser.error(
            "choose only one scan, benchmark, resume, environment-lock, or auth-pilot action"
        )
    if args.reuse_from and requested_actions:
        parser.error("--reuse-from cannot be combined with a scan or resume action")
    run_dir = (
        Path(args.resume_from) if args.resume_from else
        Path(args.resume_auth_pilot) if args.resume_auth_pilot else
        Path(args.output_root) / _run_id()
    )
    mode = (
        "capture environment lock" if args.capture_environment_lock else
        "resume Juice Shop authentication pilot" if args.resume_auth_pilot else
        "Juice Shop authentication pilot" if args.juice_auth_pilot else
        "resume triage + evaluation" if args.resume_from else
        "benchmark" if args.benchmark else
        "scan-only" if args.scan_only else
        "scan + triage + evaluation" if args.scan else
        "reuse + triage + evaluation"
    )
    display_profile = args.scan_profile
    display_model = args.model
    if args.resume_from and (run_dir / "manifest.json").is_file():
        resume_manifest = _load_json(run_dir / "manifest.json")
        if isinstance(resume_manifest, dict):
            display_profile = str(resume_manifest.get("scan_profile", display_profile))
            display_model = str(resume_manifest.get("model", display_model))
    print(
        f"Run {run_dir.name}: mode={mode}, profile={display_profile}"
        + (f", model={display_model}" if not args.scan_only else ""),
        flush=True,
    )
    if args.capture_environment_lock:
        lock = capture_environment_lock()
        challenge_path = LAB_DIR / lock["juice_shop_challenge_catalogue"]["local_path"]
        sync = catalogue_sync_report(GROUND_TRUTH_PATH, challenge_path)
        bind_juice_shop_provenance([RULES_PATH, VALIDATION_PATH], lock)
        _write_json(LAB_DIR / "ground_truth_catalogue_sync.json", sync)
        result = {
            "environment_lock": str(DEFAULT_LOCK_PATH),
            "ground_truth_catalogue_sync": str(LAB_DIR / "ground_truth_catalogue_sync.json"),
            "exit_code": 0,
        }
    elif args.juice_auth_pilot or args.resume_auth_pilot:
        environment = verify_environment_lock()
        result = run_authentication_pilot(
            run_dir, environment, resume=bool(args.resume_auth_pilot),
        )
    elif args.resume_from:
        result = resume_and_run(run_dir)
    elif args.benchmark:
        result = benchmark_vulnerable_app(run_dir, args.scan_profile)
        print(f"Done: benchmark artifacts saved to {run_dir}.", flush=True)
    elif args.scan or args.scan_only:
        environment = verify_environment_lock() if args.scan_profile == "final" else None
        juice_auth_mode, auth_decision = (
            resolve_juice_auth_mode(args.juice_auth, Path(args.output_root), args.auth_decision)
            if args.scan_profile == "final" else ("off", None)
        )
        result = scan_and_run(
            run_dir, args.scan_profile, args.model, scan_only=args.scan_only,
            environment=environment, juice_auth_mode=juice_auth_mode,
            auth_decision=auth_decision,
        )
    else:
        result = reuse_and_run(run_dir, args.scan_profile, args.model, Path(args.output_root), args.reuse_from)
    if result.get("exit_code", 0):
        print(
            f"Incomplete: partial scan artifacts saved to {run_dir}; "
            f"failed targets={result.get('failed_targets', [])}.",
            flush=True,
        )
    elif args.capture_environment_lock:
        print(f"Done: environment lock saved to {DEFAULT_LOCK_PATH}.", flush=True)
    elif args.juice_auth_pilot or args.resume_auth_pilot:
        print(
            f"Done: authentication pilot selected {result['decision']} mode; "
            f"artifacts saved to {run_dir}.",
            flush=True,
        )
    elif args.scan_only:
        print(f"Done: scan artifacts saved to {run_dir}.", flush=True)
    elif not args.benchmark:
        print(f"Done: results saved to {run_dir} ({result['evaluation_status']}).", flush=True)
    return result


if __name__ == "__main__":
    try:
        outcome = main()
    except KeyboardInterrupt:
        raise SystemExit(130)
    raise SystemExit(outcome.get("exit_code", 0) if isinstance(outcome, dict) else 0)
