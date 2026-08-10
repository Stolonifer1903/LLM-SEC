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
from itertools import combinations
from pathlib import Path
from statistics import mean
from urllib.parse import urlsplit

import numpy as np
import pandas as pd
from scipy.stats import friedmanchisquare, wilcoxon
from sklearn.metrics import (
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

from evaluator import load_detection_validation, load_ground_truth, normalize_cwe_id, normalize_text
from zap_scanner import (
    build_vulnerable_app_benchmark_payload,
    reset_scan_metadata,
    run_scan,
    save_scan_report,
    start_fresh_zap_session,
    submit_vulnerable_app_benchmark,
    wait_for_zap,
)

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

LAB_DIR = Path(__file__).resolve().parent
GROUND_TRUTH_PATH = LAB_DIR / "ground_truth.csv"
RULES_PATH = LAB_DIR / "ground_truth_match_rules.csv"
VALIDATION_PATH = LAB_DIR / "ground_truth_detection_validation.csv"
EXAMPLES_PATH = LAB_DIR / "few_shot_examples.json"
GROUND_TRUTH_CANDIDATE_COLUMNS = (
    "zap_alert_name", "zap_cwe_id", "app", "route_pattern", "evidence_pattern",
    "status", "provider_key", "request_method", "plugin_id", "evidence_source",
)
TRIAGE_RESULT_COLUMNS = (
    "zap_alert_name", "app", "url", "cwe", "strategy", "llm_verdict",
    "llm_confidence", "ground_truth_label", "matched_rule", "duplicate_count",
)

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
        "confirmed": {"type": "boolean"},
        "confidence": {"type": "number", "minimum": 0.0, "maximum": 1.0},
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
        "confirmed", "confidence", "vulnerability_type", "cwe_id", "severity",
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
    "Return exactly one JSON object with the required fields. Do not include Markdown or prose. "
    "Always provide CVSS v3.1 AV, AC, PR, UI, and Scope metrics for the finding, even when "
    "you classify it as not confirmed."
)
ALERT_NAME_ALIASES: dict[str, set[str]] = {}
_PROMPT_CACHE: dict[tuple[str, str], ChatPromptTemplate] = {}


def _prompt(strategy: str, examples: str = "") -> ChatPromptTemplate:
    key = (strategy, examples)
    if key in _PROMPT_CACHE:
        return _PROMPT_CACHE[key]
    strategy_text = {
        "zero_shot": "Assess the ZAP alert directly using the supplied evidence.",
        "few_shot": "Use the labelled generic ZAP examples as guidance, then assess the new alert independently.",
        "cot": "Reason through vulnerability type, exploit evidence, and false-positive alternatives internally, then return only the concise JSON result.",
    }[strategy]
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
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False), encoding="utf-8")


def _load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def latest_raw_alerts_path(output_root: Path) -> Path:
    """Return the newest complete DAST raw-alert artifact for reuse."""
    candidates = sorted(
        (path for path in output_root.glob("*/raw_alerts.json") if path.is_file()),
        key=lambda path: path.parent.name,
        reverse=True,
    )
    if not candidates:
        raise FileNotFoundError(f"No raw_alerts.json artifacts found under {output_root}")
    return candidates[0]


def resolve_reuse_source(output_root: Path, source: str | None = None) -> Path:
    if not source:
        return latest_raw_alerts_path(output_root)
    candidate = Path(source)
    if candidate.is_dir():
        candidate = candidate / "raw_alerts.json"
    if not candidate.is_file():
        raise FileNotFoundError(f"Reuse source does not contain raw_alerts.json: {candidate}")
    return candidate


def _run_id() -> str:
    return datetime.now(timezone.utc).strftime("run_%Y%m%dT%H%M%SZ")


def _git_revision() -> str:
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], text=True, stderr=subprocess.DEVNULL).strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def _is_transient(error: Exception) -> bool:
    text = str(error).lower()
    return any(marker in text for marker in ("429", "500", "502", "503", "504", "timeout", "rate limit", "resourceexhausted"))


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

    def __init__(self, total_assessments: int):
        self.total = total_assessments
        self.completed = 0
        self.api_requests = 0
        self.started_at = time.perf_counter()
        self.assessment_started_at = self.started_at
        self.current_number = 0
        self.current_strategy = ""
        self.current_cluster = ""

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
        now = time.perf_counter()
        assessment_seconds = now - self.assessment_started_at
        elapsed_seconds = now - self.started_at
        mean_seconds = elapsed_seconds / self.completed
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
    for field in ASSESSMENT_SCHEMA["required"]:
        if field not in value:
            raise ValueError(f"Missing assessment field: {field}")
    if not isinstance(value["confirmed"], bool) or not 0 <= float(value["confidence"]) <= 1:
        raise ValueError("Invalid confirmed or confidence value")
    for field, choices in CVSS_CHOICES.items():
        key = f"cvss_{field}"
        if str(value[key]).upper() not in choices:
            raise ValueError(f"Invalid CVSS value for {key}")
        value[key] = str(value[key]).upper()
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
    labels = [row.get("confirmed") for row in rows]
    if labels.count(True) != 2 or labels.count(False) != 2:
        raise ValueError("few_shot_examples.json must contain two confirmed and two false examples")
    target_tokens = {"juice shop", "juice_shop", "vulnerableapp", "vulnerable app", "vulnerable_app"}
    for row in rows:
        if not str(row.get("source_url", "")).strip():
            raise ValueError("Every few-shot example must include a source_url")
        text = json.dumps(row).lower()
        if any(token in text for token in target_tokens):
            raise ValueError("Few-shot examples must not identify a study application")
    return json.dumps(rows, ensure_ascii=False)


def _examples_metadata(path: Path = EXAMPLES_PATH) -> dict:
    content = path.read_bytes()
    rows = _load_json(path)
    return {
        "file": path.name,
        "sha256": hashlib.sha256(content).hexdigest(),
        "sources": sorted({str(row["source_url"]) for row in rows}),
    }


def cvss31_exploitability(assessment: dict) -> float:
    av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}[assessment["cvss_av"]]
    ac = {"L": 0.77, "H": 0.44}[assessment["cvss_ac"]]
    ui = {"N": 0.85, "R": 0.62}[assessment["cvss_ui"]]
    pr = ({"N": 0.85, "L": 0.62, "H": 0.27} if assessment["cvss_s"] == "U" else {"N": 0.85, "L": 0.68, "H": 0.50})[assessment["cvss_pr"]]
    return round(8.22 * av * ac * pr * ui, 4)


def _repair_chain(llm):
    return ChatPromptTemplate.from_messages([
        ("system", "Return only a schema-valid JSON object for the same DAST alert."),
        ("human", "The prior response was malformed. Reassess the supplied alert and return only the required JSON object.\n" + BASE_INSTRUCTION),
    ]) | llm | StrOutputParser()


def triage_clusters(clusters: list[dict], run_id: str, model: str = MODEL) -> tuple[list[dict], dict]:
    """Perform blinded inference. This function deliberately has no ground-truth inputs."""
    examples = _load_examples()
    llm = _model(model)
    repair_chain = _repair_chain(llm)
    outputs: dict[str, dict[str, dict]] = {strategy: {} for strategy in STRATEGIES}
    diagnostics = {"metadata": {"run_id": run_id, "model": model}, "strategies": {}, "failures": []}
    progress = NimProgress(len(clusters) * len(STRATEGIES))
    for strategy in STRATEGIES:
        chain = _prompt(strategy, examples) | llm | StrOutputParser()
        stats = {"attempted_calls": 0, "initial_failures": 0, "repair_attempts": 0, "repair_successes": 0, "unrecoverable_failures": 0, "latencies": []}
        for cluster_index, cluster in enumerate(clusters, start=1):
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
            stats["attempted_calls"] += 1
            latency = time.perf_counter() - started
            stats["latencies"].append(latency)
            assessment, repair_raw, initial_error, repaired = None, "", "", False
            try:
                assessment = _parse_json(initial_raw)
            except Exception as error:
                initial_error = str(error)
                stats["initial_failures"] += 1
                stats["repair_attempts"] += 1
                print("[nim]   Invalid JSON response; requesting format repair.", flush=True)
                try:
                    repair_raw = _invoke(
                        repair_chain,
                        payload,
                        progress=progress,
                        request_kind="format repair",
                    )
                except Exception as repair_request_error:
                    progress.fail_assessment(repair_request_error)
                    raise
                try:
                    assessment = _parse_json(repair_raw)
                    repaired = True
                    stats["repair_successes"] += 1
                except Exception as repair_error:
                    stats["unrecoverable_failures"] += 1
                    diagnostics["failures"].append({
                        "prompt_strategy": strategy, "cluster_id": cluster["cluster_id"],
                        "initial_error": initial_error, "repair_error": str(repair_error),
                        "initial_response": initial_raw, "repair_response": repair_raw,
                    })
            progress.complete_assessment(assessment is not None, repaired)
            output = {
                "initial_response": initial_raw, "repair_response": repair_raw,
                "initial_parse_error": initial_error, "repaired": repaired,
                "parsed_successfully": assessment is not None, "inference_latency_seconds": latency,
            }
            if assessment is None:
                output.update({"confirmed": None, "confidence": None, "cvss_exploitability": None})
            else:
                output.update(assessment)
                output["cvss_exploitability"] = cvss31_exploitability(assessment)
            outputs[strategy][cluster["cluster_id"]] = output
        diagnostics["strategies"][strategy] = {
            **stats,
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
                    "attack": alert.get("attack", ""), "other": alert.get("other", ""), **output,
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
    }
    rules_df = pd.read_csv(rules_path, dtype=str).fillna("")
    missing = required.difference(rules_df.columns)
    if missing:
        raise ValueError(f"Ground-truth rules are missing columns: {sorted(missing)}")
    if rules_df["rule_id"].str.strip().duplicated().any():
        raise ValueError("Ground-truth rule IDs must be unique")
    validated, provisional = [], []
    for _, row in rules_df.iterrows():
        rule_id = row["rule_id"].strip()
        status = row["rule_status"].strip().lower()
        label = row["ground_truth_label"].strip().upper()
        provider_key = row["provider_key"].strip()
        if not rule_id or status not in {"validated", "candidate", "supporting_only"}:
            raise ValueError(f"Rule {rule_id or '<blank>'} has invalid rule_status")
        if label not in {"VULNERABLE", "NOT_VULNERABLE"}:
            raise ValueError(f"Rule {rule_id} has invalid ground_truth_label")
        if not all(row[field].strip() for field in ("app", "zap_alert_name", "zap_cwe_id")):
            raise ValueError(f"Rule {rule_id} must define app, zap_alert_name, and zap_cwe_id")
        if provider_key and provider_key not in known_providers:
            raise ValueError(f"Rule {rule_id} references unknown provider_key {provider_key}")
        if label == "VULNERABLE":
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
                "ground_truth_label": label, "provider_key": provider_key, "rationale": row["rationale"].strip(),
            }
        except re.error as error:
            raise ValueError(f"Rule {rule_id} contains an invalid regex: {error}") from error
        (validated if status == "validated" else provisional).append(rule)

    for _, row in validation[validation["validation_status"].isin({"candidate", "supporting_only"})].iterrows():
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
    return not (rule["negative_evidence_pattern"] and rule["negative_evidence_pattern"].search(evidence))


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
            match = {"ground_truth_label": rule["ground_truth_label"], "ground_truth": rule["ground_truth_label"] == "VULNERABLE", "matched_rule_id": rule["rule_id"], "rule_status": rule["rule_status"], "provider_key": rule["provider_key"], "rationale": rule["rationale"], "provisional_rule_ids": ""}
        elif provisional_matches:
            match = {"ground_truth_label": "PROVISIONAL", "ground_truth": None, "matched_rule_id": "", "rule_status": "provisional", "provider_key": "|".join(rule["provider_key"] for rule in provisional_matches), "rationale": " | ".join(rule["rationale"] for rule in provisional_matches), "provisional_rule_ids": "|".join(rule["rule_id"] for rule in provisional_matches)}
        else:
            match = {"ground_truth_label": "UNMAPPED", "ground_truth": None, "matched_rule_id": "", "rule_status": "", "provider_key": "", "rationale": "No validated or provisional ground-truth rule matched this alert.", "provisional_rule_ids": ""}
        audit.append({
            "alert_id": alert["alert_id"], "cluster_id": alert["cluster_id"], "app": alert.get("app", ""),
            "alert_name": alert.get("alert_name", ""), "zap_cwe_id": alert.get("zap_cwe_id", ""),
            "pluginid": alert.get("pluginid", ""), "risk": alert.get("risk", ""), "url": alert.get("url", ""),
            "evidence": alert.get("evidence", ""), "alert_family": family,
            "alert_family_frequency": family_counts[family], **match,
        })
    return audit


def _ece(y_true, confidence, bins=10):
    y_true, confidence = np.asarray(y_true, dtype=float), np.asarray(confidence, dtype=float)
    edges, rows = np.linspace(0.0, 1.0, bins + 1), []
    for index in range(bins):
        mask = (confidence >= edges[index]) & ((confidence < edges[index + 1]) if index < bins - 1 else (confidence <= edges[index + 1]))
        if mask.any():
            rows.append({"bin": index, "count": int(mask.sum()), "mean_confidence": float(confidence[mask].mean()), "observed_rate": float(y_true[mask].mean()), "absolute_gap": float(abs(confidence[mask].mean() - y_true[mask].mean()))})
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


def evaluate_post_triage(run_dir: Path, records: list[dict], diagnostics: dict) -> dict:
    """Apply independent rules only after pipeline results have been persisted."""
    by_strategy = _validate_pairs(records)
    base_alerts = [by_strategy[STRATEGIES[0]][alert_id] for alert_id in sorted(by_strategy[STRATEGIES[0]], key=lambda value: int(value))]
    validated, provisional = load_automated_rules()
    audit = build_match_audit(base_alerts, validated, provisional)
    pd.DataFrame(audit).to_csv(run_dir / "ground_truth_match_audit.csv", index=False)
    unmapped = [row for row in audit if row["ground_truth_label"] in {"UNMAPPED", "PROVISIONAL"}]
    _write_json(run_dir / "unmapped_alerts.json", unmapped)

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
            triage_rows.append({
                "zap_alert_name": record.get("alert_name", ""),
                "app": record.get("app", ""),
                "url": record.get("url", ""),
                "cwe": record.get("zap_cwe_id", record.get("cweid", "")),
                "strategy": strategy,
                "llm_verdict": record.get("confirmed", ""),
                "llm_confidence": record.get("confidence", ""),
                "ground_truth_label": match["ground_truth_label"],
                "matched_rule": match["matched_rule_id"],
                "duplicate_count": record.get("dedup_cluster_size", 1),
            })
    pd.DataFrame(triage_rows, columns=TRIAGE_RESULT_COLUMNS).to_csv(
        run_dir / "triage_results.csv", index=False,
    )
    parsed_rates = {strategy: diagnostics["strategies"][strategy]["parse_success_rate"] for strategy in STRATEGIES}
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
    eligible_clusters = complete_clusters if not parse_blocked else set()
    app_status = {}
    metrics_rows, calibration_rows, stats_rows = [], [], []
    for app in sorted({row["app"] for row in audit}):
        app_clusters = {cluster_id for cluster_id in eligible_clusters if next(row["app"] for row in audit if row["cluster_id"] == cluster_id) == app}
        positives = sum(cluster_labels[cluster_id] for cluster_id in app_clusters)
        negatives = len(app_clusters) - positives
        if parse_blocked:
            app_status[app] = "insufficient_parse_quality"
            continue
        if not positives:
            app_status[app] = "insufficient_validated_positives"
            continue
        if not negatives:
            app_status[app] = "insufficient_validated_negatives"
            continue
        app_status[app] = "complete"
        correctness = {}
        for strategy in STRATEGIES:
            rows = []
            for cluster_id in sorted(app_clusters):
                record = next(record for record in by_strategy[strategy].values() if record["cluster_id"] == cluster_id)
                rows.append((cluster_labels[cluster_id], bool(record["confirmed"]), float(record["confidence"])))
            y_true = np.array([row[0] for row in rows], dtype=int)
            y_pred = np.array([row[1] for row in rows], dtype=int)
            confidence = np.array([row[2] for row in rows], dtype=float)
            ece, bins = _ece(y_true, confidence)
            report = classification_report(y_true, y_pred, labels=[0, 1], target_names=["SAFE", "VULNERABLE"], output_dict=True, zero_division=0)
            metrics_rows.append({
                "app": app, "prompt_strategy": strategy,
                "precision": precision_score(y_true, y_pred, zero_division=0), "recall": recall_score(y_true, y_pred, zero_division=0),
                "f1_macro": f1_score(y_true, y_pred, average="macro", zero_division=0), "f1_weighted": f1_score(y_true, y_pred, average="weighted", zero_division=0),
                "kappa": cohen_kappa_score(y_true, y_pred), "brier_score": brier_score_loss(y_true, confidence), "ece": ece,
                "signed_calibration_gap": float((confidence - y_true).mean()), "sample_count": len(rows), "positive_count": int(y_true.sum()), "negative_count": int((y_true == 0).sum()),
                "parse_success_rate": parsed_rates[strategy], "false_negative_count": int(((y_true == 1) & (y_pred == 0)).sum()),
                "prediction_distribution": json.dumps({"predicted_vulnerable": int(y_pred.sum()), "predicted_safe": int((y_pred == 0).sum()), "actual_vulnerable": int(y_true.sum()), "actual_safe": int((y_true == 0).sum())}),
                "classification_report": json.dumps({label: report[label] for label in ("SAFE", "VULNERABLE")}),
            })
            calibration_rows.extend([{**bin_row, "app": app, "prompt_strategy": strategy} for bin_row in bins])
            correctness[strategy] = (y_true == y_pred).astype(int).tolist()
        primary = _mcnemar(correctness["zero_shot"], correctness["cot"])
        stats_rows.append({"app": app, "test": "mcnemar_primary", "comparison": "cot vs zero_shot", **primary})
        for first, second in combinations(STRATEGIES, 2):
            result = _mcnemar(correctness[first], correctness[second])
            stats_rows.append({"app": app, "test": "mcnemar_secondary", "comparison": f"{first} vs {second}", **result})
        if len(next(iter(correctness.values()))) >= 2 and not (np.array_equal(correctness["zero_shot"], correctness["few_shot"]) and np.array_equal(correctness["zero_shot"], correctness["cot"])):
            friedman = friedmanchisquare(*[correctness[strategy] for strategy in STRATEGIES])
            stats_rows.append({"app": app, "test": "friedman", "comparison": "all strategies", "statistic": float(friedman.statistic), "p_value": float(friedman.pvalue)})
        stats_rows.extend({"app": app, "test": "wilcoxon_secondary", **row} for row in _wilcoxon(correctness))

    total_validated_positive = sum(row["ground_truth_label"] == "VULNERABLE" for row in audit)
    if parse_blocked:
        status = "insufficient_parse_quality"
    elif not total_validated_positive:
        status = "insufficient_validated_positives"
    elif any(value == "complete" for value in app_status.values()):
        status = "complete" if all(value == "complete" for value in app_status.values()) else "complete_partial"
    else:
        status = "insufficient_validated_labels"
    summary = {
        "evaluation_status": status, "app_status": app_status,
        "coverage": {"raw_alert_count": len(audit), "validated_mapped_alert_count": sum(row["ground_truth_label"] in {"VULNERABLE", "NOT_VULNERABLE"} for row in audit), "validated_positive_alert_count": total_validated_positive, "unmapped_alert_count": sum(row["ground_truth_label"] == "UNMAPPED" for row in audit), "provisional_alert_count": sum(row["ground_truth_label"] == "PROVISIONAL" for row in audit)},
        "parse_quality": {"threshold": PARSE_SUCCESS_THRESHOLD, "strategies": parsed_rates, "below_threshold_strategies": parse_blocked, "complete_mapped_cluster_count": len(complete_clusters), "excluded_mapped_cluster_count": len(mapped_clusters - complete_clusters)},
        "metrics": [{**row, "prediction_distribution": json.loads(row["prediction_distribution"]), "classification_report": json.loads(row["classification_report"])} for row in metrics_rows],
        "statistics": stats_rows,
    }
    _write_json(run_dir / "evaluation_summary.json", summary)
    pd.DataFrame(metrics_rows).to_csv(run_dir / "evaluation_results.csv", index=False)
    pd.DataFrame(stats_rows).to_csv(run_dir / "statistical_results.csv", index=False)
    pd.DataFrame(calibration_rows).to_csv(run_dir / "calibration_results.csv", index=False)
    return summary


def run_automated(
    alerts: list[dict], run_dir: Path, scan_profile: str, model: str = MODEL, *, create_run_dir: bool = True,
    source_raw_alerts: Path | None = None,
) -> dict:
    run_id = run_dir.name
    canonical = [canonical_alert(alert, index) for index, alert in enumerate(alerts)]
    clusters = deduplicate_alerts(canonical)
    if create_run_dir:
        run_dir.mkdir(parents=True, exist_ok=False)
    elif not run_dir.is_dir():
        raise ValueError(f"Run directory does not exist: {run_dir}")
    manifest = {
        "run_id": run_id, "created_at_utc": datetime.now(timezone.utc).isoformat(), "git_revision": _git_revision(),
        "scan_profile": scan_profile, "targets": TARGETS, "model": model, "nim_base_url": NIM_BASE_URL,
        "temperature": TEMPERATURE, "max_completion_tokens": MAX_COMPLETION_TOKENS, "strategies": STRATEGIES,
        "prompt_template_version": "automated-post-triage-v1", "few_shot_examples": _examples_metadata(),
        "source_alert_count": len(canonical), "cluster_count": len(clusters),
    }
    if source_raw_alerts is not None:
        manifest["source_raw_alerts"] = str(source_raw_alerts.resolve())
    _write_json(run_dir / "manifest.json", manifest)
    _write_json(run_dir / "raw_alerts.json", canonical)
    _write_json(run_dir / "clusters.json", clusters)
    print(f"[nim] Triaging {len(clusters)} unique alert clusters with {model}.", flush=True)
    records, diagnostics = triage_clusters(clusters, run_id, model)
    _write_json(run_dir / "pipeline_results.json", records)
    _write_json(run_dir / "parse_diagnostics.json", diagnostics)
    print("[evaluation] Applying ground-truth rules and calculating metrics.", flush=True)
    summary = evaluate_post_triage(run_dir, records, diagnostics)
    return {**manifest, "evaluation_status": summary["evaluation_status"], "run_dir": str(run_dir)}


def scan_and_run(
    run_dir: Path,
    scan_profile: str,
    model: str = MODEL,
    *,
    scan_only: bool = False,
) -> dict:
    print("[zap] Checking ZAP availability.", flush=True)
    wait_for_zap()
    print("[zap] Resetting ZAP session and scan metadata.", flush=True)
    start_fresh_zap_session()
    reset_scan_metadata()
    alerts = []
    target_items = list(TARGETS.items())
    for index, (app, url) in enumerate(target_items, start=1):
        print(f"[zap] Target {index}/{len(target_items)}: {app} ({url})", flush=True)
        before = len(alerts)
        alerts.extend(run_scan(url, app, scan_profile=scan_profile))
        print(f"[zap] Target complete: {app}; alerts={len(alerts) - before}.", flush=True)
    run_dir.mkdir(parents=True, exist_ok=False)
    canonical = [canonical_alert(alert, index) for index, alert in enumerate(alerts)]
    _write_json(run_dir / "raw_alerts.json", canonical)
    write_ground_truth_candidates(canonical, run_dir / "ground_truth_candidates.csv")
    save_scan_report(alerts, str(run_dir / "zap_scan_report.json"), scan_profile=scan_profile)
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
        }
    print("[nim] Scan-only mode disabled; continuing to blinded triage.", flush=True)
    return run_automated(alerts, run_dir, scan_profile, model, create_run_dir=False)


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
    parser.add_argument("--scan-profile", choices=("benchmark", "baseline", "targeted"), default="benchmark")
    parser.add_argument("--model", default=MODEL)
    parser.add_argument("--output-root", default="results/runs")
    args = parser.parse_args(argv)
    requested_actions = sum(bool(value) for value in (args.scan, args.scan_only, args.benchmark))
    if requested_actions > 1:
        parser.error("choose only one of --scan, --scan-only, or --benchmark")
    if args.reuse_from and requested_actions:
        parser.error("--reuse-from cannot be combined with a fresh scan action")
    run_dir = Path(args.output_root) / _run_id()
    mode = "benchmark" if args.benchmark else ("scan-only" if args.scan_only else ("scan + triage + evaluation" if args.scan else "reuse + triage + evaluation"))
    print(
        f"Run {run_dir.name}: mode={mode}, profile={args.scan_profile}"
        + (f", model={args.model}" if not args.scan_only else ""),
        flush=True,
    )
    if args.benchmark:
        result = benchmark_vulnerable_app(run_dir, args.scan_profile)
        print(f"Done: benchmark artifacts saved to {run_dir}.", flush=True)
    elif args.scan or args.scan_only:
        result = scan_and_run(run_dir, args.scan_profile, args.model, scan_only=args.scan_only)
    else:
        result = reuse_and_run(run_dir, args.scan_profile, args.model, Path(args.output_root), args.reuse_from)
    if args.scan_only:
        print(f"Done: scan artifacts saved to {run_dir}.", flush=True)
    elif not args.benchmark:
        print(f"Done: results saved to {run_dir} ({result['evaluation_status']}).", flush=True)
    return result


if __name__ == "__main__":
    main()
