import argparse
import json
import os
import re
import time
from dotenv import load_dotenv
from langchain_nvidia_ai_endpoints import ChatNVIDIA
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser


from zap_scanner import (
    wait_for_zap,
    run_scan,
    save_alerts,
    reset_scan_metadata,
    save_scan_report,
    start_fresh_zap_session,
)
from evaluator import (
    evaluate_pipeline_results,
    load_ground_truth,
    load_detection_validation,
    load_match_rules,
    match_alert_to_ground_truth,
    normalize_cwe_id,
)
from datetime import datetime, timezone

load_dotenv()

TARGETS = {
    "juice_shop": "http://juice-shop:3000",
    "dvwa":       "http://dvwa",
}
MODEL = "meta/llama-3.1-8b-instruct"
ALERTS_FILE = "zap_alerts.json"
GT_FILE = "ground_truth.csv"
RULES_FILE = "ground_truth_match_rules.csv"
VALIDATION_FILE = "ground_truth_detection_validation.csv"
PIPELINE_RESULTS_FILE = "pipeline_results.json"
EVALUATION_RESULTS_FILE = "evaluation_results.csv"
MATCH_AUDIT_FILE = "ground_truth_match_audit.csv"
STATISTICAL_RESULTS_FILE = "statistical_results.csv"
EVALUATION_SUMMARY_FILE = "evaluation_summary.json"
UNMAPPED_ALERTS_FILE = "unmapped_alerts.json"
PARSE_DIAGNOSTICS_FILE = "parse_diagnostics.json"
ZAP_SCAN_REPORT_FILE = "zap_scan_report.json"
RESULTS_DIR = "results"
RESULT_SUBDIRECTORIES = {
    "pipeline": "pipeline",
    "evaluation": "evaluation",
    "audit": "audit",
    "statistics": "statistics",
    "summary": "summary",
    "unmapped": "unmapped",
    "scan": "scan",
}
NIM_BASE_URL = "https://integrate.api.nvidia.com/v1"
TEMPERATURE = 0.0
MAX_COMPLETION_TOKENS = 1024
NVIDIA_API_TIMEOUT_SECONDS = float(os.getenv("NVIDIA_API_TIMEOUT_SECONDS", "300"))
NVIDIA_MAX_RETRIES = int(os.getenv("NVIDIA_MAX_RETRIES", "6"))
NVIDIA_RETRY_BASE_SECONDS = float(os.getenv("NVIDIA_RETRY_BASE_SECONDS", "5"))
NVIDIA_RETRY_MAX_SECONDS = float(os.getenv("NVIDIA_RETRY_MAX_SECONDS", "60"))
TRANSIENT_NIM_ERROR_MARKERS = (
    "[429]",
    "[500]",
    "[502]",
    "[503]",
    "[504]",
    "resourceexhausted",
    "service unavailable",
    "too many requests",
    "rate limit",
    "timed out",
    "timeout",
    "connection reset",
    "connection aborted",
)

# --- LLM SETUP ---

# Few-shot examples: 1 TP (confirmed SQL injection) + 2 FPs
# (informational timestamp disclosure and unproven CORS exposure).
# The negative majority avoids the all-positive anchoring that can bias the
# model toward VULNERABLE; it is not intended to numerically reproduce prevalence.
FEW_SHOT_EXAMPLES = """Examples:

Example 1
Alert:
Name: SQL Injection
Risk: High
Confidence: High
URL: /product?id=1
Description: SQL syntax error triggered by quote input
Evidence: database error near "'"
Output:
{"is_vulnerability": true, "vulnerability_type": "SQL Injection", "cwe_id": "CWE-89", "owasp_category": "A03:2021 Injection", "severity": "High", "confidence": 0.95, "reasoning": "Database error after SQL metacharacter suggests exploitable SQL injection.", "false_positive": false}

Example 2
Alert:
Name: Timestamp Disclosure - Unix
Risk: Low
Confidence: Low
URL: /assets/app.js
Description: Unix timestamp disclosed in static asset
Evidence: 1666666667
Output:
{"is_vulnerability": false, "vulnerability_type": "Information Disclosure", "cwe_id": "CWE-497", "owasp_category": "A01:2021 Broken Access Control", "severity": "Low", "confidence": 0.10, "reasoning": "A build timestamp in a static file is usually not exploitable and is likely a false positive.", "false_positive": true}

Example 3
Alert:
Name: Cross-Domain Misconfiguration
Risk: Medium
Confidence: Medium
URL: /api/public-data
Description: Access-Control-Allow-Origin permits requests from any origin
Evidence: Access-Control-Allow-Origin: *
Output:
{"is_vulnerability": false, "vulnerability_type": "CORS Misconfiguration", "cwe_id": "CWE-264", "owasp_category": "A05:2021 Security Misconfiguration", "severity": "Medium", "confidence": 0.15, "reasoning": "A permissive CORS header is not a confirmed vulnerability without evidence that credentials are exposed or sensitive data can be leaked cross-origin.", "false_positive": true}"""

FEW_SHOT_EXAMPLES_TEMPLATE = FEW_SHOT_EXAMPLES.replace("{", "{{").replace("}", "}}")

PROMPT_STRATEGIES = {
    "zero_shot": ChatPromptTemplate.from_messages([
        ("system", "You are a web app security expert. Analyse the ZAP scanner alert and return a JSON assessment."),
        ("human", "Alert:\nName: {alert_name}\nRisk: {risk}\nConfidence: {confidence}\nURL: {url}\nDescription: {description}\nEvidence: {evidence}\n\nReturn JSON with: is_vulnerability, vulnerability_type, cwe_id, owasp_category, severity, confidence, reasoning, false_positive. The confidence field must be a JSON number from 0.0 to 1.0: 1.0 means certain true positive and 0.0 means certain false positive. Use the full range based on the evidence and do not default to 0.5. Return only one valid JSON object. Do not include prose, Markdown fences, or comments outside or inside the JSON.")
    ]),

    "few_shot": ChatPromptTemplate.from_messages([
        ("system", "You are a web app security expert. Use the labelled examples to guide your JSON assessment."),
        ("human", FEW_SHOT_EXAMPLES_TEMPLATE + """

Now assess this alert:
Name: {alert_name}
Risk: {risk}
Confidence: {confidence}
URL: {url}
Description: {description}
Evidence: {evidence}

Return JSON with: is_vulnerability, vulnerability_type, cwe_id, owasp_category, severity, confidence, reasoning, false_positive. The confidence field must be a JSON number from 0.0 to 1.0: 1.0 means certain true positive and 0.0 means certain false positive. Use the full range based on the evidence and do not default to 0.5. Return only one valid JSON object. Do not include prose, Markdown fences, or comments outside or inside the JSON.""")
    ]),

    "cot": ChatPromptTemplate.from_messages([
        ("system", "You are a web app security expert. Think step by step internally before classifying."),
        ("human", """Analyse this ZAP scanner alert using these steps internally.

Alert: {alert_name}
Risk: {risk}
Confidence: {confidence}
URL: {url}
Description: {description}
Evidence: {evidence}

Step 1: What type of vulnerability is this?
Step 2: Could this be a false positive?
Step 3: What CWE applies?
Step 4: Before finalising, verify your reasoning contains no logical contradictions or unsupported inferences.
Step 5: Final JSON with: is_vulnerability, vulnerability_type, cwe_id, owasp_category, severity, confidence, reasoning, false_positive. The confidence field must be a JSON number from 0.0 to 1.0: 1.0 means certain true positive and 0.0 means certain false positive. Use the full range based on the evidence and do not default to 0.5. Keep the reasoning field to no more than three concise sentences. Return only one valid JSON object and do not expose the internal steps. Do not include prose, Markdown fences, or comments outside or inside the JSON.""")
    ])
}

ASSESSMENT_JSON_SCHEMA = {
    "type": "object",
    "properties": {
        "is_vulnerability": {"type": "boolean"},
        "vulnerability_type": {"type": "string"},
        "cwe_id": {"type": "string"},
        "owasp_category": {"type": "string"},
        "severity": {"type": "string"},
        "confidence": {"type": "number", "minimum": 0.0, "maximum": 1.0},
        "reasoning": {"type": "string"},
        "false_positive": {"type": "boolean"},
    },
    "required": [
        "is_vulnerability",
        "vulnerability_type",
        "cwe_id",
        "owasp_category",
        "severity",
        "confidence",
        "reasoning",
        "false_positive",
    ],
    "additionalProperties": False,
}
ASSESSMENT_RESPONSE_FORMAT = {
    "type": "json_schema",
    "json_schema": {
        "name": "vulnerability_assessment",
        "schema": ASSESSMENT_JSON_SCHEMA,
        "strict": True,
    },
}
FORMAT_REPAIR_INSTRUCTION = (
    "Your previous response was not valid JSON. Reassess the same alert under the "
    "same instructions and return only the required JSON object. Do not include prose, "
    "Markdown, comments, or internal reasoning."
)

def timestamped_output_path(filename: str, run_id: str, result_type: str) -> str:
    base, extension = os.path.splitext(os.path.basename(filename))
    output_directory = os.path.join(RESULTS_DIR, RESULT_SUBDIRECTORIES[result_type])
    return os.path.join(output_directory, f"{base}_{run_id}{extension}")


def build_run_output_paths(run_id: str) -> dict:
    return {
        "pipeline": timestamped_output_path(PIPELINE_RESULTS_FILE, run_id, "pipeline"),
        "evaluation": timestamped_output_path(EVALUATION_RESULTS_FILE, run_id, "evaluation"),
        "audit": timestamped_output_path(MATCH_AUDIT_FILE, run_id, "audit"),
        "statistics": timestamped_output_path(STATISTICAL_RESULTS_FILE, run_id, "statistics"),
        "summary": timestamped_output_path(EVALUATION_SUMMARY_FILE, run_id, "summary"),
        "unmapped": timestamped_output_path(UNMAPPED_ALERTS_FILE, run_id, "unmapped"),
        "parse_diagnostics": timestamped_output_path(
            PARSE_DIAGNOSTICS_FILE, run_id, "summary"
        ),
        "scan": timestamped_output_path(ZAP_SCAN_REPORT_FILE, run_id, "scan"),
    }


def create_output_directories(output_paths: dict) -> None:
    for path in output_paths.values():
        os.makedirs(os.path.dirname(path), exist_ok=True)


def validate_alert_scope(alerts: list[dict]) -> None:
    """Reject cached alerts that do not belong to the configured study targets."""
    unsupported_apps = sorted({
        str(alert.get("app", "")).strip() or "<missing>"
        for alert in alerts
        if (str(alert.get("app", "")).strip() or "<missing>") not in TARGETS
    })
    if unsupported_apps:
        raise ValueError(
            "Cached alert file contains out-of-scope app labels "
            f"{unsupported_apps}. Run 'python run_pipeline.py --scan' to regenerate "
            "alerts for the Juice Shop and DVWA study scope."
        )

def trim_alert_payload(alert: dict) -> dict:
    payload = dict(alert)
    payload["description"] = str(payload.get("description", ""))[:300]
    payload["evidence"] = str(payload.get("evidence", ""))[:150]
    return payload

def build_dedup_key(alert: dict) -> dict:
    """Return the complete, inspectable context used to share an inference."""
    payload = trim_alert_payload(alert)
    return {
        "app": str(payload.get("app", "")),
        "alert_name": str(payload.get("alert_name", payload.get("alert", ""))),
        "zap_cwe_id": normalize_cwe_id(payload.get("zap_cwe_id", payload.get("cweid", ""))),
        "risk": str(payload.get("risk", "")),
        "confidence": str(payload.get("confidence", "")),
        "url": str(payload.get("url", "")),
        "description": str(payload.get("description", "")),
        "evidence": str(payload.get("evidence", "")),
    }


def serialize_dedup_key(dedup_key: dict) -> str:
    return json.dumps(dedup_key, sort_keys=True, separators=(",", ":"))


def deduplicate_alerts(alerts: list[dict]) -> list[dict]:
    """Group only alerts with identical model and ground-truth context."""
    clusters_by_key = {}
    clusters = []
    for alert in alerts:
        dedup_key = build_dedup_key(alert)
        key_token = serialize_dedup_key(dedup_key)
        cluster = clusters_by_key.get(key_token)
        if cluster is None:
            cluster = {
                "dedup_key": dedup_key,
                "key_token": key_token,
                "representative": alert,
                "members": [],
            }
            clusters_by_key[key_token] = cluster
            clusters.append(cluster)
        cluster["members"].append(alert)
    return clusters

def strip_json_comments(value: str) -> str:
    result = []
    index = 0
    in_string = False
    escaped = False
    while index < len(value):
        char = value[index]
        next_char = value[index + 1] if index + 1 < len(value) else ""

        if in_string:
            result.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            index += 1
            continue

        if char == '"':
            in_string = True
            result.append(char)
            index += 1
            continue
        if char == "/" and next_char == "/":
            index += 2
            while index < len(value) and value[index] not in "\r\n":
                index += 1
            continue
        if char == "/" and next_char == "*":
            index += 2
            while index + 1 < len(value) and value[index:index + 2] != "*/":
                if value[index] in "\r\n":
                    result.append(value[index])
                index += 1
            index += 2
            continue

        result.append(char)
        index += 1
    return "".join(result)


def parse_json_candidate(candidate: str):
    try:
        return json.loads(candidate), False, None
    except Exception as original_error:
        without_comments = strip_json_comments(candidate)
        if without_comments != candidate:
            try:
                return json.loads(without_comments), True, None
            except Exception as repaired_error:
                return None, False, str(repaired_error)
        return None, False, str(original_error)


def safe_parse_json(raw_output: str):
    parsed, repaired, parse_error = parse_json_candidate(raw_output)
    if parsed is not None:
        return parsed, repaired, None

    fenced = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', raw_output, re.DOTALL)
    if fenced:
        parsed, repaired, parse_error = parse_json_candidate(fenced.group(1))
        if parsed is not None:
            return parsed, repaired, None

    loose = re.search(r'\{.*\}', raw_output, re.DOTALL)
    if loose:
        parsed, repaired, parse_error = parse_json_candidate(loose.group())
        if parsed is not None:
            return parsed, repaired, None
        return None, False, parse_error

    return None, False, "No JSON object found"


llm = None


def get_llm():
    global llm
    if llm is None:
        llm = ChatNVIDIA(
            model=MODEL,
            api_key=os.environ["NVIDIA_API_KEY"],
            base_url=NIM_BASE_URL,
            temperature=TEMPERATURE,
            max_completion_tokens=MAX_COMPLETION_TOKENS,
            timeout=NVIDIA_API_TIMEOUT_SECONDS,
        )
    return llm


def get_structured_llm():
    """Bind the hosted NIM strict JSON schema while retaining raw model text."""
    return get_llm().bind(response_format=ASSESSMENT_RESPONSE_FORMAT)


def build_assessment_chain(strategy: str, repair: bool = False):
    prompt = PROMPT_STRATEGIES[strategy]
    if repair:
        prompt = prompt + FORMAT_REPAIR_INSTRUCTION
    return prompt | get_structured_llm() | StrOutputParser()


def is_transient_nim_error(error: Exception) -> bool:
    message = str(error).lower()
    return any(marker in message for marker in TRANSIENT_NIM_ERROR_MARKERS)


def invoke_with_retry(chain, alert: dict, strategy: str) -> str:
    for attempt in range(NVIDIA_MAX_RETRIES + 1):
        try:
            return chain.invoke(alert)
        except Exception as error:
            if not is_transient_nim_error(error) or attempt >= NVIDIA_MAX_RETRIES:
                raise
            delay = min(
                NVIDIA_RETRY_BASE_SECONDS * (2 ** attempt),
                NVIDIA_RETRY_MAX_SECONDS,
            )
            error_summary = " ".join(str(error).split())[:240]
            print(
                f"  Transient NIM failure ({strategy}); retry "
                f"{attempt + 1}/{NVIDIA_MAX_RETRIES} in {delay:.1f}s: "
                f"{error_summary}",
                flush=True,
            )
            time.sleep(delay)

    raise RuntimeError("NIM retry loop exited unexpectedly")


def invoke_and_parse(chain, payload: dict, strategy: str) -> dict:
    started_at = time.perf_counter()
    raw_output = invoke_with_retry(chain, payload, strategy)
    latency_seconds = time.perf_counter() - started_at
    raw_output = "" if raw_output is None else str(raw_output)
    parsed, locally_repaired, parse_error = safe_parse_json(raw_output)
    return {
        "raw_output": raw_output,
        "parsed": parsed,
        "locally_repaired": locally_repaired,
        "parse_error": parse_error,
        "latency_seconds": latency_seconds,
    }


def assess_alert(
    alert: dict,
    strategy: str,
    cache: dict = None,
    dedup_key: dict = None,
) -> dict:
    alert = trim_alert_payload(alert)
    dedup_key = dedup_key or build_dedup_key(alert)
    key = (strategy, serialize_dedup_key(dedup_key))
    if cache is not None:
        if key in cache:
            cached_result = dict(cache[key])
            cached_result["prompt_strategy"] = strategy
            return cached_result

    initial = invoke_and_parse(
        build_assessment_chain(strategy), alert, strategy
    )
    diagnostic = {
        "initial_raw_output": initial["raw_output"],
        "initial_parse_error": initial["parse_error"],
        "initial_latency_seconds": initial["latency_seconds"],
        "repair_attempted": initial["parsed"] is None,
        "repair_raw_output": "",
        "repair_parse_error": None,
        "repair_latency_seconds": 0.0,
    }

    if initial["parsed"] is not None:
        parsed = initial["parsed"]
        parsed["raw_output"] = initial["raw_output"]
        parsed["parse_error"] = False
        parsed["json_parsed"] = True
        parsed["json_repaired"] = initial["locally_repaired"]
        parsed["prompt_strategy"] = strategy
        parsed["inference_diagnostic"] = diagnostic
        if cache is not None:
            cache[key] = parsed
        return parsed

    repair = invoke_and_parse(
        build_assessment_chain(strategy, repair=True), alert, strategy
    )
    diagnostic.update({
        "repair_raw_output": repair["raw_output"],
        "repair_parse_error": repair["parse_error"],
        "repair_latency_seconds": repair["latency_seconds"],
    })
    if repair["parsed"] is not None:
        parsed = repair["parsed"]
        parsed["raw_output"] = repair["raw_output"]
        parsed["parse_error"] = False
        parsed["json_parsed"] = True
        parsed["json_repaired"] = True
        parsed["prompt_strategy"] = strategy
        parsed["inference_diagnostic"] = diagnostic
        if cache is not None:
            cache[key] = parsed
        return parsed

    res = {
        "raw_output": repair["raw_output"],
        "parse_error": repair["parse_error"],
        "json_parsed": False,
        "json_repaired": False,
        "prompt_strategy": strategy,
        "inference_diagnostic": diagnostic,
    }
    if cache is not None:
        cache[key] = res
    print(
        f"  Parse failure ({strategy}) after format repair: {repair['parse_error']}",
        flush=True,
    )
    return res


def build_pipeline_record(
    alert: dict,
    llm_output: dict,
    strategy: str,
    run_metadata: dict,
    dedup_key: dict,
    dedup_cluster_size: int,
    inference_skipped: bool = False,
    skip_reason: str = "",
) -> dict:
    parsed_successfully = (
        bool(llm_output.get("json_parsed", False)) if not inference_skipped else False
    )
    if inference_skipped:
        predicted_vulnerable = None
    else:
        predicted_vulnerable = (
            bool(llm_output.get("is_vulnerability", False))
            if parsed_successfully else None
        )

    return {
        **run_metadata,
        "alert_id": alert["alert_id"],
        "app": alert.get("app", ""),
        "alert_name": alert.get("alert_name", alert.get("alert", "")),
        "cweid": alert.get("cweid"),
        "zap_cwe_id": normalize_cwe_id(alert.get("zap_cwe_id", alert.get("cweid", ""))),
        "pluginid": alert.get("pluginid"),
        "wascid": alert.get("wascid"),
        "url": alert.get("url", ""),
        "evidence": alert.get("evidence", ""),
        "risk": alert.get("risk", ""),
        "zap_confidence": alert.get("confidence", ""),
        "description": alert.get("description", ""),
        "solution": alert.get("solution", ""),
        "prompt_strategy": strategy,
        "dedup_key": dedup_key,
        "dedup_cluster_size": dedup_cluster_size,
        "inference_skipped": inference_skipped,
        "skip_reason": skip_reason,
        "raw_response": llm_output.get("raw_output", ""),
        "parsed_successfully": parsed_successfully,
        "json_repaired": bool(llm_output.get("json_repaired", False)),
        "predicted_vulnerable": predicted_vulnerable,
        "predicted_cwe_id": llm_output.get("cwe_id", ""),
        "predicted_severity": llm_output.get("severity"),
        "llm_confidence": llm_output.get("confidence"),
        "reasoning": llm_output.get("reasoning", ""),
        "false_positive": llm_output.get("false_positive", False),
        "parse_error": skip_reason or llm_output.get("parse_error", False),
    }


def expand_strategy_results(
    original_alerts: list[dict],
    strategy: str,
    cluster_by_alert_id: dict,
    outputs_by_key: dict,
    run_metadata: dict,
) -> list[dict]:
    expanded_results = []
    for alert in original_alerts:
        cluster = cluster_by_alert_id.get(alert["alert_id"])
        if cluster is None:
            raise ValueError(
                f"No dedup cluster found for alert_id {alert['alert_id']}"
            )

        is_unmapped = (
            cluster["ground_truth_match"]["ground_truth_label"] == "UNMAPPED"
        )
        if is_unmapped:
            skip_reason = "Inference skipped: alert is UNMAPPED by ground-truth rules."
            llm_output = {}
        else:
            skip_reason = ""
            llm_output = outputs_by_key.get(cluster["key_token"])
            if llm_output is None:
                raise ValueError(
                    f"Missing {strategy} inference for dedup key {cluster['key_token']}"
                )

        expanded_results.append(build_pipeline_record(
            alert=alert,
            llm_output=llm_output,
            strategy=strategy,
            run_metadata=run_metadata,
            dedup_key=cluster["dedup_key"],
            dedup_cluster_size=len(cluster["members"]),
            inference_skipped=is_unmapped,
            skip_reason=skip_reason,
        ))

    if len(expanded_results) != len(original_alerts):
        raise ValueError(
            "Dedup re-expansion length mismatch: "
            f"expected {len(original_alerts)}, got {len(expanded_results)}"
        )
    return expanded_results


def build_parse_diagnostics(
    mapped_clusters: list[dict],
    outputs_by_strategy: dict[str, dict],
    run_metadata: dict,
) -> dict:
    """Summarise unique NIM calls without changing pipeline result records."""
    strategies = {}
    failure_records = []
    for strategy in PROMPT_STRATEGIES:
        outputs = [
            outputs_by_strategy[strategy][cluster["key_token"]]
            for cluster in mapped_clusters
        ]
        initial_failures = [
            output for output in outputs
            if output.get("inference_diagnostic", {}).get("initial_parse_error")
        ]
        repaired_outputs = [
            output for output in outputs
            if output.get("inference_diagnostic", {}).get("repair_attempted")
        ]
        unrecoverable_outputs = [
            output for output in outputs
            if not output.get("json_parsed", False)
        ]
        total_latency_seconds = sum(
            output.get("inference_diagnostic", {}).get("initial_latency_seconds", 0.0)
            + output.get("inference_diagnostic", {}).get("repair_latency_seconds", 0.0)
            for output in outputs
        )
        strategies[strategy] = {
            "attempted_calls": len(outputs),
            "initial_failures": len(initial_failures),
            "repair_attempts": len(repaired_outputs),
            "repair_successes": sum(
                1 for output in repaired_outputs if output.get("json_parsed", False)
            ),
            "unrecoverable_failures": len(unrecoverable_outputs),
            "post_repair_parse_success_rate": (
                (len(outputs) - len(unrecoverable_outputs)) / len(outputs)
                if outputs else 0.0
            ),
            "total_latency_seconds": total_latency_seconds,
            "mean_latency_seconds": (
                total_latency_seconds / len(outputs) if outputs else 0.0
            ),
        }
        for cluster in mapped_clusters:
            output = outputs_by_strategy[strategy][cluster["key_token"]]
            diagnostic = output.get("inference_diagnostic", {})
            if not diagnostic.get("initial_parse_error"):
                continue
            failure_records.append({
                "prompt_strategy": strategy,
                "alert_ids": [member["alert_id"] for member in cluster["members"]],
                "dedup_key": cluster["dedup_key"],
                "initial_raw_response": diagnostic.get("initial_raw_output", ""),
                "initial_parse_error": diagnostic.get("initial_parse_error"),
                "initial_latency_seconds": diagnostic.get("initial_latency_seconds", 0.0),
                "repair_attempted": diagnostic.get("repair_attempted", False),
                "repair_raw_response": diagnostic.get("repair_raw_output", ""),
                "repair_parse_error": diagnostic.get("repair_parse_error"),
                "repair_latency_seconds": diagnostic.get("repair_latency_seconds", 0.0),
                "recovered": output.get("json_parsed", False),
            })

    return {
        "metadata": run_metadata,
        "parse_quality_threshold": 0.98,
        "strategies": strategies,
        "failure_records": failure_records,
    }


# --- PIPELINE RUNNER ---
def main(argv=None):
    parser = argparse.ArgumentParser(description="Run the LLM vulnerability triage pipeline")
    parser.add_argument("--scan", action="store_true", help="Run fresh ZAP scans")
    parser.add_argument(
        "--scan-profile", choices=("baseline", "targeted"), default="baseline",
        help="DAST profile; targeted runs are reported separately from baseline experiments",
    )
    parser.add_argument(
        "--print-examples",
        action="store_true",
        help="Print the complete few-shot example block and exit",
    )
    args = parser.parse_args(argv)

    if args.print_examples:
        print(FEW_SHOT_EXAMPLES)
        return

    run_started_at = datetime.now(timezone.utc)
    run_id = run_started_at.strftime("%Y%m%dT%H%M%SZ")
    output_paths = build_run_output_paths(run_id)
    create_output_directories(output_paths)
    print(
        f"Run {run_id}: model={MODEL}, temperature={TEMPERATURE}, endpoint={NIM_BASE_URL}",
        flush=True,
    )

    if args.scan or not os.path.exists(ALERTS_FILE):
        wait_for_zap()
        start_fresh_zap_session()
        reset_scan_metadata()
        alerts = []
        for label, url in TARGETS.items():
            alerts += run_scan(url, label, scan_profile=args.scan_profile)
        save_alerts(alerts)
        save_scan_report(alerts, output_paths["scan"], scan_profile=args.scan_profile)
    else:
        with open(ALERTS_FILE) as f:
            alerts = json.load(f)

    validate_alert_scope(alerts)
    alerts = [
        {
            **alert,
            "alert_id": alert_id,
            "zap_cwe_id": normalize_cwe_id(alert.get("cweid", "")),
        }
        for alert_id, alert in enumerate(alerts)
    ]
    original_alert_count = len(alerts)
    clusters = deduplicate_alerts(alerts)
    print(
        f"Exact deduplication: {len(clusters)} unique clusters from "
        f"{original_alert_count} raw alerts.",
        flush=True,
    )

    gt = load_ground_truth(GT_FILE)
    validation = load_detection_validation(VALIDATION_FILE, gt)
    rules = load_match_rules(RULES_FILE, gt, validation)
    cluster_by_alert_id = {}
    mapped_clusters = []
    mapped_alert_count = 0
    unmapped_alert_count = 0
    for cluster in clusters:
        matches = [
            match_alert_to_ground_truth(member, rules)
            for member in cluster["members"]
        ]
        labels = {match["ground_truth_label"] for match in matches}
        if len(labels) != 1:
            raise ValueError(
                f"Dedup cluster spans different ground-truth labels: {cluster['key_token']}"
            )
        cluster["ground_truth_match"] = matches[0]
        for member in cluster["members"]:
            cluster_by_alert_id[member["alert_id"]] = cluster

        cluster_size = len(cluster["members"])
        if matches[0]["ground_truth_label"] == "UNMAPPED":
            unmapped_alert_count += cluster_size
        else:
            mapped_alert_count += cluster_size
            mapped_clusters.append(cluster)

    print(
        f"Inference pre-filter: {mapped_alert_count}/{original_alert_count} mapped alerts "
        f"({len(mapped_clusters)} unique clusters) will be assessed; "
        f"{unmapped_alert_count} unmapped alerts skipped.",
        flush=True,
    )

    cache = {}
    outputs_by_strategy = {strategy: {} for strategy in PROMPT_STRATEGIES}
    for index, cluster in enumerate(mapped_clusters):
        alert = cluster["representative"]
        print(
            f"Processing mapped cluster {index + 1}/{len(mapped_clusters)}: "
            f"{alert['alert_name'][:50]}",
            flush=True,
        )
        for strategy in PROMPT_STRATEGIES.keys():
            outputs_by_strategy[strategy][cluster["key_token"]] = assess_alert(
                alert,
                strategy,
                cache,
                dedup_key=cluster["dedup_key"],
            )

    run_metadata = {
        "run_id": run_id,
        "run_timestamp_utc": run_started_at.isoformat(),
        "model": MODEL,
        "nim_base_url": NIM_BASE_URL,
        "temperature": TEMPERATURE,
        "max_completion_tokens": MAX_COMPLETION_TOKENS,
        "source_alert_count": original_alert_count,
        "alert_count": original_alert_count,
        "scan_profile": args.scan_profile,
    }
    pipeline_results = []
    for strategy in PROMPT_STRATEGIES:
        expanded_results = expand_strategy_results(
            original_alerts=alerts,
            strategy=strategy,
            cluster_by_alert_id=cluster_by_alert_id,
            outputs_by_key=outputs_by_strategy[strategy],
            run_metadata=run_metadata,
        )
        pipeline_results.extend(expanded_results)

    print(
        f"Dedup re-expansion: {len(clusters)} unique alerts → "
        f"{original_alert_count} total rows "
        f"({original_alert_count - len(clusters)} copies injected) per strategy.",
        flush=True,
    )

    with open(output_paths["pipeline"], "w") as f:
        json.dump(pipeline_results, f, indent=2)
    print(f"\nInference results saved to {output_paths['pipeline']}", flush=True)

    parse_diagnostics = build_parse_diagnostics(
        mapped_clusters=mapped_clusters,
        outputs_by_strategy=outputs_by_strategy,
        run_metadata=run_metadata,
    )
    with open(output_paths["parse_diagnostics"], "w", encoding="utf-8") as f:
        json.dump(parse_diagnostics, f, indent=2)
    print(
        f"Parse diagnostics saved to {output_paths['parse_diagnostics']}",
        flush=True,
    )

    evaluate_pipeline_results(
        pipeline_results_path=output_paths["pipeline"],
        ground_truth_path=GT_FILE,
        rules_path=RULES_FILE,
        validation_path=VALIDATION_FILE,
        evaluation_output_path=output_paths["evaluation"],
        audit_output_path=output_paths["audit"],
        statistical_output_path=output_paths["statistics"],
        summary_output_path=output_paths["summary"],
        unmapped_output_path=output_paths["unmapped"],
        parse_diagnostics_output_path=output_paths["parse_diagnostics"],
    )
    print(
        f"Results saved to {output_paths['evaluation']}, {output_paths['statistics']}, "
        f"{output_paths['audit']}, {output_paths['summary']}, "
        f"{output_paths['unmapped']}, and {output_paths['parse_diagnostics']}",
        flush=True
    )

if __name__ == "__main__":
    main()
