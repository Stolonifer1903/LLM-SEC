import os, re, json
from itertools import combinations

import pandas as pd
from dotenv import load_dotenv
from langchain_nvidia_ai_endpoints import ChatNVIDIA
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser
from scipy.stats import friedmanchisquare


from zap_scanner import wait_for_zap, run_scan, save_alerts
from evaluator import (
    load_ground_truth, match_alert_to_ground_truth,
    find_false_negatives, compute_metrics, mcnemar_test
)
import shutil
from datetime import datetime

load_dotenv()

TARGETS = {
    "juice_shop": "http://juice-shop:3000",
    "dvwa":       "http://dvwa",
    "webgoat":    "http://webgoat:8080/WebGoat",
}
MODEL = "meta/llama-3.2-3b-instruct"
ALERTS_FILE = "zap_alerts.json"
GT_FILE = "ground_truth.csv"
NVIDIA_API_TIMEOUT_SECONDS = float(os.getenv("NVIDIA_API_TIMEOUT_SECONDS", "300"))

# --- LLM SETUP ---

PROMPT_STRATEGIES = {
    "zero_shot": ChatPromptTemplate.from_messages([
        ("system", "You are a web app security expert. Analyse the ZAP scanner alert and return a JSON assessment."),
        ("human", "Alert:\nName: {alert_name}\nRisk: {risk}\nConfidence: {confidence}\nURL: {url}\nDescription: {description}\nEvidence: {evidence}\n\nReturn JSON with: is_vulnerability, vulnerability_type, cwe_id, owasp_category, severity, confidence, reasoning, false_positive")
    ]),

    "few_shot": ChatPromptTemplate.from_messages([
        ("system", "You are a web app security expert. Use the labelled examples to guide your JSON assessment."),
        ("human", """Examples:

Example 1
Alert:
Name: SQL Injection
Risk: High
Confidence: High
URL: /product?id=1
Description: SQL syntax error triggered by quote input
Evidence: database error near "'"
Output:
{{"is_vulnerability": true, "vulnerability_type": "SQL Injection", "cwe_id": "CWE-89", "owasp_category": "A03:2021 Injection", "severity": "High", "confidence": "High", "reasoning": "Database error after SQL metacharacter suggests exploitable SQL injection.", "false_positive": false}}

Example 2
Alert:
Name: Timestamp Disclosure - Unix
Risk: Low
Confidence: Low
URL: /assets/app.js
Description: Unix timestamp disclosed in static asset
Evidence: 1666666667
Output:
{{"is_vulnerability": false, "vulnerability_type": "Information Disclosure", "cwe_id": "CWE-497", "owasp_category": "A01:2021 Broken Access Control", "severity": "Low", "confidence": "Low", "reasoning": "A build timestamp in a static file is usually not exploitable and is likely a false positive.", "false_positive": true}}

Now assess this alert:
Name: {alert_name}
Risk: {risk}
Confidence: {confidence}
URL: {url}
Description: {description}
Evidence: {evidence}

Return JSON with: is_vulnerability, vulnerability_type, cwe_id, owasp_category, severity, confidence, reasoning, false_positive""")
    ]),

    "chain_of_thought": ChatPromptTemplate.from_messages([
        ("system", "You are a web app security expert. Think step by step before classifying."),
        ("human", """Analyse this ZAP scanner alert step by step.

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
Step 5: Final JSON with: is_vulnerability, vulnerability_type, cwe_id, owasp_category, severity, confidence, reasoning, false_positive""")
    ]),

    "role_play": ChatPromptTemplate.from_messages([
        ("system", "You are a senior penetration tester reviewing an automated DAST scan report. Your job is to determine whether each alert represents a genuine exploitable vulnerability or a false positive."),
        ("human", """Alert:
Name: {alert_name}
Risk: {risk}
URL: {url}
Description: {description}
Evidence: {evidence}

Return only JSON with this schema:
{{"is_vulnerability": true, "severity": "str", "cwe_id": "str", "confidence": "str", "explanation": "str"}}""")
    ])
}

def archive_previous_results():
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    for filename in ["evaluation_results.csv", "pipeline_results.json"]:
        if os.path.exists(filename):
            base, ext = os.path.splitext(filename)
            shutil.copy(filename, f"{base}_{timestamp}{ext}")
            print(f"Archived: {base}_{timestamp}{ext}")

def trim_alert_payload(alert: dict) -> dict:
    payload = dict(alert)
    payload["description"] = str(payload.get("description", ""))[:300]
    payload["evidence"] = str(payload.get("evidence", ""))[:150]
    return payload

def deduplicate_alerts(alerts: list[dict]) -> list[dict]:
    deduplicated = []
    seen = set()
    for alert in alerts:
        alert_name = alert.get("alert", alert.get("alert_name", ""))
        key = (alert_name, alert.get("url", ""))
        if key not in seen:
            seen.add(key)
            deduplicated.append(alert)
    return deduplicated

def safe_parse_json(raw_output: str):
    try:
        return json.loads(raw_output), False, None
    except Exception:
        pass

    fenced = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', raw_output, re.DOTALL)
    if fenced:
        try:
            return json.loads(fenced.group(1)), False, None
        except Exception:
            pass

    loose = re.search(r'\{.*\}', raw_output, re.DOTALL)
    if loose:
        try:
            return json.loads(loose.group()), False, None
        except Exception as e:
            return None, True, str(e)

    return None, True, "No JSON object found"


llm = ChatNVIDIA(
    model=MODEL,
    api_key=os.environ["NVIDIA_API_KEY"],
    temperature=0.0,
    max_completion_tokens=4096,
    timeout=NVIDIA_API_TIMEOUT_SECONDS
)

def assess_alert(alert: dict, strategy: str, cache: dict = None) -> dict:
    alert = trim_alert_payload(alert)
    if cache is not None:
        key = (strategy, alert.get("app"), alert.get("alert_name"), alert.get("risk"), alert.get("confidence"), alert.get("description"))
        if key in cache:
            return dict(cache[key])

    chain = PROMPT_STRATEGIES[strategy] | llm | StrOutputParser()
    raw_output = chain.invoke(alert)
    parsed, _, parse_error = safe_parse_json(raw_output)

    if parsed is not None:
        parsed["raw_output"] = raw_output
        parsed["parse_error"] = False
        parsed["json_parsed"] = True
        if cache is not None:
            cache[key] = parsed
        return parsed

    res = {
        "raw_output": raw_output,
        "parse_error": parse_error,
        "json_parsed": False
    }
    if cache is not None:
        cache[key] = res
    print(f"  Parse failure ({strategy}): {parse_error}", flush=True)
    return res

# --- PIPELINE RUNNER ---
def main():
    archive_previous_results()

    import sys
    if "--scan" in sys.argv or not os.path.exists(ALERTS_FILE):
        wait_for_zap()
        alerts = []
        for label, url in TARGETS.items():
            alerts += run_scan(url, label)
        save_alerts(alerts)
    else:
        with open(ALERTS_FILE) as f:
            alerts = json.load(f)

    original_alert_count = len(alerts)
    alerts = deduplicate_alerts(alerts)
    print(
        f"Deduplicated alerts: {len(alerts)} remain from {original_alert_count} original alerts.",
        flush=True
    )

    # Use cache to avoid redundant API queries for identical alerts (ignoring URLs)
    cache = {}
    results_by_strategy = {s: [] for s in PROMPT_STRATEGIES.keys()}
    for i, alert in enumerate(alerts):
        print(f"Processing alert {i+1}/{len(alerts)}: {alert['alert_name'][:50]}", flush=True)
        for strategy in PROMPT_STRATEGIES.keys():
            llm_output = assess_alert(alert, strategy, cache)
            results_by_strategy[strategy].append({"alert": alert, "llm_output": llm_output, "strategy": strategy})

    gt = load_ground_truth(GT_FILE)
    dfs = {}
    pipeline_results = []
    for strategy, results in results_by_strategy.items():
        rows = [match_alert_to_ground_truth(r["alert"], r["llm_output"], gt) for r in results]
        df = pd.DataFrame(rows)
        dfs[strategy] = df
        metrics = compute_metrics(df)
        fn = find_false_negatives(df, gt)
        parse_rate = df["json_parsed"].mean() if "json_parsed" in df.columns else 0.0
        print(f"\n=== {strategy.upper()} ===", flush=True)
        print(f"  Precision: {metrics['precision']:.3f} | Recall: {metrics['recall']:.3f} | F1: {metrics['f1']:.3f} | Kappa: {metrics['kappa']:.3f}", flush=True)
        print(f"  Missed ground-truth vulns (False Negatives): {len(fn)}", flush=True)
        print(f"  Parse success rate: {parse_rate:.3f}", flush=True)
        if parse_rate < 0.80:
            print("  WARNING: parse failure rate > 20% (methodology concern)", flush=True)

        for alert_id, (result, row) in enumerate(zip(results, rows)):
            parsed_successfully = bool(row["json_parsed"])
            predicted_vulnerable = bool(row["predicted_is_vuln"]) if parsed_successfully else None
            ground_truth = bool(row["gt_match"])
            pipeline_results.append({
                "alert_id": alert_id,
                "alert_name": result["alert"].get("alert_name", result["alert"].get("alert", "")),
                "url": result["alert"].get("url", ""),
                "strategy": strategy,
                "raw_response": result["llm_output"].get("raw_output", ""),
                "parsed_successfully": parsed_successfully,
                "predicted_vulnerable": predicted_vulnerable,
                "ground_truth": ground_truth,
                "correct": (predicted_vulnerable == ground_truth) if parsed_successfully else None
            })

    for strategy_a, strategy_b in combinations(PROMPT_STRATEGIES.keys(), 2):
        print(f"\n=== McNemar Test ({strategy_a} vs {strategy_b}) ===", flush=True)
        mc = mcnemar_test(dfs[strategy_a], dfs[strategy_b])
        print(f"  p-value: {mc['p_value']:.4f}", flush=True)

    correctness = []
    for strategy in PROMPT_STRATEGIES:
        df = dfs[strategy]
        strategy_correct = (
            (df["gt_match"] == df["predicted_is_vuln"]) & df["json_parsed"].astype(bool)
        ).astype(int)
        correctness.append(strategy_correct)
    friedman = friedmanchisquare(*correctness)
    print("\n=== Friedman Test (all strategies) ===", flush=True)
    print(f"  Chi-square: {friedman.statistic:.4f} | p-value: {friedman.pvalue:.4f}", flush=True)

    pd.concat(dfs.values()).to_csv("evaluation_results.csv", index=False)
    with open("pipeline_results.json", "w") as f:
        json.dump(pipeline_results, f, indent=2)
    print("\nResults saved to evaluation_results.csv and pipeline_results.json", flush=True)

if __name__ == "__main__":
    main()
