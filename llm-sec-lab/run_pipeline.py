import os, re, json
import pandas as pd
from dotenv import load_dotenv
from langchain_nvidia_ai_endpoints import ChatNVIDIA
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser
from pydantic import BaseModel, Field

from zap_scanner import wait_for_zap, run_scan, save_alerts
from evaluator import (
    load_ground_truth, match_alert_to_ground_truth,
    find_false_negatives, compute_metrics, mcnemar_test
)

load_dotenv()

TARGETS = {
    "juice_shop": "http://juice-shop:3000",
    "dvwa":       "http://dvwa",
    "webgoat":    "http://webgoat:8080/WebGoat",
}
MODEL = "meta/llama-3.1-8b-instruct"
ALERTS_FILE = "zap_alerts.json"
GT_FILE = "ground_truth.csv"

# --- LLM SETUP ---
class VulnAssessment(BaseModel):
    is_vulnerability: bool = Field(description="True if this is a confirmed vulnerability")
    vulnerability_type: str = Field(description="Type e.g. SQLi, XSS, CSRF, Command Injection, etc.")
    cwe_id: str = Field(description="Most likely CWE ID e.g. CWE-89")
    owasp_category: str = Field(description="OWASP Top 10 category e.g. A03:2021")
    severity: str = Field(description="Critical / High / Medium / Low / Informational")
    confidence: str = Field(description="High / Medium / Low")
    reasoning: str = Field(description="Brief explanation of your reasoning")
    false_positive: bool = Field(description="True if you think this is a false positive")

PROMPT_STRATEGIES = {
    "zero_shot": ChatPromptTemplate.from_messages([
        ("system", "You are a web app security expert. Analyse the ZAP scanner alert and return a JSON assessment."),
        ("human", "Alert:\nName: {alert_name}\nRisk: {risk}\nConfidence: {confidence}\nURL: {url}\nDescription: {description}\nEvidence: {evidence}\n\nReturn JSON with: is_vulnerability, vulnerability_type, cwe_id, owasp_category, severity, confidence, reasoning, false_positive")
    ]),
    "chain_of_thought": ChatPromptTemplate.from_messages([
        ("system", "You are a web app security expert. Think step by step before classifying."),
        ("human", "Analyse this ZAP scanner alert step by step.\n\nAlert: {alert_name}\nRisk: {risk}\nConfidence: {confidence}\nURL: {url}\nDescription: {description}\nEvidence: {evidence}\n\nStep 1: What type of vulnerability is this?\nStep 2: Could this be a false positive?\nStep 3: What CWE applies?\nStep 4: Final JSON with: is_vulnerability, vulnerability_type, cwe_id, owasp_category, severity, confidence, reasoning, false_positive")
    ])
}

def assess_alert(alert: dict, strategy: str) -> dict:
    llm = ChatNVIDIA(model=MODEL, api_key=os.environ["NVIDIA_API_KEY"], temperature=0.0, max_tokens=1024)
    chain = PROMPT_STRATEGIES[strategy] | llm | StrOutputParser()
    raw_output = chain.invoke(alert)
    json_match = re.search(r'\{.*\}', raw_output, re.DOTALL)
    if json_match:
        try: return json.loads(json_match.group())
        except json.JSONDecodeError: pass
    return {"raw_output": raw_output, "parse_error": True}

# --- PIPELINE RUNNER ---
def main():
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

    results_by_strategy = {s: [] for s in PROMPT_STRATEGIES.keys()}
    for i, alert in enumerate(alerts):
        print(f"Processing alert {i+1}/{len(alerts)}: {alert['alert_name'][:50]}")
        for strategy in PROMPT_STRATEGIES.keys():
            llm_output = assess_alert(alert, strategy)
            results_by_strategy[strategy].append({"alert": alert, "llm_output": llm_output, "strategy": strategy})

    gt = load_ground_truth(GT_FILE)
    dfs = {}
    for strategy, results in results_by_strategy.items():
        rows = [match_alert_to_ground_truth(r["alert"], r["llm_output"], gt) for r in results]
        df = pd.DataFrame(rows)
        dfs[strategy] = df
        metrics = compute_metrics(df)
        fn = find_false_negatives(df, gt)
        print(f"\n── {strategy.upper()} ──")
        print(f"  Precision: {metrics['precision']:.3f} | Recall: {metrics['recall']:.3f} | F1: {metrics['f1']:.3f} | Kappa: {metrics['kappa']:.3f}")
        print(f"  Missed ground-truth vulns (False Negatives): {len(fn)}")

    print("\n── McNemar Test (zero_shot vs chain_of_thought) ──")
    mc = mcnemar_test(dfs["zero_shot"], dfs["chain_of_thought"])
    print(f"  p-value: {mc['p_value']:.4f}")

    pd.concat(dfs.values()).to_csv("evaluation_results.csv", index=False)
    print("\nResults saved to evaluation_results.csv")

if __name__ == "__main__":
    main()
