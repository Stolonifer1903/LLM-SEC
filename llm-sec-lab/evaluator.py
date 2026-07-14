import pandas as pd
from sklearn.metrics import precision_score, recall_score, f1_score, cohen_kappa_score
from statsmodels.stats.contingency_tables import mcnemar

def load_ground_truth(path="ground_truth.csv") -> pd.DataFrame:
    gt = pd.read_csv(path)
    gt["app"] = gt["app"].str.strip().str.lower()
    gt["cwe_id"] = gt["cwe_id"].str.strip().str.upper()
    return gt

def match_alert_to_ground_truth(alert: dict, llm_output: dict, gt: pd.DataFrame) -> dict:
    app = alert.get("app", "").strip().lower()
    predicted_cwe = str(llm_output.get("cwe_id", "")).strip().upper()
    predicted_vuln = bool(llm_output.get("is_vulnerability", False))

    app_rows = gt[gt["app"] == app]
    cwe_match_rows = app_rows[app_rows["cwe_id"] == predicted_cwe]
    name_match_rows = app_rows[
        app_rows["zap_alert_name"].str.lower() == str(alert.get("alert_name", "")).lower()
    ]

    gt_match = (not cwe_match_rows.empty) or (not name_match_rows.empty)
    matched_challenge_id = None
    if not cwe_match_rows.empty:
        matched_challenge_id = cwe_match_rows.iloc[0]["challenge_id"]
    elif not name_match_rows.empty:
        matched_challenge_id = name_match_rows.iloc[0]["challenge_id"]

    return {
        "app": app,
        "alert_name": alert.get("alert_name"),
        "url": alert.get("url"),
        "predicted_is_vuln": predicted_vuln,
        "predicted_cwe": predicted_cwe,
        "predicted_severity": llm_output.get("severity"),
        "gt_match": gt_match,
        "matched_challenge_id": matched_challenge_id,
        "false_positive": llm_output.get("false_positive", False),
        "llm_confidence": llm_output.get("confidence"),
        "json_parsed": llm_output.get("json_parsed", False),
        "reasoning": llm_output.get("reasoning", "")
    }

def find_false_negatives(results_df: pd.DataFrame, gt: pd.DataFrame) -> pd.DataFrame:
    matched_ids = set(results_df["matched_challenge_id"].dropna())
    fn_rows = gt[~gt["challenge_id"].isin(matched_ids)].copy()
    fn_rows["reason"] = "not_detected_by_zap_or_llm"
    return fn_rows

def compute_metrics(results_df: pd.DataFrame) -> dict:
    y_true = results_df["gt_match"].astype(int).tolist()
    y_pred = results_df["predicted_is_vuln"].astype(int).tolist()
    return {
        "precision": precision_score(y_true, y_pred, zero_division=0),
        "recall":    recall_score(y_true, y_pred, zero_division=0),
        "f1":        f1_score(y_true, y_pred, zero_division=0),
        "kappa":     cohen_kappa_score(y_true, y_pred)
    }

def mcnemar_test(results_a: pd.DataFrame, results_b: pd.DataFrame) -> dict:
    a_correct = (results_a["gt_match"] == results_a["predicted_is_vuln"]).astype(int)
    b_correct = (results_b["gt_match"] == results_b["predicted_is_vuln"]).astype(int)
    n00 = ((a_correct == 0) & (b_correct == 0)).sum()
    n01 = ((a_correct == 0) & (b_correct == 1)).sum()
    n10 = ((a_correct == 1) & (b_correct == 0)).sum()
    n11 = ((a_correct == 1) & (b_correct == 1)).sum()
    table = [[n11, n10], [n01, n00]]
    result = mcnemar(table, exact=True)
    return {"statistic": result.statistic, "p_value": result.pvalue, "table": table}
