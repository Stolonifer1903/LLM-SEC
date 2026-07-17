import argparse
import json
import logging
import math
import re
import sys
from itertools import combinations
from pathlib import Path
from urllib.parse import urlsplit

import pandas as pd
from scipy.stats import friedmanchisquare, wilcoxon
from sklearn.metrics import (
    classification_report,
    cohen_kappa_score,
    f1_score,
    precision_score,
    recall_score,
)
from statsmodels.stats.contingency_tables import mcnemar


PROMPT_STRATEGIES = ("zero_shot", "few_shot", "cot")
logger = logging.getLogger(__name__)
RULE_COLUMNS = (
    "rule_id",
    "app",
    "zap_alert_name",
    "zap_cwe_id",
    "url_regex",
    "evidence_regex",
    "ground_truth_label",
    "challenge_ids",
    "rationale",
)
VALID_GROUND_TRUTH_LABELS = {"VULNERABLE", "NOT_VULNERABLE"}
PARSE_SUCCESS_THRESHOLD = 0.98
RUN_METADATA_FIELDS = (
    "run_id",
    "run_timestamp_utc",
    "model",
    "nim_base_url",
    "temperature",
    "max_completion_tokens",
    "source_alert_count",
    "alert_count",
    "scan_profile",
)
VALIDATION_COLUMNS = (
    "provider_key", "app", "current_detection_mode", "validation_status",
    "validated_detection_mode", "zap_alert_name", "zap_cwe_id", "url_regex",
    "evidence_regex", "scan_profile", "validation_run_id", "rationale",
)
VALIDATION_STATUSES = {
    "validated", "candidate", "supporting_only", "manual_required", "out_of_scope",
}


def normalize_text(value) -> str:
    return " ".join(str(value or "").strip().lower().split())


def normalize_cwe_id(value) -> str:
    text = str(value or "").strip().upper()
    if not text:
        return ""
    if text.endswith(".0") and text[:-2].lstrip("-").isdigit():
        text = text[:-2]
    if text.startswith("CWE-"):
        return text
    return f"CWE-{text}"


def normalize_url_path(value) -> str:
    path = urlsplit(str(value or "")).path or "/"
    path = re.sub(r"/{2,}", "/", path)
    if len(path) > 1:
        path = path.rstrip("/")
    return path


def _split_challenge_ids(value) -> list[str]:
    return [item.strip() for item in str(value or "").split("|") if item.strip()]


def _as_bool(value) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    if isinstance(value, (int, float)):
        return bool(value)
    return str(value).strip().lower() in {"true", "1", "yes"}


def extract_run_metadata(records: list[dict], fallbacks: dict = None) -> dict:
    fallbacks = fallbacks or {}
    metadata = {}
    for field in RUN_METADATA_FIELDS:
        values = {
            str(record[field])
            for record in records
            if record.get(field) is not None and str(record.get(field)).strip()
        }
        if len(values) > 1:
            raise ValueError(f"Pipeline records contain inconsistent {field} values")
        if values:
            metadata[field] = next(iter(values))
        elif fallbacks.get(field) is not None:
            metadata[field] = fallbacks[field]
        else:
            metadata[field] = "UNRECORDED"
    return metadata


def load_ground_truth(path="ground_truth.csv") -> pd.DataFrame:
    gt = pd.read_csv(path, dtype=str).fillna("")
    required = {"app", "ground_truth_label"}
    missing = required.difference(gt.columns)
    if missing:
        raise ValueError(f"Ground truth is missing columns: {sorted(missing)}")

    if "challenge_id" not in gt.columns:
        if "provider_key" not in gt.columns:
            raise ValueError(
                "Ground truth must contain challenge_id or provider_key"
            )
        gt["challenge_id"] = gt["provider_key"]

    gt["app"] = gt["app"].map(normalize_text)
    gt["challenge_id"] = gt["challenge_id"].str.strip()
    if (gt["challenge_id"] == "").any():
        raise ValueError("Every ground-truth row must have a challenge identifier")
    if gt["challenge_id"].duplicated().any():
        duplicates = sorted(
            gt.loc[gt["challenge_id"].duplicated(), "challenge_id"].unique()
        )
        raise ValueError(f"Duplicate ground-truth challenge identifiers: {duplicates}")

    if "zap_alert_name" in gt.columns:
        gt["zap_alert_name"] = gt["zap_alert_name"].map(normalize_text)
    elif "expected_zap_alert_names" in gt.columns:
        gt["zap_alert_name"] = gt["expected_zap_alert_names"].map(normalize_text)
    else:
        gt["zap_alert_name"] = ""

    if "cwe_id" in gt.columns:
        gt["cwe_id"] = gt["cwe_id"].map(normalize_cwe_id)
    else:
        gt["cwe_id"] = ""
    gt["ground_truth_label"] = gt["ground_truth_label"].str.strip().str.upper()
    return gt[gt["ground_truth_label"] == "VULNERABLE"].copy()


def load_detection_validation(path, gt: pd.DataFrame) -> pd.DataFrame:
    """Load the review overlay without altering the provider-derived catalogue."""
    validation = pd.read_csv(path, dtype=str).fillna("")
    missing = set(VALIDATION_COLUMNS).difference(validation.columns)
    if missing:
        raise ValueError(f"Detection validation overlay is missing columns: {sorted(missing)}")
    validation["provider_key"] = validation["provider_key"].str.strip()
    if (validation["provider_key"] == "").any() or validation["provider_key"].duplicated().any():
        raise ValueError("Validation overlay provider_key values must be present and unique")
    known = set(gt["challenge_id"])
    unknown = sorted(set(validation["provider_key"]).difference(known))
    if unknown:
        raise ValueError(f"Validation overlay references unknown provider keys: {unknown}")
    validation["app"] = validation["app"].map(normalize_text)
    validation["validation_status"] = validation["validation_status"].str.strip().str.lower()
    invalid = sorted(set(validation["validation_status"]).difference(VALIDATION_STATUSES))
    if invalid:
        raise ValueError(f"Invalid validation statuses: {invalid}")
    validated = validation[validation["validation_status"] == "validated"]
    required = ("validated_detection_mode", "zap_alert_name", "zap_cwe_id", "url_regex", "evidence_regex")
    for field in required:
        if (validated[field].str.strip() == "").any():
            raise ValueError(f"Validated overlay rows must define {field}")

    # Every catalogue challenge must be visible in the review summary. Rows
    # omitted from the hand-maintained overlay receive a conservative default
    # derived from the catalogue's declared detection mode; they cannot match
    # a positive rule until a reviewer explicitly marks them validated.
    explicit_keys = set(validation["provider_key"])
    defaults = []
    for _, row in gt.iterrows():
        provider_key = row["challenge_id"]
        if provider_key in explicit_keys:
            continue
        current_mode = str(row.get("zap_detection_mode", "")).strip().lower()
        if current_mode == "manual":
            status = "manual_required"
        elif current_mode in {"zap_active", "zap_passive"}:
            status = "candidate"
        else:
            status = "out_of_scope"
        defaults.append({
            "provider_key": provider_key,
            "app": row.get("app", ""),
            "current_detection_mode": current_mode,
            "validation_status": status,
            "validated_detection_mode": "",
            "zap_alert_name": row.get("zap_alert_name", ""),
            "zap_cwe_id": row.get("cwe_id", ""),
            "url_regex": "",
            "evidence_regex": "",
            "scan_profile": "",
            "validation_run_id": "",
            "rationale": "No explicit validation record exists yet.",
        })
    if defaults:
        validation = pd.concat([validation, pd.DataFrame(defaults)], ignore_index=True)
    return validation


def load_match_rules(path="ground_truth_match_rules.csv", gt: pd.DataFrame = None, validation: pd.DataFrame = None) -> list[dict]:
    rules_df = pd.read_csv(path, dtype=str).fillna("")
    missing = set(RULE_COLUMNS).difference(rules_df.columns)
    if missing:
        raise ValueError(f"Ground-truth rules are missing columns: {sorted(missing)}")
    rules_df["rule_id"] = rules_df["rule_id"].str.strip()
    if (rules_df["rule_id"] == "").any():
        raise ValueError("Every ground-truth rule must have a non-empty rule_id")
    if rules_df["rule_id"].duplicated().any():
        duplicates = sorted(rules_df.loc[rules_df["rule_id"].duplicated(), "rule_id"].unique())
        raise ValueError(f"Duplicate ground-truth rule IDs: {duplicates}")

    known_challenge_ids = set(gt["challenge_id"]) if gt is not None else set()
    rules = []
    for _, row in rules_df.iterrows():
        for field in ("app", "zap_alert_name", "zap_cwe_id"):
            if not row[field].strip():
                raise ValueError(f"Rule {row['rule_id']} must define {field}")
        label = row["ground_truth_label"].strip().upper()
        if label not in VALID_GROUND_TRUTH_LABELS:
            raise ValueError(
                f"Rule {row['rule_id']} has invalid ground_truth_label {label!r}"
            )

        challenge_ids = _split_challenge_ids(row["challenge_ids"])
        if label == "VULNERABLE" and not challenge_ids:
            raise ValueError(f"Vulnerable rule {row['rule_id']} must reference a challenge ID")
        unknown_ids = sorted(set(challenge_ids).difference(known_challenge_ids))
        if gt is not None and unknown_ids:
            raise ValueError(
                f"Rule {row['rule_id']} references unknown challenge IDs: {unknown_ids}"
            )
        if label == "VULNERABLE" and validation is not None:
            validation_rows = validation[
                (validation["provider_key"].isin(challenge_ids))
                & (validation["validation_status"] == "validated")
                & (validation["app"] == normalize_text(row["app"]))
                & (validation["zap_alert_name"].map(normalize_text) == normalize_text(row["zap_alert_name"]))
                & (validation["zap_cwe_id"].map(normalize_cwe_id) == normalize_cwe_id(row["zap_cwe_id"]))
                & (validation["url_regex"].str.strip() == row["url_regex"].strip())
                & (validation["evidence_regex"].str.strip() == row["evidence_regex"].strip())
            ]
            if len(validation_rows) != 1:
                raise ValueError(
                    f"Vulnerable rule {row['rule_id']} must exactly match one validated overlay row"
                )

        try:
            url_pattern = re.compile(row["url_regex"], re.IGNORECASE) if row["url_regex"] else None
            evidence_pattern = (
                re.compile(row["evidence_regex"], re.IGNORECASE | re.DOTALL)
                if row["evidence_regex"] else None
            )
        except re.error as exc:
            raise ValueError(f"Rule {row['rule_id']} contains an invalid regex: {exc}") from exc

        rules.append({
            "rule_id": row["rule_id"].strip(),
            "app": normalize_text(row["app"]),
            "zap_alert_name": normalize_text(row["zap_alert_name"]),
            "zap_cwe_id": normalize_cwe_id(row["zap_cwe_id"]),
            "url_pattern": url_pattern,
            "evidence_pattern": evidence_pattern,
            "ground_truth_label": label,
            "challenge_ids": challenge_ids,
            "rationale": row["rationale"].strip(),
        })
    return rules


def _rule_matches_alert(rule: dict, alert: dict) -> bool:
    if rule["app"] != normalize_text(alert.get("app", "")):
        return False
    if rule["zap_alert_name"] != normalize_text(alert.get("alert_name", "")):
        return False
    if rule["zap_cwe_id"] != normalize_cwe_id(alert.get("zap_cwe_id", "")):
        return False

    url_path = normalize_url_path(alert.get("url", ""))
    evidence = str(alert.get("evidence", ""))
    if rule["url_pattern"] and not rule["url_pattern"].search(url_path):
        return False
    if rule["evidence_pattern"] and not rule["evidence_pattern"].search(evidence):
        return False
    return True


def match_alert_to_ground_truth(alert: dict, rules: list[dict]) -> dict:
    matches = [rule for rule in rules if _rule_matches_alert(rule, alert)]
    if len(matches) > 1:
        rule_ids = [rule["rule_id"] for rule in matches]
        raise ValueError(
            f"Alert {alert.get('alert_id')} matches overlapping rules: {rule_ids}"
        )

    if not matches:
        return {
            "ground_truth_label": "UNMAPPED",
            "ground_truth": None,
            "matched_rule_id": "",
            "challenge_ids": [],
            "rationale": "No defensible ground-truth rule matched this alert.",
        }

    rule = matches[0]
    return {
        "ground_truth_label": rule["ground_truth_label"],
        "ground_truth": rule["ground_truth_label"] == "VULNERABLE",
        "matched_rule_id": rule["rule_id"],
        "challenge_ids": rule["challenge_ids"],
        "rationale": rule["rationale"],
    }


def _alert_sort_key(alert_id):
    text = str(alert_id)
    return (0, int(text)) if text.isdigit() else (1, text)


def validate_paired_design(records: list[dict]) -> dict[str, list[dict]]:
    if not records:
        raise ValueError("pipeline_results.json contains no records")

    records_by_strategy = {strategy: {} for strategy in PROMPT_STRATEGIES}
    for record in records:
        strategy = record.get("prompt_strategy")
        if strategy not in records_by_strategy:
            raise ValueError(f"Unexpected prompt strategy: {strategy!r}")
        raw_alert_id = record.get("alert_id")
        if raw_alert_id is None or not str(raw_alert_id).strip():
            raise ValueError("Every pipeline result must contain alert_id")
        alert_id = str(raw_alert_id)
        if alert_id in records_by_strategy[strategy]:
            raise ValueError(f"Duplicate alert_id {alert_id} for strategy {strategy}")
        records_by_strategy[strategy][alert_id] = record

    reference_ids = set(records_by_strategy[PROMPT_STRATEGIES[0]])
    for strategy in PROMPT_STRATEGIES:
        strategy_ids = set(records_by_strategy[strategy])
        if strategy_ids != reference_ids:
            missing = sorted(reference_ids.difference(strategy_ids), key=_alert_sort_key)
            extra = sorted(strategy_ids.difference(reference_ids), key=_alert_sort_key)
            raise ValueError(
                f"Paired design violation for {strategy}: missing={missing}, extra={extra}"
            )

    metadata_fields = ("app", "alert_name", "zap_cwe_id", "url", "evidence")
    for alert_id in reference_ids:
        reference = records_by_strategy[PROMPT_STRATEGIES[0]][alert_id]
        reference_metadata = tuple(str(reference.get(field, "")) for field in metadata_fields)
        for strategy in PROMPT_STRATEGIES[1:]:
            candidate = records_by_strategy[strategy][alert_id]
            candidate_metadata = tuple(str(candidate.get(field, "")) for field in metadata_fields)
            if candidate_metadata != reference_metadata:
                raise ValueError(
                    f"Alert metadata differs across strategies for alert_id {alert_id}"
                )

    ordered_ids = sorted(reference_ids, key=_alert_sort_key)
    return {
        strategy: [records_by_strategy[strategy][alert_id] for alert_id in ordered_ids]
        for strategy in PROMPT_STRATEGIES
    }


def calculate_parse_quality(
    records_by_strategy: dict[str, list[dict]],
    mapped_ids: set[str],
) -> dict:
    """Return the complete paired subset and parse-quality diagnostics."""
    valid_ids_by_strategy = {}
    strategy_summary = {}
    for strategy in PROMPT_STRATEGIES:
        mapped_records = [
            record for record in records_by_strategy[strategy]
            if str(record["alert_id"]) in mapped_ids
        ]
        valid_ids = {
            str(record["alert_id"])
            for record in mapped_records
            if _as_bool(record.get("parsed_successfully", False))
            and record.get("predicted_vulnerable") is not None
        }
        valid_ids_by_strategy[strategy] = valid_ids
        attempted_count = len(mapped_records)
        parse_success_count = len(valid_ids)
        strategy_summary[strategy] = {
            "attempted_count": attempted_count,
            "parse_success_count": parse_success_count,
            "parse_failure_count": attempted_count - parse_success_count,
            "repair_success_count": sum(
                1 for record in mapped_records
                if _as_bool(record.get("json_repaired", False))
                and str(record["alert_id"]) in valid_ids
            ),
            "parse_success_rate": (
                parse_success_count / attempted_count if attempted_count else 0.0
            ),
        }

    complete_paired_ids = set(mapped_ids)
    for valid_ids in valid_ids_by_strategy.values():
        complete_paired_ids.intersection_update(valid_ids)
    excluded_ids = sorted(mapped_ids.difference(complete_paired_ids), key=_alert_sort_key)
    below_threshold = [
        strategy for strategy in PROMPT_STRATEGIES
        if strategy_summary[strategy]["parse_success_rate"] < PARSE_SUCCESS_THRESHOLD
    ]
    return {
        "threshold": PARSE_SUCCESS_THRESHOLD,
        "strategies": strategy_summary,
        "complete_paired_alert_count": len(complete_paired_ids),
        "complete_paired_alert_ids": sorted(complete_paired_ids, key=_alert_sort_key),
        "excluded_paired_alert_count": len(excluded_ids),
        "excluded_paired_alert_ids": excluded_ids,
        "below_threshold_strategies": below_threshold,
    }


def update_parse_diagnostics(
    path: Path,
    metadata: dict,
    parse_quality: dict,
) -> None:
    if path.exists():
        with open(path, encoding="utf-8") as file:
            diagnostics = json.load(file)
    else:
        diagnostics = {"metadata": metadata}
    diagnostics["evaluation_parse_quality"] = parse_quality
    with open(path, "w", encoding="utf-8") as file:
        json.dump(diagnostics, file, indent=2)


def build_match_audit(base_records: list[dict], rules: list[dict]) -> pd.DataFrame:
    family_counts = {}
    for record in base_records:
        family_key = (
            normalize_text(record.get("app", "")),
            normalize_text(record.get("alert_name", "")),
            normalize_cwe_id(record.get("zap_cwe_id", "")),
        )
        family_counts[family_key] = family_counts.get(family_key, 0) + 1

    audit_rows = []
    for record in base_records:
        match = match_alert_to_ground_truth(record, rules)
        family_key = (
            normalize_text(record.get("app", "")),
            normalize_text(record.get("alert_name", "")),
            normalize_cwe_id(record.get("zap_cwe_id", "")),
        )
        audit_rows.append({
            "alert_id": record["alert_id"],
            "app": record.get("app", ""),
            "alert_name": record.get("alert_name", ""),
            "zap_cwe_id": normalize_cwe_id(record.get("zap_cwe_id", "")),
            "url": record.get("url", ""),
            "normalized_url_path": normalize_url_path(record.get("url", "")),
            "evidence": record.get("evidence", ""),
            "ground_truth_label": match["ground_truth_label"],
            "ground_truth": match["ground_truth"],
            "matched_rule_id": match["matched_rule_id"],
            "challenge_ids": "|".join(match["challenge_ids"]),
            "rationale": match["rationale"],
            "family_frequency": family_counts[family_key],
        })
    return pd.DataFrame(audit_rows)


def compute_metrics(results_df: pd.DataFrame) -> dict:
    y_true = results_df["ground_truth"].astype(bool).astype(int)
    y_pred = results_df["predicted_is_vuln"].astype(bool).astype(int)
    kappa = cohen_kappa_score(y_true, y_pred)
    per_class = classification_report(
        y_true,
        y_pred,
        labels=[0, 1],
        target_names=["SAFE", "VULNERABLE"],
        output_dict=True,
        zero_division=0,
    )
    class_report = {}
    for label in ("SAFE", "VULNERABLE"):
        class_report[label] = {
            "precision": float(per_class[label]["precision"]),
            "recall": float(per_class[label]["recall"]),
            "f1-score": float(per_class[label]["f1-score"]),
            "support": int(per_class[label]["support"]),
        }

    return {
        "precision": precision_score(y_true, y_pred, zero_division=0),
        "recall": recall_score(y_true, y_pred, zero_division=0),
        "f1_macro": f1_score(y_true, y_pred, average="macro", zero_division=0),
        "f1_weighted": f1_score(y_true, y_pred, average="weighted", zero_division=0),
        "kappa": 0.0 if math.isnan(kappa) else kappa,
        "prediction_distribution": {
            "predicted_vulnerable": int((y_pred == 1).sum()),
            "predicted_safe": int((y_pred == 0).sum()),
            "actual_vulnerable": int((y_true == 1).sum()),
            "actual_safe": int((y_true == 0).sum()),
        },
        "classification_report": class_report,
    }


def find_false_negatives(results_df: pd.DataFrame) -> pd.DataFrame:
    return results_df[
        results_df["ground_truth"].astype(bool)
        & ~results_df["predicted_is_vuln"].astype(bool)
    ].copy()


def mcnemar_test(correct_a, correct_b) -> dict:
    a_correct = pd.Series(correct_a, dtype=int).reset_index(drop=True)
    b_correct = pd.Series(correct_b, dtype=int).reset_index(drop=True)
    if len(a_correct) != len(b_correct):
        raise ValueError("McNemar inputs must have equal length")
    n00 = int(((a_correct == 0) & (b_correct == 0)).sum())
    n01 = int(((a_correct == 0) & (b_correct == 1)).sum())
    n10 = int(((a_correct == 1) & (b_correct == 0)).sum())
    n11 = int(((a_correct == 1) & (b_correct == 1)).sum())
    table = [[n11, n10], [n01, n00]]
    result = mcnemar(table, exact=True)
    return {"statistic": float(result.statistic), "p_value": float(result.pvalue), "table": table}


def friedman_test(correctness: dict[str, list[int]]) -> dict:
    vectors = [list(correctness[strategy]) for strategy in PROMPT_STRATEGIES]
    if all(vector == vectors[0] for vector in vectors[1:]):
        return {"statistic": 0.0, "p_value": 1.0}
    result = friedmanchisquare(*vectors)
    return {"statistic": float(result.statistic), "p_value": float(result.pvalue)}


def wilcoxon_posthoc(correctness: dict[str, list[int]]) -> list[dict]:
    pairs = list(combinations(PROMPT_STRATEGIES, 2))
    comparisons = []
    for strategy_a, strategy_b in pairs:
        values_a = list(correctness[strategy_a])
        values_b = list(correctness[strategy_b])
        differences = [a - b for a, b in zip(values_a, values_b)]
        if all(difference == 0 for difference in differences):
            statistic, raw_p_value = 0.0, 1.0
        else:
            result = wilcoxon(values_a, values_b, zero_method="wilcox", alternative="two-sided")
            statistic, raw_p_value = float(result.statistic), float(result.pvalue)
        comparisons.append({
            "strategy_a": strategy_a,
            "strategy_b": strategy_b,
            "statistic": statistic,
            "raw_p_value": raw_p_value,
            "bonferroni_p_value": min(raw_p_value * len(pairs), 1.0),
        })
    return comparisons


def evaluate_pipeline_results(
    pipeline_results_path="pipeline_results.json",
    ground_truth_path="ground_truth.csv",
    rules_path="ground_truth_match_rules.csv",
    validation_path=None,
    evaluation_output_path="evaluation_results.csv",
    audit_output_path="ground_truth_match_audit.csv",
    statistical_output_path="statistical_results.csv",
    summary_output_path=None,
    unmapped_output_path=None,
    parse_diagnostics_output_path=None,
    model=None,
    temperature=None,
    nim_base_url=None,
    run_id=None,
    run_timestamp_utc=None,
    max_completion_tokens=None,
    source_alert_count=None,
) -> dict:
    if not logging.getLogger().handlers:
        logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    pipeline_results_path = Path(pipeline_results_path)
    summary_output_path = Path(summary_output_path) if summary_output_path else (
        pipeline_results_path.parent / "evaluation_summary.json"
    )
    unmapped_output_path = Path(unmapped_output_path) if unmapped_output_path else (
        pipeline_results_path.parent / "unmapped_alerts.json"
    )
    parse_diagnostics_output_path = (
        Path(parse_diagnostics_output_path) if parse_diagnostics_output_path else (
            pipeline_results_path.parent / "parse_diagnostics.json"
        )
    )
    with open(pipeline_results_path, encoding="utf-8") as file:
        records = json.load(file)

    records_by_strategy = validate_paired_design(records)
    metadata = extract_run_metadata(records, {
        "run_id": run_id,
        "run_timestamp_utc": run_timestamp_utc,
        "model": model,
        "nim_base_url": nim_base_url,
        "temperature": temperature,
        "max_completion_tokens": max_completion_tokens,
        "source_alert_count": source_alert_count,
        "alert_count": len(records_by_strategy[PROMPT_STRATEGIES[0]]),
    })
    gt = load_ground_truth(ground_truth_path)
    validation = load_detection_validation(validation_path, gt) if validation_path else None
    rules = load_match_rules(rules_path, gt, validation)
    audit_df = build_match_audit(records_by_strategy[PROMPT_STRATEGIES[0]], rules)
    audit_df.insert(0, "model", metadata["model"])
    audit_df.insert(0, "run_id", metadata["run_id"])
    audit_df.to_csv(audit_output_path, index=False)

    match_by_alert_id = {
        str(row["alert_id"]): row
        for row in audit_df.to_dict(orient="records")
    }
    mapped_ids = {
        alert_id
        for alert_id, match in match_by_alert_id.items()
        if match["ground_truth_label"] != "UNMAPPED"
    }
    mapped_count = len(mapped_ids)
    unmapped_count = len(match_by_alert_id) - mapped_count
    positive_count = int((audit_df["ground_truth_label"] == "VULNERABLE").sum())
    negative_count = int((audit_df["ground_truth_label"] == "NOT_VULNERABLE").sum())
    total_alert_count = len(match_by_alert_id)
    matched_rate = mapped_count / total_alert_count if total_alert_count else 0.0
    logger.info(
        "Matched alerts: %s / %s (%.1f%%)",
        mapped_count,
        total_alert_count,
        matched_rate * 100,
    )
    logger.info("Unmapped alerts (excluded): %s", unmapped_count)

    unmapped_records = []
    for strategy in PROMPT_STRATEGIES:
        for record in records_by_strategy[strategy]:
            if str(record["alert_id"]) in mapped_ids:
                continue
            unmapped_records.append({
                "run_id": record.get("run_id"),
                "alert_id": record["alert_id"],
                "alert_name": record.get("alert_name", ""),
                "cweid": record.get("cweid", record.get("zap_cwe_id")),
                "zap_cwe_id": record.get("zap_cwe_id", ""),
                "pluginid": record.get("pluginid"),
                "wascid": record.get("wascid"),
                "app": record.get("app", ""),
                "strategy": strategy,
                "risk": record.get("risk", ""),
                "confidence": record.get("zap_confidence", record.get("confidence", "")),
                "url": record.get("url", ""),
                "description": record.get("description", ""),
                "evidence": record.get("evidence", ""),
                "solution": record.get("solution", ""),
                "dedup_key": record.get("dedup_key"),
                "dedup_cluster_size": record.get("dedup_cluster_size", 1),
                "inference_skipped": _as_bool(record.get("inference_skipped", False)),
                "skip_reason": record.get("skip_reason", ""),
            })
    with open(unmapped_output_path, "w", encoding="utf-8") as file:
        json.dump(unmapped_records, file, indent=2)

    linked_challenge_ids = set()
    for challenge_ids in audit_df.loc[
        audit_df["ground_truth_label"] == "VULNERABLE", "challenge_ids"
    ]:
        linked_challenge_ids.update(_split_challenge_ids(challenge_ids))
    scan_coverage_gaps = gt[~gt["challenge_id"].isin(linked_challenge_ids)].copy()
    parse_quality = calculate_parse_quality(records_by_strategy, mapped_ids)
    update_parse_diagnostics(
        parse_diagnostics_output_path,
        metadata,
        parse_quality,
    )

    positive_rate = positive_count / mapped_count if mapped_count else 0.0
    class_imbalance_warning = positive_rate < 0.10
    coverage_summary = {
        "total_alerts": total_alert_count,
        "matched_alerts": mapped_count,
        "unmapped_alerts": unmapped_count,
        "matched_rate": matched_rate,
        "actual_vulnerable": positive_count,
        "actual_safe": negative_count,
        "positive_rate": positive_rate,
        "class_imbalance_warning": class_imbalance_warning,
        "scan_coverage_gap_count": len(scan_coverage_gaps),
    }
    observed_families = {
        f"{normalize_text(record.get('app'))}|{normalize_text(record.get('alert_name'))}"
        for record in records_by_strategy[PROMPT_STRATEGIES[0]]
    }
    if "zap_detection_mode" in gt.columns:
        expected_catalogue = gt[
            gt["zap_detection_mode"].str.lower().isin(["zap_active", "zap_passive"])
        ]
    else:
        expected_catalogue = gt.iloc[0:0]
    expected_families = {
        f"{normalize_text(row['app'])}|{normalize_text(row.get('zap_alert_name', ''))}"
        for _, row in expected_catalogue.iterrows()
        if normalize_text(row.get("zap_alert_name", "")) not in {"", "n/a"}
    }
    validation_summary = (
        validation["validation_status"].value_counts().to_dict() if validation is not None else {}
    )
    detection_coverage = {
        "expected_active_passive_families": sorted(expected_families),
        "observed_families": sorted(observed_families),
        "observed_expected_families": sorted(expected_families.intersection(observed_families)),
        "missing_expected_families": sorted(expected_families.difference(observed_families)),
        "validation_status_counts": validation_summary,
    }
    if positive_count == 0:
        blocking_reasons = ["no_mapped_vulnerable_alerts"]
        if parse_quality["below_threshold_strategies"]:
            blocking_reasons.append("parse_quality_below_98_percent")
        blocked_summary = {
            "evaluation_status": "blocked_no_mapped_vulnerable_alerts",
            "metadata": metadata,
            "coverage": coverage_summary,
            "detection_coverage": detection_coverage,
            "parse_quality": parse_quality,
            "blocking_reasons": blocking_reasons,
            "reason": (
                "No mapped alert has a VULNERABLE ground-truth label. Add a defensible "
                "Juice Shop or DVWA positive match rule before calculating classification "
                "metrics or paired statistical tests."
            ),
        }
        with open(summary_output_path, "w", encoding="utf-8") as file:
            json.dump(blocked_summary, file, indent=2)
        print(
            f"\nGround-truth coverage: {mapped_count}/{total_alert_count} mapped "
            f"({positive_count} vulnerable, {negative_count} not vulnerable); "
            f"{unmapped_count} unmapped.",
            flush=True,
        )
        print(
            "\nEVALUATION BLOCKED: no mapped VULNERABLE alerts are available. "
            "Audit, unmapped-alert, and coverage-summary artifacts were written; "
            "classification metrics and statistical tests were not calculated.",
            flush=True,
        )
        raise ValueError(
            "Evaluation blocked: zero mapped VULNERABLE alerts. Add a defensible "
            "Juice Shop or DVWA positive rule and rerun evaluation."
        )

    if parse_quality["below_threshold_strategies"]:
        blocked_summary = {
            "evaluation_status": "blocked_parse_quality",
            "metadata": metadata,
            "coverage": coverage_summary,
            "detection_coverage": detection_coverage,
            "parse_quality": parse_quality,
            "blocking_reasons": ["parse_quality_below_98_percent"],
            "reason": (
                "One or more prompt strategies fell below the 98% post-repair "
                "parse-success threshold. Metrics and paired statistical tests were "
                "not calculated."
            ),
        }
        with open(summary_output_path, "w", encoding="utf-8") as file:
            json.dump(blocked_summary, file, indent=2)
        print(
            "\nEVALUATION BLOCKED: parse success below 98% after one format repair "
            f"for {', '.join(parse_quality['below_threshold_strategies'])}. "
            "Audit, unmapped-alert, diagnostics, and coverage-summary artifacts were written; "
            "classification metrics and statistical tests were not calculated.",
            flush=True,
        )
        raise ValueError(
            "Evaluation blocked: parse success below the 98% post-repair threshold."
        )

    summary_rows = []
    strategy_details = {}
    correctness = {}
    for strategy in PROMPT_STRATEGIES:
        evaluation_rows = []
        strategy_records = records_by_strategy[strategy]
        strategy_parse_quality = parse_quality["strategies"][strategy]
        for record in strategy_records:
            alert_id = str(record["alert_id"])
            if alert_id not in parse_quality["complete_paired_alert_ids"]:
                continue
            match = match_by_alert_id[alert_id]
            evaluation_rows.append({
                "alert_id": record["alert_id"],
                "ground_truth": _as_bool(match["ground_truth"]),
                "predicted_is_vuln": _as_bool(record["predicted_vulnerable"]),
            })

        results_df = pd.DataFrame(evaluation_rows)
        if results_df.empty:
            raise ValueError("No alerts were mapped by the ground-truth rules")
        metrics = compute_metrics(results_df)
        false_negatives = find_false_negatives(results_df)
        strategy_correctness = (
            results_df["ground_truth"] == results_df["predicted_is_vuln"]
        ).astype(int).tolist()
        correctness[strategy] = strategy_correctness
        strategy_details[strategy] = {
            "metrics": {
                "precision": float(metrics["precision"]),
                "recall": float(metrics["recall"]),
                "f1_macro": float(metrics["f1_macro"]),
                "f1_weighted": float(metrics["f1_weighted"]),
                "kappa": float(metrics["kappa"]),
            },
            "prediction_distribution": metrics["prediction_distribution"],
            "classification_report": metrics["classification_report"],
            "parse_success_rate": strategy_parse_quality["parse_success_rate"],
            "parse_success_count": strategy_parse_quality["parse_success_count"],
            "parse_failure_count": strategy_parse_quality["parse_failure_count"],
            "repaired_json_count": strategy_parse_quality["repair_success_count"],
            "inference_attempt_count": strategy_parse_quality["attempted_count"],
            "inference_skipped_count": (
                len(strategy_records) - strategy_parse_quality["attempted_count"]
            ),
            "false_negative_count": len(false_negatives),
        }

        summary_rows.append({
            "run_id": metadata["run_id"],
            "run_timestamp_utc": metadata["run_timestamp_utc"],
            "model": metadata["model"],
            "nim_base_url": metadata["nim_base_url"],
            "temperature": metadata["temperature"],
            "max_completion_tokens": metadata["max_completion_tokens"],
            "source_alert_count": metadata["source_alert_count"],
            "alert_count": metadata["alert_count"],
            "prompt_strategy": strategy,
            "precision": metrics["precision"],
            "recall": metrics["recall"],
            "f1_macro": metrics["f1_macro"],
            "f1_weighted": metrics["f1_weighted"],
            "kappa": metrics["kappa"],
            "parse_success_rate": strategy_parse_quality["parse_success_rate"],
            "parse_failure_count": strategy_parse_quality["parse_failure_count"],
            "repaired_json_count": strategy_parse_quality["repair_success_count"],
            "false_negative_count": len(false_negatives),
            "mapped_alert_count": mapped_count,
            "unmapped_alert_count": unmapped_count,
            "ground_truth_positive_count": positive_count,
            "ground_truth_negative_count": negative_count,
            "scan_coverage_gap_count": len(scan_coverage_gaps),
        })

    mcnemar_results = []
    for strategy_a, strategy_b in combinations(PROMPT_STRATEGIES, 2):
        result = mcnemar_test(correctness[strategy_a], correctness[strategy_b])
        result.update({"strategy_a": strategy_a, "strategy_b": strategy_b})
        mcnemar_results.append(result)
    friedman_result = friedman_test(correctness)
    wilcoxon_results = wilcoxon_posthoc(correctness)

    for row in summary_rows:
        row["friedman_statistic"] = friedman_result["statistic"]
        row["friedman_p_value"] = friedman_result["p_value"]
        row["statistical_results_file"] = str(statistical_output_path)
    evaluation_df = pd.DataFrame(summary_rows)
    evaluation_df.to_csv(evaluation_output_path, index=False)

    statistical_rows = []
    for result in mcnemar_results:
        statistical_rows.append({
            "run_id": metadata["run_id"],
            "model": metadata["model"],
            "test": "mcnemar",
            "strategy_a": result["strategy_a"],
            "strategy_b": result["strategy_b"],
            "statistic": result["statistic"],
            "raw_p_value": result["p_value"],
            "adjusted_p_value": result["p_value"],
            "correction": "none",
            "contingency_table": json.dumps(result["table"]),
        })
    statistical_rows.append({
        "run_id": metadata["run_id"],
        "model": metadata["model"],
        "test": "friedman",
        "strategy_a": "all",
        "strategy_b": "",
        "statistic": friedman_result["statistic"],
        "raw_p_value": friedman_result["p_value"],
        "adjusted_p_value": friedman_result["p_value"],
        "correction": "none",
        "contingency_table": "",
    })
    for result in wilcoxon_results:
        statistical_rows.append({
            "run_id": metadata["run_id"],
            "model": metadata["model"],
            "test": "wilcoxon",
            "strategy_a": result["strategy_a"],
            "strategy_b": result["strategy_b"],
            "statistic": result["statistic"],
            "raw_p_value": result["raw_p_value"],
            "adjusted_p_value": result["bonferroni_p_value"],
            "correction": "bonferroni_3_comparisons",
            "contingency_table": "",
        })
    statistical_df = pd.DataFrame(statistical_rows)
    statistical_df.to_csv(statistical_output_path, index=False)

    evaluation_summary = {
        "evaluation_status": "completed",
        "metadata": metadata,
        "coverage": coverage_summary,
        "detection_coverage": detection_coverage,
        "parse_quality": parse_quality,
        "strategies": strategy_details,
        "statistical_tests": {
            "mcnemar": mcnemar_results,
            "friedman": friedman_result,
            "wilcoxon": wilcoxon_results,
        },
    }
    with open(summary_output_path, "w", encoding="utf-8") as file:
        json.dump(evaluation_summary, file, indent=2)

    print(
        f"\nGround-truth coverage: {mapped_count}/{len(match_by_alert_id)} mapped "
        f"({positive_count} vulnerable, {negative_count} not vulnerable); "
        f"{unmapped_count} unmapped.",
        flush=True,
    )
    if class_imbalance_warning:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8")
        print(
            "\n⚠️  CLASS IMBALANCE WARNING: "
            f"Positive rate = {positive_rate:.1%}. "
            "Precision and macro F1 are unreliable.\n",
            flush=True,
        )
    print(
        f"Challenge catalogue coverage gaps: {len(scan_coverage_gaps)}/{len(gt)}",
        flush=True,
    )
    print(
        "Complete paired analysis set: "
        f"{parse_quality['complete_paired_alert_count']}/{mapped_count} mapped alerts; "
        f"{parse_quality['excluded_paired_alert_count']} excluded for parse failure.",
        flush=True,
    )
    print("Dominant alert families:", flush=True)
    family_summary = (
        audit_df.groupby(["app", "alert_name", "zap_cwe_id"], dropna=False)
        .size()
        .sort_values(ascending=False)
        .head(5)
    )
    for (app, alert_name, cwe_id), count in family_summary.items():
        print(f"  {app} | {alert_name} | {cwe_id}: {count}", flush=True)

    print("Top unmapped alert names:", flush=True)
    unmapped_name_summary = (
        audit_df.loc[audit_df["ground_truth_label"] == "UNMAPPED", "alert_name"]
        .value_counts()
        .head(10)
    )
    if unmapped_name_summary.empty:
        print("  None", flush=True)
    else:
        for alert_name, count in unmapped_name_summary.items():
            print(f"  {alert_name}: {count}", flush=True)

    for row in summary_rows:
        print(f"\n=== {row['prompt_strategy'].upper()} ===", flush=True)
        print(
            f"  Precision: {row['precision']:.3f} | Recall: {row['recall']:.3f} | "
            f"Macro F1: {row['f1_macro']:.3f} | Weighted F1: {row['f1_weighted']:.3f} | "
            f"Kappa: {row['kappa']:.3f}",
            flush=True,
        )
        print(
            f"  False negatives: {row['false_negative_count']} | "
            f"Parse success rate: {row['parse_success_rate']:.3f}",
            flush=True,
        )
        print("  Per-class breakdown:", flush=True)
        print("    Class        Precision  Recall  F1     Support", flush=True)
        for label in ("SAFE", "VULNERABLE"):
            class_row = strategy_details[row["prompt_strategy"]]["classification_report"][label]
            print(
                f"    {label:<12} {class_row['precision']:<10.3f} "
                f"{class_row['recall']:<7.3f} {class_row['f1-score']:<6.3f} "
                f"{class_row['support']}",
                flush=True,
            )
        if row["parse_success_rate"] < 0.80:
            print("  WARNING: parse failure rate > 20% (methodology concern)", flush=True)

    for result in mcnemar_results:
        print(
            f"\nMcNemar ({result['strategy_a']} vs {result['strategy_b']}): "
            f"p={result['p_value']:.4f}",
            flush=True,
        )
    print(
        f"\nFriedman: chi-square={friedman_result['statistic']:.4f}, "
        f"p={friedman_result['p_value']:.4f}",
        flush=True,
    )
    for result in wilcoxon_results:
        print(
            f"Wilcoxon ({result['strategy_a']} vs {result['strategy_b']}): "
            f"raw p={result['raw_p_value']:.4f}, "
            f"Bonferroni p={result['bonferroni_p_value']:.4f}",
            flush=True,
        )

    return {
        "evaluation": evaluation_df,
        "audit": audit_df,
        "scan_coverage_gaps": scan_coverage_gaps,
        "mcnemar": mcnemar_results,
        "friedman": friedman_result,
        "wilcoxon": wilcoxon_results,
        "statistics": statistical_df,
        "metadata": metadata,
        "summary": evaluation_summary,
        "unmapped_alerts": unmapped_records,
        "parse_quality": parse_quality,
    }


def main():
    parser = argparse.ArgumentParser(description="Evaluate LLM triage pipeline results")
    parser.add_argument("--pipeline-results", default="pipeline_results.json")
    parser.add_argument("--ground-truth", default="ground_truth.csv")
    parser.add_argument("--rules", default="ground_truth_match_rules.csv")
    parser.add_argument("--evaluation-output", default="evaluation_results.csv")
    parser.add_argument("--audit-output", default="ground_truth_match_audit.csv")
    parser.add_argument("--statistical-output", default="statistical_results.csv")
    parser.add_argument("--summary-output", default="evaluation_summary.json")
    parser.add_argument("--unmapped-output", default="unmapped_alerts.json")
    parser.add_argument("--parse-diagnostics-output", default="parse_diagnostics.json")
    parser.add_argument("--model")
    parser.add_argument("--temperature", type=float)
    parser.add_argument("--nim-base-url")
    parser.add_argument("--run-id")
    parser.add_argument("--run-timestamp-utc")
    parser.add_argument("--max-completion-tokens", type=int)
    parser.add_argument("--source-alert-count", type=int)
    args = parser.parse_args()
    evaluate_pipeline_results(
        pipeline_results_path=args.pipeline_results,
        ground_truth_path=args.ground_truth,
        rules_path=args.rules,
        evaluation_output_path=args.evaluation_output,
        audit_output_path=args.audit_output,
        statistical_output_path=args.statistical_output,
        summary_output_path=args.summary_output,
        unmapped_output_path=args.unmapped_output,
        parse_diagnostics_output_path=args.parse_diagnostics_output,
        model=args.model,
        temperature=args.temperature,
        nim_base_url=args.nim_base_url,
        run_id=args.run_id,
        run_timestamp_utc=args.run_timestamp_utc,
        max_completion_tokens=args.max_completion_tokens,
        source_alert_count=args.source_alert_count,
    )


if __name__ == "__main__":
    main()
