import time
import json
import os
import re
import requests
from collections import Counter
from datetime import datetime, timezone
from urllib.parse import urlencode

ZAP_BASE_URL = 'http://localhost:8090'
ZAP_API_BASE = f'{ZAP_BASE_URL}/JSON'
API_TIMEOUT = (3, 5)
SESSION_RESET_TIMEOUT = (3, float(os.getenv("ZAP_SESSION_RESET_TIMEOUT_SECONDS", "90")))
MAX_STATUS_TIMEOUTS = 120
SPIDER_MAX_DEPTH = int(os.getenv("ZAP_SPIDER_MAX_DEPTH", "10"))
SPIDER_MAX_CHILDREN = int(os.getenv("ZAP_SPIDER_MAX_CHILDREN", "500"))
AJAX_SPIDER_MAX_DURATION_MINS = int(os.getenv("ZAP_AJAX_MAX_DURATION_MINS", "20"))
ACTIVE_SCAN_THREADS_PER_HOST = int(os.getenv("ZAP_ACTIVE_THREADS_PER_HOST", "2"))
DVWA_HOST_URL = os.getenv("DVWA_HOST_URL", "http://localhost:8081")
DVWA_USERNAME = os.getenv("DVWA_USERNAME", "admin")
DVWA_PASSWORD = os.getenv("DVWA_PASSWORD", "password")

TARGET_PROFILES = {
    "juice_shop": {
        "context_name": "juice_shop_dast",
        "exclude_regexes": [
            r"http://juice-shop:3000/juice-shop/.*",
            # Keep these resources in passive-scan history, but do not use
            # them as active-scan attack targets. They create a large number
            # of non-application paths and can exhaust the Juice Shop process.
            r"http://juice-shop:3000/(?:assets|build|node_modules|fonts|i18n|ftp|socket\.io)(?:/.*)?",
        ],
        "use_ajax_spider": True,
        "required_paths": ["/rest/products/search"],
    },
    "dvwa": {
        "context_name": "dvwa_dast",
        "exclude_regexes": [],
        "use_ajax_spider": False,
        "required_paths": ["/vulnerabilities/sqli/", "/vulnerabilities/exec/"],
    },
}
SCAN_METADATA = []
SCAN_PROFILES = ("baseline", "targeted")
TARGETED_SCANNER_IDS = (6, 20019, 40012, 40014, 40017, 40018, 40019, 40020, 40021, 40022, 40026, 40027, 90020, 90037)
NOISE_SCANNER_ID = 10104
TARGETED_REQUESTS = {
    "juice_shop": [
        {"url": "/rest/products/search?q=apple", "method": "GET", "post_data": ""},
    ],
    "dvwa": [
        {"url": "/vulnerabilities/sqli/?id=1&Submit=Submit", "method": "GET", "post_data": ""},
        {"url": "/vulnerabilities/sqli_blind/?id=1&Submit=Submit", "method": "GET", "post_data": ""},
        {"url": "/vulnerabilities/exec/", "method": "POST", "post_data": "ip=127.0.0.1&Submit=Submit"},
        {"url": "/vulnerabilities/fi/?page=include.php", "method": "GET", "post_data": ""},
        {"url": "/vulnerabilities/xss_r/?name=ZAP", "method": "GET", "post_data": ""},
        {"url": "/vulnerabilities/xss_s/", "method": "POST", "post_data": "txtName=ZAP&mtxMessage=seed&btnSign=Sign+Guestbook"},
    ],
}

session = requests.Session()
session.trust_env = False

def zap_api(component: str, kind: str, endpoint: str, *, request_timeout=API_TIMEOUT, **params):
    """Call a ZAP API endpoint without reserving common request parameter names."""
    url = f'{ZAP_API_BASE}/{component}/{kind}/{endpoint}/'
    response = session.get(url, params=params, timeout=request_timeout)
    response.raise_for_status()
    return response.json()

def configure_active_scan(scan_profile: str = "baseline") -> list[dict]:
    if scan_profile not in SCAN_PROFILES:
        raise ValueError(f"Unknown scan profile: {scan_profile}")
    # This is an authorized lab scan. Zero removes ZAP's active-scan caps.
    zap_api("ascan", "action", "setOptionThreadPerHost", Integer=ACTIVE_SCAN_THREADS_PER_HOST)
    zap_api("ascan", "action", "setOptionMaxRuleDurationInMins", Integer=0)
    zap_api("ascan", "action", "setOptionMaxScanDurationInMins", Integer=0)
    zap_api("ascan", "action", "setOptionMaxAlertsPerRule", Integer=0)
    zap_api("ascan", "action", "setOptionHandleAntiCSRFTokens", Boolean="true")
    # DVWA issues this token on its login and test forms. Register it before
    # authenticated crawling so ZAP can refresh the value between requests.
    zap_api("acsrf", "action", "addOptionToken", String="user_token")
    # ZAP 2.17 exposes separate enable/disable actions rather than a
    # setScannerEnabled action.
    zap_api("ascan", "action", "enableScanners", ids=str(NOISE_SCANNER_ID))
    for scanner_id in TARGETED_SCANNER_IDS:
        zap_api(
            "ascan", "action", "setScannerAttackStrength",
            id=str(scanner_id), attackStrength="DEFAULT",
        )
    if scan_profile == "targeted":
        zap_api("ascan", "action", "disableScanners", ids=str(NOISE_SCANNER_ID))
        for scanner_id in TARGETED_SCANNER_IDS:
            zap_api(
                "ascan", "action", "setScannerAttackStrength",
                id=str(scanner_id), attackStrength="HIGH",
            )
    return zap_api("ascan", "view", "scanners").get("scanners", [])


def configure_spider() -> None:
    zap_api("spider", "action", "setOptionMaxDepth", Integer=SPIDER_MAX_DEPTH)
    zap_api("spider", "action", "setOptionMaxChildren", Integer=SPIDER_MAX_CHILDREN)
    zap_api("spider", "action", "setOptionThreadCount", Integer=2)


def configure_ajax_spider() -> None:
    zap_api("ajaxSpider", "action", "setOptionMaxCrawlDepth", Integer=SPIDER_MAX_DEPTH)
    zap_api("ajaxSpider", "action", "setOptionMaxDuration", Integer=AJAX_SPIDER_MAX_DURATION_MINS)
    zap_api("ajaxSpider", "action", "setOptionNumberOfBrowsers", Integer=1)

def wait_for_progress(get_status, scan_id: str, label: str, poll_seconds: int) -> None:
    start = time.time()
    timeout_count = 0
    while True:
        try:
            status = get_status(scan_id)
            timeout_count = 0
        except (requests.Timeout, requests.ConnectionError) as exc:
            timeout_count += 1
            if timeout_count > MAX_STATUS_TIMEOUTS:
                raise RuntimeError(f"{label} status did not respond after {MAX_STATUS_TIMEOUTS} retries") from exc
            elapsed_minutes = (time.time() - start) / 60
            print(f"  {label} status unavailable; retrying ({timeout_count}/{MAX_STATUS_TIMEOUTS}) after {elapsed_minutes:.1f} min", end="\r")
            time.sleep(poll_seconds)
            continue
        if not str(status).isdigit():
            raise RuntimeError(f"{label} scan failed or was not created. ZAP returned status: {status}")
        progress = int(status)
        if progress >= 100:
            return
        elapsed_minutes = (time.time() - start) / 60
        print(f"  {label} progress: {progress}% after {elapsed_minutes:.1f} min", end="\r")
        time.sleep(poll_seconds)


def scan_id_from_response(response: dict, action: str, scan_label: str) -> str:
    """Return ZAP's scan identifier for either normal or user-scoped actions."""
    for key in ("scan", action):
        scan_id = response.get(key)
        if scan_id is not None and str(scan_id):
            return str(scan_id)
    raise RuntimeError(
        f"[{scan_label}] ZAP did not return a scan ID for {action}: {response}"
    )

def wait_for_zap(timeout=60):
    start = time.time()
    last_error = None
    while time.time() - start < timeout:
        try:
            response = session.get(f'{ZAP_BASE_URL}/JSON/core/view/version/', timeout=3)
            response.raise_for_status()
            # Do not begin a scan until the JavaScript-aware crawler add-on is ready.
            zap_api("ajaxSpider", "view", "status")
            print("ZAP is running, version:", response.json().get('version'))
            return True
        except Exception as exc:
            last_error = exc
            time.sleep(3)
    raise TimeoutError(f"ZAP did not start within the specified timeout. Last error: {last_error}")


def _context_names() -> set[str]:
    contexts = zap_api("context", "view", "contextList").get("contextList", [])
    if isinstance(contexts, str):
        return {name.strip() for name in contexts.strip("[]").split(",") if name.strip()}
    return set(contexts)


def create_context(target_url: str, scan_label: str) -> dict:
    profile = TARGET_PROFILES[scan_label]
    context_name = profile["context_name"]
    if context_name in _context_names():
        zap_api("context", "action", "removeContext", contextName=context_name)
    context_id = zap_api("context", "action", "newContext", contextName=context_name)["contextId"]
    zap_api(
        "context",
        "action",
        "includeInContext",
        contextName=context_name,
        # Include the root document as well as all child paths. ZAP's context
        # regex is matched against the complete URL, including the no-slash root.
        regex=rf"{re.escape(target_url)}(?:/.*)?",
    )
    for pattern in profile["exclude_regexes"]:
        zap_api("context", "action", "excludeFromContext", contextName=context_name, regex=pattern)
    return {"id": context_id, "name": context_name}


def _extract_csrf_token(response: requests.Response) -> str:
    match = re.search(r"name=['\"]user_token['\"]\s+value=['\"]([^'\"]+)", response.text)
    if not match:
        raise RuntimeError("DVWA response did not include the expected user_token")
    return match.group(1)


def prepare_dvwa() -> None:
    """Reset DVWA's lab database so the documented low-security test state is available."""
    dvwa = requests.Session()
    dvwa.trust_env = False
    setup = dvwa.get(f"{DVWA_HOST_URL}/setup.php", timeout=30)
    setup.raise_for_status()
    reset = dvwa.post(
        f"{DVWA_HOST_URL}/setup.php",
        data={"create_db": "Create / Reset Database", "user_token": _extract_csrf_token(setup)},
        timeout=60,
    )
    reset.raise_for_status()
    if "Database has been created" not in reset.text and "Database has been reset" not in reset.text:
        raise RuntimeError("DVWA database preparation did not report a successful reset")


def configure_dvwa_user(context: dict, target_url: str) -> str:
    # DVWA rejects the login POST unless its per-page anti-CSRF token is sent.
    # ZAP refreshes {%user_token%} from the login form because the token name
    # is registered in configure_active_scan().
    login_request_data = (
        "username={%username%}&password={%password%}&Login=Login&"
        "user_token={%user_token%}"
    )
    auth_config = urlencode({
        "loginUrl": f"{target_url}/login.php",
        "loginRequestData": login_request_data,
    })
    zap_api(
        "authentication",
        "action",
        "setAuthenticationMethod",
        contextId=context["id"],
        authMethodName="formBasedAuthentication",
        authMethodConfigParams=auth_config,
    )
    zap_api(
        "sessionManagement",
        "action",
        "setSessionManagementMethod",
        contextId=context["id"],
        methodName="cookieBasedSessionManagement",
        methodConfigParams="",
    )
    zap_api(
        "authentication",
        "action",
        "setLoggedInIndicator",
        contextId=context["id"],
        loggedInIndicatorRegex="Logout",
    )
    zap_api(
        "authentication",
        "action",
        "setLoggedOutIndicator",
        contextId=context["id"],
        loggedOutIndicatorRegex="Login ::",
    )
    user_id = zap_api(
        "users", "action", "newUser", contextId=context["id"], name="dvwa_admin"
    )["userId"]
    zap_api(
        "users",
        "action",
        "setAuthenticationCredentials",
        contextId=context["id"],
        userId=user_id,
        authCredentialsConfigParams=urlencode({
            "username": DVWA_USERNAME,
            "password": DVWA_PASSWORD,
        }),
    )
    zap_api("users", "action", "setUserEnabled", contextId=context["id"], userId=user_id, enabled="true")
    return user_id


def seed_juice_shop_requests(target_url: str) -> None:
    """Add stable, read-only API routes to ZAP's history before active scanning."""
    seed_urls = [
        f"{target_url}/rest/products/search?q=apple",
        f"{target_url}/rest/products/1/reviews",
    ]
    for url in seed_urls:
        try:
            zap_api("core", "action", "accessUrl", url=url, followRedirects="true")
        except requests.RequestException as exc:
            # Discovery validation below remains authoritative. A failed
            # convenience seed must not discard an otherwise valid crawl.
            print(f"[juice_shop] API seed request failed for {url}: {exc}")


def run_targeted_active_scans(target_url: str, scan_label: str, context: dict, user_id: str | None) -> list[dict]:
    """Run reproducible, endpoint-specific scans after normal discovery."""
    scan_ids = []
    for request_spec in TARGETED_REQUESTS[scan_label]:
        url = f"{target_url}{request_spec['url']}"
        params = {
            "url": url,
            "recurse": "false",
            "inScopeOnly": "true",
            "scanPolicyName": "Default Policy",
            "method": request_spec["method"],
            "postData": request_spec["post_data"],
            "contextId": context["id"],
        }
        action = "scanAsUser" if user_id is not None else "scan"
        if user_id is not None:
            params["userId"] = user_id
        response = zap_api("ascan", "action", action, **params)
        scan_id = scan_id_from_response(response, action, scan_label)
        wait_for_progress(
            lambda current_id: zap_api("ascan", "view", "status", scanId=current_id)["status"],
            scan_id,
            f"Targeted active scan {request_spec['url']}",
            5,
        )
        scan_ids.append({"url": url, "method": request_spec["method"], "scan_id": scan_id})
    return scan_ids


def start_fresh_zap_session() -> None:
    """Prevent prior aborted scans from contaminating discovery or exhausting ZAP."""
    # ZAP serializes session disposal and database creation. A large completed
    # scan can therefore take longer than ordinary API calls even though the
    # daemon is healthy; do not apply the five-second status-call timeout here.
    zap_api(
        "core", "action", "newSession", name="", overwrite="true",
        request_timeout=SESSION_RESET_TIMEOUT,
    )


def wait_for_ajax_spider(timeout=AJAX_SPIDER_MAX_DURATION_MINS * 60 + 120) -> None:
    start = time.time()
    while True:
        status = zap_api("ajaxSpider", "view", "status").get("status", "")
        if status.lower() == "stopped":
            return
        if time.time() - start > timeout:
            zap_api("ajaxSpider", "action", "stop")
            raise TimeoutError("AJAX spider did not complete within its configured duration")
        elapsed_minutes = (time.time() - start) / 60
        print(f"  AJAX spider progress: {status} after {elapsed_minutes:.1f} min", end="\r")
        time.sleep(5)


def wait_for_passive_scan(timeout=300) -> None:
    start = time.time()
    while True:
        remaining = int(zap_api("pscan", "view", "recordsToScan").get("recordsToScan", 0))
        if remaining == 0:
            return
        if time.time() - start > timeout:
            raise TimeoutError(f"Passive scan queue did not drain; {remaining} records remain")
        time.sleep(2)


def get_target_urls(target_url: str) -> list[str]:
    return sorted(url for url in zap_api("core", "view", "urls").get("urls", []) if url.startswith(target_url))


def verify_discovery(target_url: str, scan_label: str) -> list[str]:
    urls = get_target_urls(target_url)
    missing = [
        path for path in TARGET_PROFILES[scan_label]["required_paths"]
        if not any(path in url for url in urls)
    ]
    if missing:
        raise RuntimeError(
            f"[{scan_label}] required DAST paths were not discovered: {missing}. "
            "Do not interpret this run as a comprehensive assessment."
        )
    return urls


def run_scan(target_url: str, scan_label: str, scan_profile: str = "baseline") -> list[dict]:
    if scan_label not in TARGET_PROFILES:
        raise ValueError(f"No DAST target profile configured for {scan_label}")
    if scan_profile not in SCAN_PROFILES:
        raise ValueError(f"Unknown scan profile: {scan_profile}")
    scan_started_at = datetime.now(timezone.utc)
    configure_spider()
    scanner_snapshot = configure_active_scan(scan_profile)
    context = create_context(target_url, scan_label)
    user_id = None
    if scan_label == "dvwa":
        prepare_dvwa()
        user_id = configure_dvwa_user(context, target_url)

    print(f"[{scan_label}] Starting authenticated-aware spider on {target_url}")
    spider_action = "scanAsUser" if user_id is not None else "scan"
    spider_params = {
        "url": target_url,
        "maxChildren": SPIDER_MAX_CHILDREN,
        "recurse": "true",
        "subtreeOnly": "true",
    }
    if user_id is not None:
        spider_params.update({"contextId": context["id"], "userId": user_id})
    else:
        spider_params["contextName"] = context["name"]
    spider_response = zap_api("spider", "action", spider_action, **spider_params)
    spider_id = scan_id_from_response(spider_response, spider_action, scan_label)
    wait_for_progress(
        lambda scan_id: zap_api("spider", "view", "status", scanId=scan_id)["status"],
        spider_id,
        "Spider",
        2
    )
    print(f"[{scan_label}] Spider complete.")

    if TARGET_PROFILES[scan_label]["use_ajax_spider"]:
        configure_ajax_spider()
        print(f"[{scan_label}] Starting AJAX spider on {target_url}")
        zap_api(
            "ajaxSpider",
            "action",
            "scan",
            url=target_url,
            contextName=context["name"],
            subtreeOnly="true",
        )
        wait_for_ajax_spider()
        print(f"\n[{scan_label}] AJAX spider complete.")

    if scan_label == "juice_shop":
        seed_juice_shop_requests(target_url)
    wait_for_passive_scan()
    discovered_urls = verify_discovery(target_url, scan_label)

    print(f"[{scan_label}] Starting active scan on {target_url}")
    active_action = "scanAsUser" if user_id is not None else "scan"
    active_params = {
        "url": target_url,
        "recurse": "true",
        "inScopeOnly": "true",
        "scanPolicyName": "Default Policy",
        "method": "",
        "postData": "",
        "contextId": context["id"],
    }
    if user_id is not None:
        active_params["userId"] = user_id
    active_response = zap_api("ascan", "action", active_action, **active_params)
    ascan_id = scan_id_from_response(active_response, active_action, scan_label)
    wait_for_progress(
        lambda scan_id: zap_api("ascan", "view", "status", scanId=scan_id)["status"],
        ascan_id,
        "Active scan",
        5
    )
    print(f"\n[{scan_label}] Active scan complete.")

    targeted_scans = []
    if scan_profile == "targeted":
        print(f"[{scan_label}] Starting focused targeted active scans.")
        targeted_scans = run_targeted_active_scans(target_url, scan_label, context, user_id)

    raw_alerts = zap_api("core", "view", "alerts", baseurl=target_url)["alerts"]
    alerts = []
    for a in raw_alerts:
        alerts.append({
            "app": scan_label,
            "alert_name": a.get("alert", ""),
            "risk": a.get("risk", ""),
            "confidence": a.get("confidence", ""),
            "url": a.get("url", ""),
            "description": a.get("description", ""),
            "solution": a.get("solution", ""),
            "cweid": a.get("cweid", ""),
            "wascid": a.get("wascid", ""),
            "evidence": a.get("evidence", ""),
            "pluginid": a.get("pluginId", a.get("pluginid")),
            "param": a.get("param", ""),
            "attack": a.get("attack", ""),
            "other": a.get("other", ""),
            "tags": a.get("tags", {}),
            "message_id": a.get("messageId", a.get("messageid")),
            "scan_profile": scan_profile,
        })
    SCAN_METADATA.append({
        "app": scan_label,
        "target_url": target_url,
        "context": context,
        "authenticated_user_id": user_id,
        "scan_profile": scan_profile,
        "effective_scanners": scanner_snapshot,
        "targeted_scans": targeted_scans,
        "started_at_utc": scan_started_at.isoformat(),
        "completed_at_utc": datetime.now(timezone.utc).isoformat(),
        "discovered_url_count": len(discovered_urls),
        "discovered_urls": discovered_urls,
        "alert_count": len(alerts),
    })
    print(f"[{scan_label}] Found {len(alerts)} alerts.")
    return alerts

def save_alerts(alerts: list[dict], path: str = "zap_alerts.json"):
    with open(path, "w") as f:
        json.dump(alerts, f, indent=2)
    print(f"Alerts saved to {path}")


def reset_scan_metadata() -> None:
    SCAN_METADATA.clear()


def save_scan_report(alerts: list[dict], path: str, scan_profile: str = "baseline") -> None:
    families = Counter(
        (alert["app"], alert["alert_name"], alert.get("cweid", ""), alert["risk"])
        for alert in alerts
    )
    noise_alerts = [alert for alert in alerts if str(alert.get("pluginid", "")) == str(NOISE_SCANNER_ID)]
    non_noise_alerts = [alert for alert in alerts if alert not in noise_alerts]
    confirmed_candidates = [
        alert for alert in non_noise_alerts
        if alert.get("risk") == "High" and str(alert.get("evidence", "")).strip()
    ]
    other_high_medium = [
        alert for alert in non_noise_alerts
        if alert.get("risk") in {"High", "Medium"} and alert not in confirmed_candidates
    ]
    repeated_headers = [
        alert for alert in non_noise_alerts
        if alert.get("alert_name") in {
            "Content Security Policy (CSP) Header Not Set",
            "Missing Anti-clickjacking Header",
            "Cross-Domain Misconfiguration",
        }
    ]
    report = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "scanner_configuration": {
            "scan_profile": scan_profile,
            "spider_max_depth": SPIDER_MAX_DEPTH,
            "spider_max_children": SPIDER_MAX_CHILDREN,
            "ajax_spider_max_duration_mins": AJAX_SPIDER_MAX_DURATION_MINS,
            "active_scan_threads_per_host": ACTIVE_SCAN_THREADS_PER_HOST,
            "active_scan_max_rule_duration_mins": 0,
            "active_scan_max_duration_mins": 0,
            "active_scan_max_alerts_per_rule": 0,
        },
        "targets": SCAN_METADATA,
        "quality_summary": {
            "raw_alert_count": len(alerts),
            "noise_alert_count": len(noise_alerts),
            "noise_alert_family_counts": [
                {
                    "app": app,
                    "alert_name": name,
                    "pluginid": pluginid,
                    "count": count,
                }
                for (app, name, pluginid), count in Counter(
                    (
                        alert.get("app", ""),
                        alert.get("alert_name", ""),
                        alert.get("pluginid", ""),
                    )
                    for alert in noise_alerts
                ).most_common()
            ],
            "non_noise_alert_count": len(non_noise_alerts),
            "confirmed_evidence_candidates": confirmed_candidates,
            "other_high_medium_findings": other_high_medium,
            "repeated_header_findings": repeated_headers,
        },
        "alert_family_counts": [
            {
                "app": app,
                "alert_name": name,
                "cweid": cweid,
                "risk": risk,
                "count": count,
            }
            for (app, name, cweid, risk), count in families.most_common()
        ],
        "alerts": alerts,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print(f"ZAP scan report saved to {path}")

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Run the authorized local ZAP DAST scan")
    parser.add_argument("--scan-profile", choices=SCAN_PROFILES, default="baseline")
    args = parser.parse_args()
    wait_for_zap()
    start_fresh_zap_session()
    reset_scan_metadata()
    all_alerts = []
    all_alerts += run_scan("http://juice-shop:3000", "juice_shop", args.scan_profile)
    all_alerts += run_scan("http://dvwa", "dvwa", args.scan_profile)
    save_alerts(all_alerts)
    save_scan_report(all_alerts, "zap_scan_report.json", args.scan_profile)
