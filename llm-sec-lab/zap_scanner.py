import time
import json
import os
import re
import requests
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlencode, urlsplit

ZAP_BASE_URL = 'http://localhost:8090'
ZAP_API_BASE = f'{ZAP_BASE_URL}/JSON'
API_TIMEOUT = (3, 5)
SESSION_RESET_TIMEOUT = (3, float(os.getenv("ZAP_SESSION_RESET_TIMEOUT_SECONDS", "90")))
MAX_STATUS_TIMEOUTS = int(os.getenv("ZAP_STATUS_MAX_CONSECUTIVE_ERRORS", "12"))
SPIDER_MAX_DURATION_MINS = int(os.getenv("ZAP_SPIDER_MAX_DURATION_MINS", "10"))
SPIDER_MAX_DEPTH = int(os.getenv("ZAP_SPIDER_MAX_DEPTH", "5"))
SPIDER_MAX_CHILDREN = int(os.getenv("ZAP_SPIDER_MAX_CHILDREN", "100"))
AJAX_SPIDER_MAX_DURATION_MINS = int(os.getenv("ZAP_AJAX_MAX_DURATION_MINS", "10"))
AJAX_SPIDER_MAX_DEPTH = int(os.getenv("ZAP_AJAX_MAX_CRAWL_DEPTH", "5"))
AJAX_SPIDER_BROWSERS = int(os.getenv("ZAP_AJAX_BROWSERS", "1"))
CLIENT_SPIDER_MAX_DURATION_MINS = int(os.getenv("ZAP_CLIENT_MAX_DURATION_MINS", "15"))
CLIENT_SPIDER_MAX_DEPTH = int(os.getenv("ZAP_CLIENT_MAX_CRAWL_DEPTH", "5"))
CLIENT_SPIDER_MAX_CHILDREN = int(os.getenv("ZAP_CLIENT_MAX_CHILDREN", "100"))
CLIENT_SPIDER_BROWSERS = int(os.getenv("ZAP_CLIENT_BROWSERS", "1"))
PASSIVE_SCAN_TIMEOUT_SECONDS = int(os.getenv("ZAP_PASSIVE_SCAN_TIMEOUT_SECONDS", "600"))
ACTIVE_SCAN_MAX_DURATION_MINS = int(os.getenv("ZAP_ACTIVE_MAX_SCAN_DURATION_MINS", "120"))
ACTIVE_RULE_MAX_DURATION_MINS = int(os.getenv("ZAP_ACTIVE_MAX_RULE_DURATION_MINS", "10"))
ACTIVE_SCAN_STALL_MINS = int(os.getenv("ZAP_ACTIVE_STALL_MINS", "45"))
FOCUSED_SCAN_TIMEOUT_MINS = int(os.getenv("ZAP_FOCUSED_SCAN_TIMEOUT_MINS", "5"))
FOCUSED_SCAN_GROUP_TIMEOUT_MINS = int(os.getenv("ZAP_FOCUSED_SCAN_GROUP_TIMEOUT_MINS", "30"))
TARGETED_SCAN_TIMEOUT_MINS = int(os.getenv("ZAP_TARGETED_SCAN_TIMEOUT_MINS", "30"))
ACTIVE_SCAN_THREADS_PER_HOST = int(os.getenv("ZAP_ACTIVE_THREADS_PER_HOST", "4"))
ACTIVE_SCAN_INJECTABLE_TARGETS = 31  # Query, POST, path, headers, and cookies.
ACTIVE_SCAN_STRUCTURED_HANDLERS = 7  # Multipart, XML, and JSON.
BENCHMARK_ENDPOINT = os.getenv(
    "VULNERABLE_APP_BENCHMARK_URL",
    "http://localhost:9090/VulnerableApp/scanner/benchmark",
)
VULNERABLE_APP_CATALOG_URL = os.getenv(
    "VULNERABLE_APP_CATALOG_URL",
    "http://localhost:9090/VulnerableApp/allEndPointJson",
)

TARGET_PROFILES = {
    "juice_shop": {
        "context_name": "juice_shop_dast",
        # Keep the legacy /juice-shop/ static alias out of crawler scope; it
        # expands into a recursive dependency tree. /ftp remains in scope.
        "context_exclude_regexes": [
            r"http://juice-shop:3000/juice-shop/.*",
        ],
        "active_scan_exclude_regexes": [
            # Discover these resources and retain their passive-scan history,
            # but do not actively attack them. They create a large number of
            # non-application paths and can exhaust the Juice Shop process.
            r"http://juice-shop:3000/(?:assets|build|node_modules|fonts|i18n|socket\.io|media)(?:/.*)?",
            r"http://juice-shop:3000/(?:[^/?]+\.(?:js|css|map|woff2?|ttf|eot|png|jpe?g|gif|svg|ico))(?:\?.*)?",
        ],
        "use_ajax_spider": True,
        "use_client_spider": True,
        "final_use_client_spider": False,
        "required_paths": [
            "/api/Challenges/",
            "/api/Feedbacks/",
            "/api/Quantitys/",
            "/ftp/legal.md",
            "/rest/admin/application-configuration",
            "/rest/admin/application-version",
            "/rest/captcha/",
            "/rest/languages",
            "/rest/products/1/reviews",
            "/rest/products/search",
            "/rest/user/whoami",
        ],
    },
    "vulnerable_app": {
        "context_name": "vulnerable_app_dast",
        "context_exclude_regexes": [],
        "active_scan_exclude_regexes": [],
        "use_ajax_spider": True,
        "use_client_spider": True,
        "final_use_client_spider": True,
        "required_paths": ["/VulnerableApp/"],
    },
}
SCAN_METADATA = []
ZAP_VERSION = ""
SCAN_PROFILES = ("benchmark", "baseline", "targeted", "final")
TARGETED_SCANNER_IDS = (6, 20019, 40012, 40014, 40017, 40018, 40019, 40020, 40021, 40022, 40026, 40027, 90020, 90037)
NOISE_SCANNER_ID = 10104
PROFILE_SCAN_POLICIES = {
    "benchmark": "Pen Test",
    "baseline": "Default Policy",
    "targeted": "Default Policy",
    "final": "LLM-SEC-Final",
}
FINAL_DISABLED_SCANNER_IDS = (
    10045, 10048, 20015, 20017, 20018, 40009, 40019, 40020, 40021,
    40022, 40026, 40027, 40028, 40029, 40032, 40042, 40043, 40045,
    40048, 90017, 90021, 90023, 90026, 90029, NOISE_SCANNER_ID,
)
ACTIVE_SCAN_INPUT_VECTORS = {
    "query_and_data_driven_nodes": True,
    "post_data": True,
    "multipart_form_data": True,
    "xml": True,
    "json": True,
    "url_path": True,
    "http_headers_all_requests": True,
    "cookies": True,
    "scripts": True,
}
FOCUSED_SCAN_POLICIES = {
    "LLM-SEC-Reflected-XSS": (40012,),
    "LLM-SEC-DOM-XSS": (40026,),
    "LLM-SEC-SQLi": (40018, 40019),
    "LLM-SEC-Final-SQLi": (40018,),
}
FOCUSED_POLICY_SNAPSHOTS = {}
FOCUSED_SCAN_REQUESTS = {
    "vulnerable_app": [
        {"url": "/XSSWithHtmlTagInjection/LEVEL_1?input=zap_seed", "method": "GET", "policy": "LLM-SEC-Reflected-XSS"},
        {"url": "/XSSWithHtmlTagInjection/LEVEL_2?input=zap_seed", "method": "GET", "policy": "LLM-SEC-Reflected-XSS"},
        {"url": "/XSSWithHtmlTagInjection/LEVEL_3?input=zap_seed", "method": "GET", "policy": "LLM-SEC-Reflected-XSS"},
        {"url": "/XSSInImgTagAttribute/LEVEL_1?input=zap_seed", "method": "GET", "policy": "LLM-SEC-Reflected-XSS"},
        {"url": "/XSSInImgTagAttribute/LEVEL_2?input=zap_seed", "method": "GET", "policy": "LLM-SEC-Reflected-XSS"},
        {"url": "/ErrorBasedSQLInjectionVulnerability/LEVEL_1?id=1", "method": "GET", "policy": "LLM-SEC-SQLi"},
        {"url": "/ErrorBasedSQLInjectionVulnerability/LEVEL_2?id=1", "method": "GET", "policy": "LLM-SEC-SQLi"},
        {"url": "/BlindSQLInjectionVulnerability/LEVEL_1?id=1", "method": "GET", "policy": "LLM-SEC-SQLi"},
        {"url": "/BlindSQLInjectionVulnerability/LEVEL_2?id=1", "method": "GET", "policy": "LLM-SEC-SQLi"},
        {"url": "/UnionBasedSQLInjectionVulnerability/LEVEL_1?id=1", "method": "GET", "policy": "LLM-SEC-SQLi"},
        {"url": "/UnionBasedSQLInjectionVulnerability/LEVEL_2?id=1", "method": "GET", "policy": "LLM-SEC-SQLi"},
    ],
    "juice_shop": [
        {"url": "/rest/products/search?q=apple", "method": "GET", "policy": "LLM-SEC-SQLi"},
        {"url": "/#/search?q=apple", "method": "GET", "policy": "LLM-SEC-DOM-XSS", "browser_warm": True},
    ],
}
TARGETED_REQUESTS = {
    "juice_shop": [
        {"url": "/rest/products/search?q=apple", "method": "GET", "post_data": ""},
    ],
    "vulnerable_app": [
        {"url": "/", "method": "GET", "post_data": ""},
    ],
}
JUICE_SHOP_SEED_PATHS = (
    "/api/Challenges/?name=Score%20Board",
    "/api/Feedbacks/",
    "/api/Quantitys/",
    "/ftp/legal.md",
    "/rest/admin/application-configuration",
    "/rest/admin/application-version",
    "/rest/captcha/",
    "/rest/languages",
    "/rest/products/1/reviews",
    "/rest/products/search?q=apple",
    "/rest/user/whoami",
)

session = requests.Session()
session.trust_env = False

def zap_api(component: str, kind: str, endpoint: str, *, request_timeout=API_TIMEOUT, **params):
    """Call a ZAP API endpoint without reserving common request parameter names."""
    url = f'{ZAP_API_BASE}/{component}/{kind}/{endpoint}/'
    response = session.get(url, params=params, timeout=request_timeout)
    response.raise_for_status()
    return response.json()

def configure_active_scan(
    scan_profile: str = "benchmark", scan_label: str | None = None,
) -> list[dict]:
    if scan_profile not in SCAN_PROFILES:
        raise ValueError(f"Unknown scan profile: {scan_profile}")
    scan_policy = PROFILE_SCAN_POLICIES[scan_profile]
    if scan_profile != "final" and (
        ACTIVE_SCAN_MAX_DURATION_MINS < 1 or ACTIVE_RULE_MAX_DURATION_MINS < 1
    ):
        raise ValueError("ZAP active scan duration limits must be at least 1 minute")
    if ACTIVE_SCAN_STALL_MINS < 1:
        raise ValueError("ZAP_ACTIVE_STALL_MINS must be at least 1")
    max_rule_duration = 0 if scan_profile == "final" else ACTIVE_RULE_MAX_DURATION_MINS
    max_scan_duration = 0 if scan_profile == "final" else ACTIVE_SCAN_MAX_DURATION_MINS
    zap_api("ascan", "action", "setOptionThreadPerHost", Integer=ACTIVE_SCAN_THREADS_PER_HOST)
    zap_api("ascan", "action", "setOptionMaxRuleDurationInMins", Integer=max_rule_duration)
    zap_api("ascan", "action", "setOptionMaxScanDurationInMins", Integer=max_scan_duration)
    zap_api("ascan", "action", "setOptionMaxAlertsPerRule", Integer=0)
    zap_api("ascan", "action", "setOptionHandleAntiCSRFTokens", Boolean="true")
    zap_api("ascan", "action", "setOptionAddQueryParam", Boolean="true")
    zap_api(
        "ascan", "action", "setOptionScanHeadersAllRequests",
        Boolean="false" if scan_profile == "final" else "true",
    )
    zap_api("ascan", "action", "setOptionInjectPluginIdInHeader", Boolean="true")
    zap_api("ascan", "action", "setOptionTargetParamsInjectable", Integer=ACTIVE_SCAN_INJECTABLE_TARGETS)
    zap_api("ascan", "action", "setOptionTargetParamsEnabledRPC", Integer=ACTIVE_SCAN_STRUCTURED_HANDLERS)
    # ZAP 2.17 exposes separate enable/disable actions rather than a
    # setScannerEnabled action.
    if scan_profile in {"benchmark", "final"}:
        if scan_profile == "final":
            try:
                zap_api("ascan", "action", "removeScanPolicy", scanPolicyName=scan_policy)
            except requests.RequestException:
                pass
            zap_api("ascan", "action", "addScanPolicy", scanPolicyName=scan_policy)
        # Pen Test is the installed policy which enables every non-example active
        # rule. Keep the user-agent fuzzer off: it is noise for this benchmark.
        zap_api("ascan", "action", "enableAllScanners", scanPolicyName=scan_policy)
        scanners = zap_api(
            "ascan", "view", "scanners", scanPolicyName=scan_policy,
        ).get("scanners", [])
        configured_disabled_ids = (
            FINAL_DISABLED_SCANNER_IDS
            if scan_profile == "final" and scan_label in {None, "juice_shop"}
            else (NOISE_SCANNER_ID,)
        )
        installed_ids = {str(scanner.get("id", "")).strip() for scanner in scanners}
        disabled_ids = tuple(
            value for value in configured_disabled_ids if str(value) in installed_ids
        )
        if disabled_ids:
            zap_api(
                "ascan", "action", "disableScanners",
                ids=",".join(str(value) for value in disabled_ids), scanPolicyName=scan_policy,
            )
        for scanner in scanners:
            scanner_id = str(scanner.get("id", "")).strip()
            if not scanner_id or scanner_id in {str(value) for value in disabled_ids}:
                continue
            zap_api(
                "ascan", "action", "setScannerAttackStrength",
                id=scanner_id,
                attackStrength="MEDIUM" if scan_profile == "final" else "HIGH",
                scanPolicyName=scan_policy,
            )
            zap_api(
                "ascan", "action", "setScannerAlertThreshold",
                id=scanner_id, alertThreshold="LOW", scanPolicyName=scan_policy,
            )
        return zap_api(
            "ascan", "view", "scanners", scanPolicyName=scan_policy,
        ).get("scanners", [])

    zap_api(
        "ascan", "action", "enableScanners",
        ids=str(NOISE_SCANNER_ID), scanPolicyName=scan_policy,
    )
    for scanner_id in TARGETED_SCANNER_IDS:
        zap_api(
            "ascan", "action", "setScannerAttackStrength",
            id=str(scanner_id), attackStrength="DEFAULT", scanPolicyName=scan_policy,
        )
    if scan_profile == "targeted":
        zap_api(
            "ascan", "action", "disableScanners",
            ids=str(NOISE_SCANNER_ID), scanPolicyName=scan_policy,
        )
        for scanner_id in TARGETED_SCANNER_IDS:
            zap_api(
                "ascan", "action", "setScannerAttackStrength",
                id=str(scanner_id), attackStrength="HIGH", scanPolicyName=scan_policy,
            )
    return zap_api(
        "ascan", "view", "scanners", scanPolicyName=scan_policy,
    ).get("scanners", [])


def configure_focused_scan_policies() -> dict[str, list[dict]]:
    """Recreate narrow high-signal policies so persisted ZAP state cannot leak in."""
    snapshots = {}
    for policy_name, scanner_ids in FOCUSED_SCAN_POLICIES.items():
        try:
            zap_api("ascan", "action", "removeScanPolicy", scanPolicyName=policy_name)
        except requests.RequestException:
            pass
        zap_api("ascan", "action", "addScanPolicy", scanPolicyName=policy_name)
        zap_api("ascan", "action", "disableAllScanners", scanPolicyName=policy_name)
        ids = ",".join(str(scanner_id) for scanner_id in scanner_ids)
        zap_api("ascan", "action", "enableScanners", ids=ids, scanPolicyName=policy_name)
        for scanner_id in scanner_ids:
            zap_api(
                "ascan", "action", "setScannerAttackStrength",
                id=str(scanner_id), attackStrength="HIGH", scanPolicyName=policy_name,
            )
            zap_api(
                "ascan", "action", "setScannerAlertThreshold",
                id=str(scanner_id), alertThreshold="LOW", scanPolicyName=policy_name,
            )
        scanners = zap_api(
            "ascan", "view", "scanners", scanPolicyName=policy_name,
        ).get("scanners", [])
        installed = {
            str(scanner.get("id", "")).strip(): scanner for scanner in scanners
            if str(scanner.get("id", "")).strip()
        }
        missing = sorted(set(ids.split(",")) - set(installed))
        if missing:
            raise RuntimeError(
                f"Focused scan policy {policy_name} is missing required ZAP plugins: {missing}"
            )
        disabled = sorted(
            scanner_id for scanner_id in ids.split(",")
            if str(installed[scanner_id].get("enabled", "")).strip().lower() != "true"
        )
        if disabled:
            raise RuntimeError(
                f"Focused scan policy {policy_name} did not enable required ZAP plugins: {disabled}"
            )
        snapshots[policy_name] = scanners
    FOCUSED_POLICY_SNAPSHOTS.clear()
    FOCUSED_POLICY_SNAPSHOTS.update(snapshots)
    return snapshots


def ensure_focused_scan_policies() -> dict[str, list[dict]]:
    if not FOCUSED_POLICY_SNAPSHOTS:
        return configure_focused_scan_policies()
    return FOCUSED_POLICY_SNAPSHOTS


def configure_spider() -> None:
    if SPIDER_MAX_DURATION_MINS < 1 or SPIDER_MAX_DEPTH < 1 or SPIDER_MAX_CHILDREN < 1:
        raise ValueError("ZAP traditional spider limits must be positive")
    zap_api("spider", "action", "setOptionMaxDuration", Integer=SPIDER_MAX_DURATION_MINS)
    zap_api("spider", "action", "setOptionMaxDepth", Integer=SPIDER_MAX_DEPTH)
    zap_api("spider", "action", "setOptionMaxChildren", Integer=SPIDER_MAX_CHILDREN)
    zap_api("spider", "action", "setOptionThreadCount", Integer=2)


def configure_ajax_spider() -> None:
    if AJAX_SPIDER_BROWSERS < 1:
        raise ValueError("ZAP_AJAX_BROWSERS must be at least 1")
    if AJAX_SPIDER_MAX_DURATION_MINS < 1 or AJAX_SPIDER_MAX_DEPTH < 1:
        raise ValueError("ZAP AJAX spider limits must be positive")
    zap_api("ajaxSpider", "action", "setOptionMaxCrawlDepth", Integer=AJAX_SPIDER_MAX_DEPTH)
    zap_api("ajaxSpider", "action", "setOptionMaxDuration", Integer=AJAX_SPIDER_MAX_DURATION_MINS)
    zap_api("ajaxSpider", "action", "setOptionNumberOfBrowsers", Integer=AJAX_SPIDER_BROWSERS)


def configure_client_spider() -> None:
    if CLIENT_SPIDER_BROWSERS < 1:
        raise ValueError("ZAP_CLIENT_BROWSERS must be at least 1")
    if (
        CLIENT_SPIDER_MAX_DURATION_MINS < 1
        or CLIENT_SPIDER_MAX_DEPTH < 1
        or CLIENT_SPIDER_MAX_CHILDREN < 1
    ):
        raise ValueError("ZAP Client Spider limits must be positive")
    zap_api(
        "clientSpider", "action", "setOptionMaxDuration",
        Integer=CLIENT_SPIDER_MAX_DURATION_MINS,
    )
    zap_api(
        "clientSpider", "action", "setOptionMaxChildren",
        Integer=CLIENT_SPIDER_MAX_CHILDREN,
    )


def _stop_scan(component: str, scan_id: str | None = None) -> None:
    params = {"scanId": str(scan_id)} if scan_id is not None else {}
    zap_api(component, "action", "stop", **params)

def _poll_progress(
    get_status,
    scan_id: str,
    label: str,
    poll_seconds: int,
    *,
    timeout_seconds: float | None = None,
    stop_scan=None,
    get_progress_snapshot=None,
    stall_seconds: float | None = None,
) -> dict:
    start = time.time()
    last_change = start
    last_progress = None
    last_snapshot_token = ""
    progress_snapshots = []
    timeout_count = 0
    while True:
        try:
            status = get_status(scan_id)
            timeout_count = 0
        except (requests.Timeout, requests.ConnectionError) as exc:
            timeout_count += 1
            if timeout_count > MAX_STATUS_TIMEOUTS:
                print()
                raise RuntimeError(f"{label} status did not respond after {MAX_STATUS_TIMEOUTS} retries") from exc
            elapsed_minutes = (time.time() - start) / 60
            print(f"  {label} status unavailable; retrying ({timeout_count}/{MAX_STATUS_TIMEOUTS}) after {elapsed_minutes:.1f} min", end="\r")
            time.sleep(poll_seconds)
            continue
        if not str(status).isdigit():
            print()
            raise RuntimeError(f"{label} scan failed or was not created. ZAP returned status: {status}")
        progress = int(status)
        snapshot = None
        snapshot_token = ""
        if get_progress_snapshot is not None:
            try:
                snapshot = get_progress_snapshot(scan_id)
                snapshot_token = json.dumps(snapshot, sort_keys=True, default=str)
            except (requests.RequestException, ValueError, TypeError) as exc:
                snapshot = {"capture_error": str(exc)}
        if progress != last_progress or (snapshot_token and snapshot_token != last_snapshot_token):
            last_change = time.time()
            last_progress = progress
            if snapshot_token:
                last_snapshot_token = snapshot_token
            progress_snapshots.append({
                "captured_at_utc": datetime.now(timezone.utc).isoformat(),
                "progress": progress,
                "scan_progress": snapshot,
            })
        if progress >= 100:
            print()
            return {
                "status": "completed", "scan_id": str(scan_id), "progress": progress,
                "elapsed_seconds": round(time.time() - start, 3), "error": "",
                "progress_snapshots": progress_snapshots,
            }
        elapsed_minutes = (time.time() - start) / 60
        print(f"  {label} progress: {progress}% after {elapsed_minutes:.1f} min", end="\r")
        if timeout_seconds is not None and time.time() - start >= timeout_seconds:
            try:
                if stop_scan is not None:
                    stop_scan(scan_id)
            except requests.RequestException as exc:
                print()
                raise RuntimeError(f"{label} exceeded its deadline and could not be stopped") from exc
            print()
            return {
                "status": "timed_out", "scan_id": str(scan_id), "progress": progress,
                "elapsed_seconds": round(time.time() - start, 3),
                "error": f"Exceeded {timeout_seconds:g} second deadline",
                "progress_snapshots": progress_snapshots,
            }
        if stall_seconds is not None and time.time() - last_change >= stall_seconds:
            try:
                if stop_scan is not None:
                    stop_scan(scan_id)
            except requests.RequestException as exc:
                print()
                raise RuntimeError(f"{label} stalled and could not be stopped") from exc
            print()
            return {
                "status": "stalled", "scan_id": str(scan_id), "progress": progress,
                "elapsed_seconds": round(time.time() - start, 3),
                "no_progress_seconds": round(time.time() - last_change, 3),
                "error": f"No plugin progress or request-count change for {stall_seconds:g} seconds",
                "progress_snapshots": progress_snapshots,
            }
        time.sleep(poll_seconds)


def wait_for_progress(
    get_status,
    scan_id: str,
    label: str,
    poll_seconds: int,
    *,
    timeout_seconds: float | None = None,
    stop_scan=None,
    get_progress_snapshot=None,
    stall_seconds: float | None = None,
) -> dict:
    try:
        return _poll_progress(
            get_status, scan_id, label, poll_seconds,
            timeout_seconds=timeout_seconds, stop_scan=stop_scan,
            get_progress_snapshot=get_progress_snapshot, stall_seconds=stall_seconds,
        )
    except KeyboardInterrupt:
        if stop_scan is not None:
            try:
                stop_scan(scan_id)
            except requests.RequestException:
                pass
        print()
        raise


def scan_id_from_response(response: dict, action: str, scan_label: str) -> str:
    """Return ZAP's scan identifier for either normal or user-scoped actions."""
    for key in ("scan", "scanId", action):
        scan_id = response.get(key)
        if scan_id is not None and str(scan_id):
            return str(scan_id)
    raise RuntimeError(
        f"[{scan_label}] ZAP did not return a scan ID for {action}: {response}"
    )

def wait_for_zap(timeout=60):
    global ZAP_VERSION
    start = time.time()
    last_error = None
    while time.time() - start < timeout:
        try:
            response = session.get(f'{ZAP_BASE_URL}/JSON/core/view/version/', timeout=3)
            response.raise_for_status()
            # Do not begin a scan until the JavaScript-aware crawler add-on is ready.
            zap_api("ajaxSpider", "view", "status")
            ZAP_VERSION = str(response.json().get("version", ""))
            print("ZAP is running, version:", ZAP_VERSION)
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
    for pattern in profile["context_exclude_regexes"]:
        zap_api("context", "action", "excludeFromContext", contextName=context_name, regex=pattern)
    return {"id": context_id, "name": context_name}


def configure_juice_shop_authentication(target_url: str, context: dict) -> dict:
    """Configure ZAP browser authentication without persisting credentials."""
    email = os.getenv("JUICE_SHOP_AUTH_EMAIL", "").strip()
    password = os.getenv("JUICE_SHOP_AUTH_PASSWORD", "")
    if not email or not password:
        raise RuntimeError(
            "Authenticated Juice Shop scanning requires JUICE_SHOP_AUTH_EMAIL and "
            "JUICE_SHOP_AUTH_PASSWORD environment variables"
        )
    registration = ensure_juice_shop_test_account(target_url, email, password)
    login_url = f"{target_url}/#/login"
    verification_url = f"{target_url}/rest/user/whoami"
    auth_config = urlencode({
        "loginPageUrl": login_url,
        "browserId": "firefox-headless",
        "verificationUrl": verification_url,
        "verificationPollFrequency": "5",
    })
    zap_api(
        "authentication", "action", "setAuthenticationMethod",
        contextId=context["id"], authMethodName="browserBasedAuthentication",
        authMethodConfigParams=auth_config,
    )
    zap_api(
        "sessionManagement", "action", "setSessionManagementMethod",
        contextId=context["id"], methodName="autoDetectSessionManagement",
        methodConfigParams="",
    )
    logout_regex = rf"{re.escape(target_url)}/(?:rest/user/logout|#/logout)(?:[/?#].*)?"
    zap_api(
        "context", "action", "excludeFromContext",
        contextName=context["name"], regex=logout_regex,
    )
    user_name = "llm-sec-juice-shop"
    user_response = zap_api(
        "users", "action", "newUser", contextId=context["id"], name=user_name,
    )
    user_id = str(user_response.get("userId", user_response.get("user", "")))
    if not user_id:
        raise RuntimeError(f"ZAP did not return an authenticated user ID: {user_response}")
    credentials = urlencode({"username": email, "password": password})
    zap_api(
        "users", "action", "setAuthenticationCredentials",
        contextId=context["id"], userId=user_id,
        authCredentialsConfigParams=credentials,
    )
    zap_api(
        "users", "action", "setUserEnabled",
        contextId=context["id"], userId=user_id, enabled="true",
    )
    return {
        "user_id": user_id,
        "user_name": user_name,
        "email": email,
        "method": "browserBasedAuthentication",
        "session_management": "autoDetectSessionManagement",
        "login_url": login_url,
        "verification_url": verification_url,
        "logout_exclusion": logout_regex,
        "expected_session_tokens": ["Authorization: Bearer", "cookie"],
        "registration": registration,
    }


def ensure_juice_shop_test_account(target_url: str, email: str, password: str) -> dict:
    """Create the local test account if absent; duplicate-account responses are harmless."""
    body = json.dumps({
        "email": email,
        "password": password,
        "passwordRepeat": password,
        "securityQuestion": {"id": 1, "answer": "automated-local-lab"},
    }, separators=(",", ":"))
    parsed = urlsplit(target_url)
    request = "\r\n".join([
        "POST /api/Users/ HTTP/1.1",
        f"Host: {parsed.netloc}",
        "Content-Type: application/json",
        f"Content-Length: {len(body.encode('utf-8'))}",
        "User-Agent: LLM-SEC-Auth-Bootstrap",
        "",
        body,
    ])
    zap_api("core", "action", "sendRequest", request=request, followRedirects="false")
    return {
        "attempted": True,
        "endpoint": f"{target_url}/api/Users/",
        "credentials_persisted": False,
        "note": "Account creation is idempotent; authentication verification is authoritative.",
    }


def verify_authenticated_whoami(target_url: str, email: str, timeout_seconds: int = 60) -> dict:
    """Verify that an authenticated browser request reached Juice Shop's whoami route."""
    started = time.time()
    whoami_url = f"{target_url}/rest/user/whoami"
    while time.time() - started < timeout_seconds:
        messages = zap_api(
            "core", "view", "messages", baseurl=whoami_url, start=0, count=100,
        ).get("messages", [])
        for message in reversed(messages):
            response_body = str(message.get("responseBody", ""))
            request_header = str(message.get("requestHeader", ""))
            token_types = []
            if re.search(r"(?im)^Authorization:\s*Bearer\s+\S+", request_header):
                token_types.append("authorization_bearer")
            if re.search(r"(?im)^Cookie:\s*.+", request_header):
                token_types.append("cookie")
            if email.lower() in response_body.lower() and token_types:
                return {
                    "status": "verified",
                    "verification_url": whoami_url,
                    "message_id": str(message.get("id", "")),
                    "elapsed_seconds": round(time.time() - started, 3),
                    "observed_session_token_types": token_types,
                    "credentials_or_tokens_persisted": False,
                }
        time.sleep(5)
    raise RuntimeError(
        "Authenticated Juice Shop session was not verified through /rest/user/whoami"
    )


def configure_active_scan_exclusions(scan_label: str) -> list[str]:
    """Replace global active-scan exclusions with this target's host-scoped rules."""
    patterns = list(TARGET_PROFILES[scan_label]["active_scan_exclude_regexes"])
    zap_api("ascan", "action", "clearExcludedFromScan")
    for pattern in patterns:
        zap_api("ascan", "action", "excludeFromScan", regex=pattern)
    return patterns


def seed_juice_shop_requests(target_url: str) -> dict:
    """Add stable, read-only API routes to ZAP's history before active scanning."""
    seed_urls = [f"{target_url}{path}" for path in JUICE_SHOP_SEED_PATHS]
    seeded = 0
    failed_urls = []
    for url in seed_urls:
        try:
            zap_api("core", "action", "accessUrl", url=url, followRedirects="true")
        except requests.RequestException as exc:
            # Discovery validation below remains authoritative. A failed
            # convenience seed must not discard an otherwise valid crawl.
            print(f"[juice_shop] API seed request failed for {url}: {exc}")
            failed_urls.append(url)
        else:
            seeded += 1
    return {
        "attempted": len(seed_urls),
        "seeded": seeded,
        "failed": len(failed_urls),
        "failed_urls": failed_urls,
        "error": "",
    }


def _vulnerable_app_seed_specs(target_url: str) -> list[dict]:
    """Build method-correct seed requests from VulnerableApp's scanner catalogue."""
    response = session.get(VULNERABLE_APP_CATALOG_URL, timeout=API_TIMEOUT)
    response.raise_for_status()
    specs, seen = [], set()
    for family in response.json():
        name = str(family.get("Name", "")).strip()
        for level in family.get("Detailed Information", []):
            route = f"/{name}/{str(level.get('Level', '')).strip()}"
            method = str(level.get("HttpMethod", "GET")).strip().upper() or "GET"
            if not name or route.endswith("/"):
                continue
            key = (route, method)
            if key in seen:
                continue
            seen.add(key)
            # A benign parameter gives active rules a concrete input vector on
            # routes whose templates consume arbitrary query/body parameters.
            if method == "GET":
                if name in {
                    "BlindSQLInjectionVulnerability",
                    "ErrorBasedSQLInjectionVulnerability",
                    "UnionBasedSQLInjectionVulnerability",
                }:
                    query = "id=1"
                elif name in {"XSSWithHtmlTagInjection", "XSSInImgTagAttribute"}:
                    query = "input=zap_seed"
                else:
                    query = "zap_seed=1"
                specs.append({"method": method, "url": f"{target_url}{route}?{query}", "body": "", "content_type": ""})
            elif name == "XXEVulnerability":
                specs.append({
                    "method": method, "url": f"{target_url}{route}",
                    "body": "<zapSeed><value>1</value></zapSeed>",
                    "content_type": "application/xml",
                })
            else:
                specs.append({
                    "method": method, "url": f"{target_url}{route}",
                    "body": "username=zap_seed&password=zap_seed&input=zap_seed&comment=zap_seed&file=zap_seed.txt",
                    "content_type": "application/x-www-form-urlencoded",
                })
    return specs


def _raw_seed_request(spec: dict) -> str:
    parsed = urlsplit(spec["url"])
    path = parsed.path + (f"?{parsed.query}" if parsed.query else "")
    body = spec["body"]
    headers = [
        f"{spec['method']} {path} HTTP/1.1",
        f"Host: {parsed.netloc}",
        "User-Agent: LLM-SEC-ZAP-Benchmark-Seed",
    ]
    if body:
        headers.extend([
            f"Content-Type: {spec['content_type']}",
            f"Content-Length: {len(body.encode('utf-8'))}",
        ])
    return "\r\n".join(headers) + "\r\n\r\n" + body


def seed_vulnerable_app_requests(target_url: str) -> dict:
    """Prime ZAP history with benchmark routes, methods, and safe input vectors."""
    try:
        specs = _vulnerable_app_seed_specs(target_url)
    except requests.RequestException as exc:
        print(f"[vulnerable_app] Benchmark catalogue unavailable; continuing without route seeds: {exc}")
        return {
            "attempted": 0, "seeded": 0, "failed": 0,
            "failed_urls": [], "error": str(exc),
        }

    seeded = 0
    failed_urls = []
    for spec in specs:
        try:
            zap_api(
                "core", "action", "sendRequest",
                request=_raw_seed_request(spec), followRedirects="true",
            )
            seeded += 1
        except requests.RequestException as exc:
            print(f"[vulnerable_app] Seed request failed for {spec['method']} {spec['url']}: {exc}")
            failed_urls.append(spec["url"])
    return {
        "attempted": len(specs),
        "seeded": seeded,
        "failed": len(failed_urls),
        "failed_urls": failed_urls,
        "error": "",
    }


def run_targeted_active_scans(
    target_url: str,
    scan_label: str,
    context: dict,
    user_id: str | None,
    scan_policy: str,
) -> list[dict]:
    """Run reproducible, endpoint-specific scans after normal discovery."""
    scan_ids = []
    for request_spec in TARGETED_REQUESTS[scan_label]:
        url = f"{target_url}{request_spec['url']}"
        params = {
            "url": url,
            "recurse": "false",
            "inScopeOnly": "true",
            "scanPolicyName": scan_policy,
            "method": request_spec["method"],
            "postData": request_spec["post_data"],
            "contextId": context["id"],
        }
        action = "scanAsUser" if user_id is not None else "scan"
        if user_id is not None:
            params["userId"] = user_id
        response = zap_api("ascan", "action", action, **params)
        scan_id = scan_id_from_response(response, action, scan_label)
        outcome = wait_for_progress(
            lambda current_id: zap_api("ascan", "view", "status", scanId=current_id)["status"],
            scan_id,
            f"Targeted active scan {request_spec['url']}",
            5,
            timeout_seconds=TARGETED_SCAN_TIMEOUT_MINS * 60,
            stop_scan=lambda current_id: _stop_scan("ascan", current_id),
        )
        scan_ids.append({
            "url": url, "method": request_spec["method"], "scan_id": scan_id,
            "status": outcome["status"], "outcome": outcome,
        })
    return scan_ids


def _seed_focused_request(url: str, method: str) -> dict:
    """Put the exact parameterized request in ZAP history before selecting it."""
    spec = {"url": url, "method": method, "body": "", "content_type": ""}
    try:
        zap_api(
            "core", "action", "sendRequest",
            request=_raw_seed_request(spec), followRedirects="true",
        )
        return {"url": url, "method": method, "success": True, "error": ""}
    except requests.RequestException as exc:
        return {"url": url, "method": method, "success": False, "error": str(exc)}


def run_focused_active_scans(
    target_url: str,
    scan_label: str,
    context: dict,
    user_id: str | None = None,
    scan_profile: str = "benchmark",
) -> list[dict]:
    """Run narrow, reproducible high-signal scans after the broad active scan."""
    ensure_focused_scan_policies()
    results = []
    group_started = time.time()
    requests_to_scan = [
        {
            **request,
            "policy": "LLM-SEC-Final-SQLi"
            if scan_profile == "final" and request["policy"] == "LLM-SEC-SQLi"
            else request["policy"],
        }
        for request in FOCUSED_SCAN_REQUESTS[scan_label]
        if not (scan_profile == "final" and request["policy"] == "LLM-SEC-DOM-XSS")
    ]
    for request_spec in requests_to_scan:
        group_remaining = (
            float("inf") if scan_profile == "final" else
            FOCUSED_SCAN_GROUP_TIMEOUT_MINS * 60 - (time.time() - group_started)
        )
        if group_remaining <= 0:
            results.append({
                "url": f"{target_url}{request_spec['url']}",
                "method": request_spec["method"],
                "policy": request_spec["policy"],
                "scan_id": "",
                "status": "skipped",
                "error": "Focused scan group deadline exhausted",
            })
            continue
        url = f"{target_url}{request_spec['url']}"
        browser_warmed = False
        if request_spec.get("browser_warm"):
            browser_outcome = run_client_spider(url, context, scan_label)
            browser_warmed = browser_outcome["status"] == "completed"
            seed = {
                "url": url, "method": request_spec["method"],
                "success": browser_warmed,
                "error": "" if browser_warmed else browser_outcome.get("error", "Client spider did not complete"),
                "client_spider": browser_outcome,
            }
        else:
            seed = _seed_focused_request(url, request_spec["method"])

        group_remaining = (
            float("inf") if scan_profile == "final" else
            FOCUSED_SCAN_GROUP_TIMEOUT_MINS * 60 - (time.time() - group_started)
        )
        if group_remaining <= 0:
            results.append({
                "url": url,
                "method": request_spec["method"],
                "policy": request_spec["policy"],
                "scan_id": "",
                "status": "skipped",
                "seed": seed,
                "browser_warmed": browser_warmed,
                "error": "Focused scan group deadline exhausted",
            })
            continue
        is_dom_scan = request_spec["policy"] == "LLM-SEC-DOM-XSS"
        if is_dom_scan:
            zap_api("ascan", "action", "setOptionThreadPerHost", Integer=1)
        try:
            action = "scanAsUser" if user_id is not None else "scan"
            scan_params = {
                "url": url,
                "recurse": "false",
                "inScopeOnly": "true",
                "scanPolicyName": request_spec["policy"],
                "method": request_spec["method"],
                "postData": "",
                "contextId": context["id"],
            }
            if user_id is not None:
                scan_params["userId"] = user_id
            response = zap_api(
                "ascan", "action", action,
                **scan_params,
            )
            scan_id = scan_id_from_response(response, action, scan_label)
            outcome = wait_for_progress(
                lambda current_id: zap_api(
                    "ascan", "view", "status", scanId=current_id,
                )["status"],
                scan_id,
                f"Focused {request_spec['policy']} scan {request_spec['url']}",
                5,
                timeout_seconds=(
                    None if scan_profile == "final"
                    else min(FOCUSED_SCAN_TIMEOUT_MINS * 60, group_remaining)
                ),
                stop_scan=lambda current_id: _stop_scan("ascan", current_id),
                get_progress_snapshot=lambda current_id: zap_api(
                    "ascan", "view", "scanProgress", scanId=current_id,
                ),
                stall_seconds=ACTIVE_SCAN_STALL_MINS * 60 if scan_profile == "final" else None,
            )
            try:
                progress = zap_api("ascan", "view", "scanProgress", scanId=scan_id)
            except requests.RequestException as exc:
                progress = {"error": str(exc)}
            results.append({
                "url": url,
                "method": request_spec["method"],
                "policy": request_spec["policy"],
                "scan_id": scan_id,
                "status": outcome["status"],
                "outcome": outcome,
                "seed": seed,
                "browser_warmed": browser_warmed,
                "scan_progress": progress,
            })
        finally:
            if is_dom_scan:
                zap_api(
                    "ascan", "action", "setOptionThreadPerHost",
                    Integer=ACTIVE_SCAN_THREADS_PER_HOST,
                )
    return results


def start_fresh_zap_session() -> None:
    """Prevent prior aborted scans from contaminating discovery or exhausting ZAP."""
    # ZAP serializes session disposal and database creation. A large completed
    # scan can therefore take longer than ordinary API calls even though the
    # daemon is healthy; do not apply the five-second status-call timeout here.
    zap_api(
        "core", "action", "newSession", name="", overwrite="true",
        request_timeout=SESSION_RESET_TIMEOUT,
    )
    FOCUSED_POLICY_SNAPSHOTS.clear()


def wait_for_ajax_spider(timeout=None) -> dict:
    start = time.time()
    try:
        while True:
            status = zap_api("ajaxSpider", "view", "status").get("status", "")
            if status.lower() == "stopped":
                print()
                return {
                    "status": "completed", "scan_id": "", "progress": 100,
                    "elapsed_seconds": round(time.time() - start, 3), "error": "",
                }
            if timeout is not None and time.time() - start > timeout:
                zap_api("ajaxSpider", "action", "stop")
                print()
                return {
                    "status": "timed_out", "scan_id": "", "progress": status,
                    "elapsed_seconds": round(time.time() - start, 3),
                    "error": f"Exceeded {timeout:g} second deadline",
                }
            elapsed_minutes = (time.time() - start) / 60
            print(f"  AJAX spider progress: {status} after {elapsed_minutes:.1f} min", end="\r")
            time.sleep(5)
    except KeyboardInterrupt:
        try:
            zap_api("ajaxSpider", "action", "stop")
        except requests.RequestException:
            pass
        print()
        raise


def wait_for_passive_scan(timeout=PASSIVE_SCAN_TIMEOUT_SECONDS) -> dict:
    start = time.time()
    while True:
        remaining = int(zap_api("pscan", "view", "recordsToScan").get("recordsToScan", 0))
        if remaining == 0:
            return {
                "status": "completed", "remaining_records": 0,
                "elapsed_seconds": round(time.time() - start, 3), "error": "",
            }
        if time.time() - start > timeout:
            return {
                "status": "timed_out", "remaining_records": remaining,
                "elapsed_seconds": round(time.time() - start, 3),
                "error": f"Passive scan queue did not drain within {timeout:g} seconds",
            }
        time.sleep(2)


def run_client_spider(target_url: str, context: dict, scan_label: str) -> dict:
    """Use browser-driven discovery when the installed ZAP supports it."""
    try:
        configure_client_spider()
        response = zap_api(
            "clientSpider", "action", "scan", browser="firefox-headless",
            url=target_url, contextName=context["name"], subtreeOnly="true",
            maxCrawlDepth=CLIENT_SPIDER_MAX_DEPTH,
            pageLoadTime=10,
            numberOfBrowsers=CLIENT_SPIDER_BROWSERS,
            scopeCheck="STRICT",
        )
        scan_id = scan_id_from_response(response, "scan", scan_label)
        return wait_for_progress(
            lambda current_id: zap_api("clientSpider", "view", "status", scanId=current_id)["status"],
            scan_id, "Client spider", 5,
            timeout_seconds=CLIENT_SPIDER_MAX_DURATION_MINS * 60,
            stop_scan=lambda current_id: _stop_scan("clientSpider", current_id),
        )
    except requests.RequestException as exc:
        print(f"[{scan_label}] Client spider unavailable; continuing with AJAX spider: {exc}")
        return {
            "status": "unavailable", "scan_id": "", "progress": "",
            "elapsed_seconds": 0.0, "error": str(exc),
        }


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


def _request_method(message_id) -> str:
    if message_id is None or str(message_id).strip() in {"", "-1"}:
        return ""
    try:
        response = zap_api("core", "view", "message", id=str(message_id))
    except (requests.RequestException, ValueError):
        return ""
    message = response.get("message", response)
    if not isinstance(message, dict):
        return ""
    header = str(message.get("requestHeader", ""))
    first_line = header.splitlines()[0] if header else ""
    return first_line.split(" ", 1)[0].upper() if " " in first_line else ""


def _normalise_alert_evidence(alert: dict) -> tuple[str, str]:
    """Use ZAP's DOM reproduction steps when rule 40026 omits evidence."""
    plugin_id = alert.get("pluginId", alert.get("pluginid"))
    native_evidence = str(alert.get("evidence", "") or "")
    other = str(alert.get("other", "") or "")
    if str(plugin_id) == "40026" and not native_evidence.strip() and other.strip():
        return other, "other"
    return native_evidence, "native" if native_evidence.strip() else ""


def collect_alerts(
    target_url: str, scan_label: str, scan_profile: str = "benchmark",
    *, authentication_context: str = "unauthenticated", environment: dict | None = None,
) -> tuple[list[dict], list[dict]]:
    """Recover raw and enriched alerts from the current ZAP session."""
    raw_alerts = zap_api("core", "view", "alerts", baseurl=target_url).get("alerts", [])
    alerts = []
    for alert in raw_alerts:
        plugin_id = alert.get("pluginId", alert.get("pluginid"))
        other = str(alert.get("other", "") or "")
        evidence, evidence_source = _normalise_alert_evidence(alert)
        message_id = alert.get("messageId", alert.get("messageid"))
        environment = environment or {}
        target_environment = environment.get("images", {}).get(scan_label, {})
        alerts.append({
            "app": scan_label,
            "alert_name": alert.get("alert", ""),
            "risk": alert.get("risk", ""),
            "confidence": alert.get("confidence", ""),
            "url": alert.get("url", ""),
            "description": alert.get("description", ""),
            "solution": alert.get("solution", ""),
            "cweid": alert.get("cweid", ""),
            "wascid": alert.get("wascid", ""),
            "evidence": evidence,
            "evidence_source": evidence_source,
            "pluginid": plugin_id,
            "plugin_id": plugin_id,
            "param": alert.get("param", ""),
            "attack": alert.get("attack", ""),
            "other": other,
            "tags": alert.get("tags", {}),
            "message_id": message_id,
            "request_method": _request_method(message_id),
            "scan_profile": scan_profile,
            "authentication_context": authentication_context,
            "target_version": target_environment.get(
                "application_version",
                environment.get("runtime", {}).get(scan_label, {}).get("application_version", ""),
            ),
            "target_image_digest": target_environment.get("pinned_reference", "").split("@", 1)[-1]
            if target_environment.get("pinned_reference") else "",
            "zap_version": environment.get("runtime", {}).get("zap", {}).get(
                "application_version", ZAP_VERSION,
            ),
            "environment_lock_sha256": environment.get("environment_lock_sha256", ""),
        })
    return raw_alerts, alerts


def run_scan(
    target_url: str,
    scan_label: str,
    scan_profile: str = "benchmark",
    *,
    stage_callback=None,
    return_details: bool = False,
    auth_mode: str = "off",
    focused_only: bool = False,
    environment: dict | None = None,
) -> list[dict] | dict:
    if scan_label not in TARGET_PROFILES:
        raise ValueError(f"No DAST target profile configured for {scan_label}")
    if scan_profile not in SCAN_PROFILES:
        raise ValueError(f"Unknown scan profile: {scan_profile}")
    if auth_mode not in {"off", "on"}:
        raise ValueError(f"Unknown authentication mode: {auth_mode}")
    if auth_mode == "on" and scan_label != "juice_shop":
        raise ValueError("Authenticated scanning is only configured for Juice Shop")
    scan_policy = PROFILE_SCAN_POLICIES[scan_profile]
    scan_started_at = datetime.now(timezone.utc)
    focused_policy_snapshots = ensure_focused_scan_policies()
    configure_spider()
    scanner_snapshot = configure_active_scan(scan_profile, scan_label)
    context = create_context(target_url, scan_label)
    auth = configure_juice_shop_authentication(target_url, context) if auth_mode == "on" else None
    user_id = auth["user_id"] if auth else None
    stage_outcomes = {}

    def record_stage(stage: str, outcome: dict) -> dict:
        value = {**outcome, "stage": stage}
        stage_outcomes[stage] = value
        if stage_callback is not None:
            stage_callback(stage, value)
        return value

    print(f"[{scan_label}] Starting traditional spider on {target_url}")
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
    record_stage("traditional_spider", {"status": "running", "scan_id": spider_id})
    spider_outcome = wait_for_progress(
        lambda scan_id: zap_api("spider", "view", "status", scanId=scan_id)["status"],
        spider_id,
        "Traditional spider",
        2,
        timeout_seconds=SPIDER_MAX_DURATION_MINS * 60,
        stop_scan=lambda current_id: _stop_scan("spider", current_id),
    )
    record_stage("traditional_spider", spider_outcome)
    print(f"[{scan_label}] Traditional spider {spider_outcome['status']}.")

    ajax_outcome = {"status": "skipped", "error": "Disabled for target"}
    if TARGET_PROFILES[scan_label]["use_ajax_spider"]:
        configure_ajax_spider()
        print(f"[{scan_label}] Starting AJAX spider on {target_url}")
        ajax_action = "scanAsUser" if user_id is not None else "scan"
        ajax_params = {
            "url": target_url,
            "contextName": context["name"],
            "subtreeOnly": "true",
        }
        if user_id is not None:
            ajax_params["userName"] = auth["user_name"]
        zap_api(
            "ajaxSpider",
            "action",
            ajax_action,
            **ajax_params,
        )
        record_stage("ajax_spider", {"status": "running", "scan_id": ""})
        ajax_outcome = wait_for_ajax_spider(AJAX_SPIDER_MAX_DURATION_MINS * 60)
        record_stage("ajax_spider", ajax_outcome)
        print(f"[{scan_label}] AJAX spider {ajax_outcome['status']}.")
        if auth is not None:
            authentication_verification = verify_authenticated_whoami(target_url, auth["email"])
            record_stage("authentication_verification", authentication_verification)
    elif auth is not None:
        raise RuntimeError("Authenticated Juice Shop scanning requires AJAX Spider")

    client_outcome = {"status": "skipped", "error": "Disabled for target"}
    use_client_spider = TARGET_PROFILES[scan_label]["use_client_spider"]
    if scan_profile == "final":
        use_client_spider = TARGET_PROFILES[scan_label]["final_use_client_spider"]
    if use_client_spider:
        print(f"[{scan_label}] Starting browser-driven client spider on {target_url}")
        record_stage("client_spider", {"status": "running", "scan_id": ""})
        client_outcome = run_client_spider(target_url, context, scan_label)
        record_stage("client_spider", client_outcome)
        print(f"[{scan_label}] Client spider {client_outcome['status']}.")

    crawler_discovered_urls = get_target_urls(target_url)
    seed_summary = {
        "attempted": 0, "seeded": 0, "failed": 0, "failed_urls": [], "error": "",
    }
    if scan_label == "juice_shop":
        seed_summary = seed_juice_shop_requests(target_url)
    elif scan_label == "vulnerable_app":
        seed_summary = seed_vulnerable_app_requests(target_url)
    record_stage("seeding", {
        "status": "completed" if not seed_summary.get("failed") else "completed_with_warnings",
        **seed_summary,
    })
    record_stage("passive_scan", {"status": "running"})
    passive_outcome = wait_for_passive_scan()
    record_stage("passive_scan", passive_outcome)
    discovered_urls = verify_discovery(target_url, scan_label)
    record_stage("discovery_validation", {
        "status": "completed", "discovered_url_count": len(discovered_urls),
    })
    active_scan_exclusions = configure_active_scan_exclusions(scan_label)

    active_outcome = {"status": "skipped", "error": "Focused pilot mode"}
    if not focused_only:
        print(f"[{scan_label}] Starting active scan on {target_url}")
        active_action = "scanAsUser" if user_id is not None else "scan"
        active_params = {
            "url": target_url,
            "recurse": "true",
            "inScopeOnly": "true",
            "scanPolicyName": scan_policy,
            "method": "",
            "postData": "",
            "contextId": context["id"],
        }
        if user_id is not None:
            active_params["userId"] = user_id
        active_response = zap_api("ascan", "action", active_action, **active_params)
        ascan_id = scan_id_from_response(active_response, active_action, scan_label)
        record_stage("broad_active_scan", {"status": "running", "scan_id": ascan_id})
        active_outcome = wait_for_progress(
            lambda scan_id: zap_api("ascan", "view", "status", scanId=scan_id)["status"],
            ascan_id,
            "Active scan",
            5,
            timeout_seconds=(
                None if scan_profile == "final" else ACTIVE_SCAN_MAX_DURATION_MINS * 60
            ),
            stop_scan=lambda current_id: _stop_scan("ascan", current_id),
            get_progress_snapshot=lambda current_id: zap_api(
                "ascan", "view", "scanProgress", scanId=current_id,
            ),
            stall_seconds=ACTIVE_SCAN_STALL_MINS * 60 if scan_profile == "final" else None,
        )
    record_stage("broad_active_scan", active_outcome)
    print(f"[{scan_label}] Active scan {active_outcome['status']}.")

    focused_scans = []
    if active_outcome.get("status") != "stalled":
        print(f"[{scan_label}] Starting high-signal XSS/SQLi focused scans.")
        focused_scans = run_focused_active_scans(
            target_url, scan_label, context, user_id=user_id, scan_profile=scan_profile,
        )
    focused_statuses = {scan.get("status", "failed") for scan in focused_scans}
    focused_status = (
        "skipped" if active_outcome.get("status") == "stalled" else
        "completed" if focused_statuses <= {"completed"} else "completed_with_warnings"
    )
    record_stage("focused_active_scans", {
        "status": focused_status, "scan_count": len(focused_scans),
        "outcomes": focused_scans,
    })
    print(f"[{scan_label}] High-signal focused scans {focused_status}.")

    targeted_scans = []
    if scan_profile == "targeted":
        print(f"[{scan_label}] Starting focused targeted active scans.")
        targeted_scans = run_targeted_active_scans(
            target_url, scan_label, context, user_id, scan_policy,
        )
        targeted_status = (
            "completed" if all(scan.get("status") == "completed" for scan in targeted_scans)
            else "completed_with_warnings"
        )
        record_stage("targeted_active_scans", {
            "status": targeted_status, "outcomes": targeted_scans,
        })

    _raw_alerts, alerts = collect_alerts(
        target_url, scan_label, scan_profile,
        authentication_context="authenticated" if user_id is not None else "unauthenticated",
        environment=environment,
    )
    warning_stages = [
        stage for stage, outcome in stage_outcomes.items()
        if outcome.get("status") not in {"completed", "skipped", "verified"}
    ]
    target_status = (
        "incomplete" if active_outcome.get("status") == "stalled" else
        "completed_with_warnings" if warning_stages else "completed"
    )
    target_metadata = {
        "app": scan_label,
        "target_url": target_url,
        "context": context,
        "authenticated_user_id": user_id,
        "authentication": ({
            "enabled": True,
            "user_id": user_id,
            "user_name": auth["user_name"],
            "method": auth["method"],
            "session_management": auth["session_management"],
            "verification_url": auth["verification_url"],
            "logout_exclusion": auth["logout_exclusion"],
            "expected_session_tokens": auth["expected_session_tokens"],
            "registration": auth["registration"],
        } if auth else {"enabled": False}),
        "scan_profile": scan_profile,
        "effective_scanners": scanner_snapshot,
        "focused_scan_policies": focused_policy_snapshots,
        "focused_scans": focused_scans,
        "targeted_scans": targeted_scans,
        "benchmark_route_seeds": seed_summary,
        "client_spider_completed": client_outcome.get("status") == "completed",
        "stage_outcomes": stage_outcomes,
        "warnings": warning_stages,
        "target_status": target_status,
        "crawler_discovered_url_count": len(crawler_discovered_urls),
        "crawler_discovered_urls": crawler_discovered_urls,
        "active_scan_exclusions": active_scan_exclusions,
        "required_paths": list(TARGET_PROFILES[scan_label]["required_paths"]),
        "started_at_utc": scan_started_at.isoformat(),
        "completed_at_utc": datetime.now(timezone.utc).isoformat(),
        "discovered_url_count": len(discovered_urls),
        "discovered_urls": discovered_urls,
        "alert_count": len(alerts),
    }
    SCAN_METADATA.append(target_metadata)
    print(f"[{scan_label}] Found {len(alerts)} alerts.")
    if return_details:
        return {
            "alerts": alerts,
            "raw_zap_alerts": _raw_alerts,
            "metadata": target_metadata,
            "status": target_metadata["target_status"],
        }
    return alerts

def save_alerts(alerts: list[dict], path: str = "zap_alerts.json"):
    with open(path, "w") as f:
        json.dump(alerts, f, indent=2)
    print(f"Alerts saved to {path}")


def reset_scan_metadata() -> None:
    SCAN_METADATA.clear()


def get_scan_metadata() -> list[dict]:
    return list(SCAN_METADATA)


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
    request_method_populated_count = sum(bool(alert.get("request_method")) for alert in alerts)
    high_signal_plugin_ids = {"40012", "40026", "40018", "40019"}
    high_signal_alerts = [
        alert for alert in alerts
        if str(alert.get("plugin_id", alert.get("pluginid", ""))) in high_signal_plugin_ids
    ]
    report = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "zap_version": ZAP_VERSION,
        "scanner_configuration": {
            "scan_profile": scan_profile,
            "spider_max_duration_mins": SPIDER_MAX_DURATION_MINS,
            "spider_max_depth": SPIDER_MAX_DEPTH,
            "spider_max_children": SPIDER_MAX_CHILDREN,
            "ajax_spider_max_duration_mins": AJAX_SPIDER_MAX_DURATION_MINS,
            "ajax_spider_max_crawl_depth": AJAX_SPIDER_MAX_DEPTH,
            "ajax_spider_number_of_browsers": AJAX_SPIDER_BROWSERS,
            "client_spider_max_duration_mins": CLIENT_SPIDER_MAX_DURATION_MINS,
            "client_spider_max_crawl_depth": CLIENT_SPIDER_MAX_DEPTH,
            "client_spider_max_children": CLIENT_SPIDER_MAX_CHILDREN,
            "client_spider_number_of_browsers": CLIENT_SPIDER_BROWSERS,
            "passive_scan_timeout_seconds": PASSIVE_SCAN_TIMEOUT_SECONDS,
            "active_scan_threads_per_host": ACTIVE_SCAN_THREADS_PER_HOST,
            "active_scan_max_rule_duration_mins": 0 if scan_profile == "final" else ACTIVE_RULE_MAX_DURATION_MINS,
            "active_scan_max_duration_mins": 0 if scan_profile == "final" else ACTIVE_SCAN_MAX_DURATION_MINS,
            "active_scan_stall_watchdog_mins": ACTIVE_SCAN_STALL_MINS if scan_profile == "final" else None,
            "active_scan_max_alerts_per_rule": 0,
            "focused_scan_timeout_mins": 0 if scan_profile == "final" else FOCUSED_SCAN_TIMEOUT_MINS,
            "focused_scan_group_timeout_mins": 0 if scan_profile == "final" else FOCUSED_SCAN_GROUP_TIMEOUT_MINS,
            "scan_policy": PROFILE_SCAN_POLICIES[scan_profile],
            "active_scan_input_vectors": {
                **ACTIVE_SCAN_INPUT_VECTORS,
                "http_headers_all_requests": scan_profile != "final",
            },
            "disabled_scanner_ids_by_target": (
                {"juice_shop": list(FINAL_DISABLED_SCANNER_IDS), "vulnerable_app": [NOISE_SCANNER_ID]}
                if scan_profile == "final" else
                {"juice_shop": [NOISE_SCANNER_ID], "vulnerable_app": [NOISE_SCANNER_ID]}
            ),
            "active_scan_injectable_targets": ACTIVE_SCAN_INJECTABLE_TARGETS,
            "active_scan_structured_handlers": ACTIVE_SCAN_STRUCTURED_HANDLERS,
            "focused_scan_policies": {
                name: list(scanner_ids) for name, scanner_ids in FOCUSED_SCAN_POLICIES.items()
            },
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
            "request_method_populated_count": request_method_populated_count,
            "request_method_missing_count": len(alerts) - request_method_populated_count,
            "confirmed_evidence_candidates": confirmed_candidates,
            "other_high_medium_findings": other_high_medium,
            "repeated_header_findings": repeated_headers,
            "high_signal_plugins": [
                {
                    "plugin_id": plugin_id,
                    "alert_count": sum(
                        str(alert.get("plugin_id", alert.get("pluginid", ""))) == plugin_id
                        for alert in high_signal_alerts
                    ),
                    "attack_and_evidence_count": sum(
                        str(alert.get("plugin_id", alert.get("pluginid", ""))) == plugin_id
                        and bool(str(alert.get("attack", "")).strip())
                        and bool(str(alert.get("evidence", "")).strip())
                        for alert in high_signal_alerts
                    ),
                }
                for plugin_id in sorted(high_signal_plugin_ids)
            ],
            "dom_evidence_source_counts": dict(Counter(
                alert.get("evidence_source", "")
                for alert in high_signal_alerts
                if str(alert.get("plugin_id", alert.get("pluginid", ""))) == "40026"
            )),
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
    destination = Path(path)
    temporary = destination.with_name(f".{destination.name}.tmp")
    with temporary.open("w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    temporary.replace(destination)
    print(f"ZAP scan report saved to {path}")


def build_vulnerable_app_benchmark_payload(alerts: list[dict]) -> dict:
    """Convert enriched raw alerts to VulnerableApp's official DAST schema."""
    findings, seen = [], set()
    for alert in alerts:
        if alert.get("app") != "vulnerable_app":
            continue
        cwe = str(alert.get("cweid", "")).strip()
        wasc = str(alert.get("wascid", "")).strip()
        method = str(alert.get("request_method", "")).strip().upper()
        finding = {"url": alert.get("url", "")}
        if cwe and cwe not in {"0", "-1"}:
            finding["cwe"] = cwe if cwe.upper().startswith("CWE-") else f"CWE-{cwe}"
        if wasc and wasc not in {"0", "-1"}:
            finding["wascId"] = wasc
        if method:
            finding["method"] = method
        key = tuple(sorted(finding.items()))
        if finding["url"] and key not in seen:
            seen.add(key)
            findings.append(finding)
    return {"tool": "LLM-SEC-ZAP", "scanType": "DAST", "findings": findings}


def submit_vulnerable_app_benchmark(payload: dict, endpoint: str = BENCHMARK_ENDPOINT) -> dict:
    response = session.post(endpoint, json=payload, timeout=(3, 30))
    response.raise_for_status()
    return response.json()

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Run the authorized local ZAP DAST scan")
    parser.add_argument("--scan-profile", choices=SCAN_PROFILES, default="benchmark")
    args = parser.parse_args()
    wait_for_zap()
    start_fresh_zap_session()
    reset_scan_metadata()
    all_alerts = []
    all_alerts += run_scan("http://vulnerable-app:9090/VulnerableApp", "vulnerable_app", args.scan_profile)
    all_alerts += run_scan("http://juice-shop:3000", "juice_shop", args.scan_profile)
    save_alerts(all_alerts)
    save_scan_report(all_alerts, "zap_scan_report.json", args.scan_profile)
