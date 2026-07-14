import time
import json
import requests

ZAP_BASE_URL = 'http://localhost:8090'
ZAP_API_BASE = f'{ZAP_BASE_URL}/JSON'
API_TIMEOUT = (3, 5)
MAX_STATUS_TIMEOUTS = 120

session = requests.Session()
session.trust_env = False

def zap_api(component: str, kind: str, name: str, **params):
    url = f'{ZAP_API_BASE}/{component}/{kind}/{name}/'
    response = session.get(url, params=params, timeout=API_TIMEOUT)
    response.raise_for_status()
    return response.json()

def configure_active_scan() -> None:
    zap_api("ascan", "action", "setOptionThreadPerHost", Integer=1)
    zap_api("ascan", "action", "setOptionMaxRuleDurationInMins", Integer=2)
    zap_api("ascan", "action", "setOptionMaxScanDurationInMins", Integer=15)
    zap_api("ascan", "action", "setOptionMaxAlertsPerRule", Integer=5)

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

def wait_for_zap(timeout=60):
    start = time.time()
    last_error = None
    while time.time() - start < timeout:
        try:
            response = session.get(f'{ZAP_BASE_URL}/JSON/core/view/version/', timeout=3)
            response.raise_for_status()
            print("ZAP is running, version:", response.json().get('version'))
            return True
        except Exception as exc:
            last_error = exc
            time.sleep(3)
    raise TimeoutError(f"ZAP did not start within the specified timeout. Last error: {last_error}")
    
def run_scan(target_url: str, scan_label: str) -> list[dict]:
    print(f"[{scan_label}] Starting spider on {target_url}")
    spider_id = zap_api("spider", "action", "scan", url=target_url)["scan"]
    wait_for_progress(
        lambda scan_id: zap_api("spider", "view", "status", scanId=scan_id)["status"],
        spider_id,
        "Spider",
        2
    )
    print(f"[{scan_label}] Spider complete.")

    print(f"[{scan_label}] Starting active scan on {target_url}")
    configure_active_scan()
    ascan_id = zap_api("ascan", "action", "scan", url=target_url)["scan"]
    wait_for_progress(
        lambda scan_id: zap_api("ascan", "view", "status", scanId=scan_id)["status"],
        ascan_id,
        "Active scan",
        5
    )
    print(f"\n[{scan_label}] Active scan complete.")

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
            "evidence": a.get("evidence", "")
        })
    print(f"[{scan_label}] Found {len(alerts)} alerts.")
    return alerts

def save_alerts(alerts: list[dict], path: str = "zap_alerts.json"):
    with open(path, "w") as f:
        json.dump(alerts, f, indent=2)
    print(f"Alerts saved to {path}")

if __name__ == "__main__":
    wait_for_zap()
    all_alerts = []
    all_alerts += run_scan("http://juice-shop:3000", "juice_shop")
    all_alerts += run_scan("http://dvwa", "dvwa")
    all_alerts += run_scan("http://webgoat:8080/WebGoat", "webgoat")
    save_alerts(all_alerts)
