
"""
AI-Net Final End-to-End Smoke Test
Run while the Flask application is already running:
    python AI-Net_Final_Test.py

This test logs in, verifies authentication, checks the main SOC API endpoints,
and reports HTTP/JSON health without changing live-capture state.
"""

import json
import sys
from urllib.request import Request, build_opener, HTTPCookieProcessor
from http.cookiejar import CookieJar
from urllib.parse import urlencode

BASE = "http://127.0.0.1:5000"
USERNAME = "admin"
PASSWORD = "admin123"

GET_ENDPOINTS = [
    "/auth/status",
    "/database/status",
    "/database/health",
    "/database/consistency",
    "/system/health",
    "/system/readiness",
    "/soc_dashboard",
    "/soc_command_center",
    "/soc_kpi_dashboard",
    "/soc_executive_report",
    "/soc_report_archive",
    "/soc_report_compliance",
    "/soc_report_compliance/health",
    "/soc_report_governance",
    "/soc_report_governance/certifications",
    "/soc_report_governance/certification_summary",
    "/incident_dashboard",
    "/incident_audit_log",
    "/soc_cases",
    "/recent_detections",
    "/security_alerts",
    "/detection_history",
    "/live_capture/status",
]

jar = CookieJar()
opener = build_opener(HTTPCookieProcessor(jar))

def request(path, method="GET", data=None):
    url = BASE + path
    body = None
    headers = {"Accept": "application/json"}
    if data is not None:
        body = json.dumps(data).encode()
        headers["Content-Type"] = "application/json"
    req = Request(url, data=body, headers=headers, method=method)
    return opener.open(req, timeout=10)

def main():
    results = []

    # Login first.
    try:
        form = urlencode({"username": USERNAME, "password": PASSWORD}).encode()
        req = Request(
            BASE + "/login",
            data=form,
            headers={"Content-Type": "application/x-www-form-urlencoded",
                     "Accept": "text/html"},
            method="POST",
        )
        response = opener.open(req, timeout=10)
        login_ok = response.status in (200, 302, 303)
        results.append(("LOGIN", response.status, "PASS" if login_ok else "FAIL"))
        response.read()
    except Exception as exc:
        print("LOGIN: FAIL —", exc)
        print("\nStart the Flask app first with: python app.py")
        return 1

    for path in GET_ENDPOINTS:
        try:
            response = request(path)
            content_type = (response.headers.get("Content-Type") or "").lower()
            raw = response.read()
            is_json = "application/json" in content_type
            if is_json:
                try:
                    payload = json.loads(raw.decode("utf-8"))
                    state = "PASS" if response.status == 200 else "REVIEW"
                    results.append((path, response.status, state))
                except Exception:
                    results.append((path, response.status, "FAIL-INVALID-JSON"))
            else:
                results.append((path, response.status, "FAIL-NON-JSON"))
        except Exception as exc:
            results.append((path, "ERR", "FAIL"))
            print(f"{path}: {exc}")

    passed = sum(x[2] == "PASS" for x in results)
    total = len(results)
    print("\n" + "=" * 64)
    print("AI-Net FINAL END-TO-END API SMOKE TEST")
    print("=" * 64)
    for endpoint, status, state in results:
        print(f"{state:18} {str(status):>4}  {endpoint}")
    print("-" * 64)
    print(f"PASS: {passed}/{total}")

    failures = [x for x in results if x[2] != "PASS"]
    if failures:
        print("RESULT: REVIEW REQUIRED")
        return 2

    print("RESULT: PASS")
    return 0

if __name__ == "__main__":
    sys.exit(main())
