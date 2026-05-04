#!/usr/bin/env python3
"""
Round 13 RedTeam Attack Suite - Shield WAF Penetration Test
Tests: SQL Injection, XSS, File Upload (WebShell), CC Attack, DDoS, Brute Force

Records: block/bypass, attack type identification accuracy, false positives
"""

import requests
import threading
import time
import json
import sys
import os
import random
import string
import hashlib
import itertools
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict
from urllib.parse import urlencode, quote

# ============================================================
# Configuration
# ============================================================
WAF_URL = "http://127.0.0.1:8081"
BACKEND_URL = "http://127.0.0.1:8082"
ADMIN_URL = "http://127.0.0.1:9090"
SHIELD_LOG = "/opt/shield/logs/shield.log"
RESULTS_FILE = "/tmp/round13_results.json"
LOG_OFFSET_FILE = "/tmp/round13_log_offset.txt"

# Session with retry
session = requests.Session()
session.headers.update({"User-Agent": "RedTeam-Round13/1.0"})

def get_metrics():
    """Fetch current WAF metrics from admin API."""
    try:
        r = requests.get(f"{ADMIN_URL}/stats", timeout=5)
        if r.status_code == 200:
            return r.json()
    except:
        pass
    return {}

def get_log_snapshot(start_byte=0):
    """Get new log content from SHIELD_LOG since start_byte."""
    try:
        with open(SHIELD_LOG, 'r') as f:
            f.seek(start_byte)
            content = f.read()
            new_pos = f.tell()
        return content, new_pos
    except:
        return "", start_byte

def parse_log_lines(log_content):
    """Parse shield log JSON lines, return list of log entries."""
    entries = []
    for line in log_content.strip().split('\n'):
        if line.strip():
            try:
                entries.append(json.loads(line))
            except:
                pass
    return entries

def classify_waf_response(resp):
    """
    Classify WAF response into:
    - 'blocked': 403 Forbidden
    - 'challenged': JS challenge page (200 with verification content)
    - 'ratelimited': 429 Too Many Requests
    - 'passed': Reached backend normally
    - 'error': 5xx or connection error
    """
    if resp is None:
        return 'error'
    status = resp.status_code
    if status == 403:
        return 'blocked'
    if status == 429:
        return 'ratelimited'
    if status == 200:
        text = resp.text[:500]
        if 'Verifying your browser' in text or 'Checking browser environment' in text:
            return 'challenged'
        return 'passed'
    if 500 <= status < 600:
        return 'error'
    return 'other_%d' % status

def send_request(method, path, params=None, data=None, headers=None, files=None, cookies=None, timeout=10):
    """Send request through WAF and return (response, classification)."""
    url = f"{WAF_URL}{path}"
    try:
        if method == "GET":
            resp = session.get(url, params=params, headers=headers, cookies=cookies, timeout=timeout, allow_redirects=False)
        elif method == "POST":
            if files:
                resp = session.post(url, data=data, files=files, headers=headers, cookies=cookies, timeout=timeout, allow_redirects=False)
            elif isinstance(data, dict) and not any(isinstance(v, (bytes,)) for v in data.values()):
                resp = session.post(url, data=data, headers=headers, cookies=cookies, timeout=timeout, allow_redirects=False)
            else:
                resp = session.post(url, data=data, headers=headers, cookies=cookies, timeout=timeout, allow_redirects=False)
        else:
            resp = session.request(method, url, params=params, data=data, headers=headers, cookies=cookies, timeout=timeout, allow_redirects=False)
        return resp, classify_waf_response(resp)
    except Exception as e:
        return None, 'error'

def get_initial_metrics():
    """Get baseline metrics before attack."""
    return get_metrics()

def log_offset_reset():
    """Reset log file offset tracking."""
    try:
        size = os.path.getsize(SHIELD_LOG)
        with open(LOG_OFFSET_FILE, 'w') as f:
            f.write(str(size))
        return size
    except:
        return 0

def log_offset_read():
    """Read new log entries since last checkpoint."""
    try:
        with open(LOG_OFFSET_FILE, 'r') as f:
            offset = int(f.read().strip())
    except:
        offset = 0

    content, new_offset = get_log_snapshot(offset)

    try:
        with open(LOG_OFFSET_FILE, 'w') as f:
            f.write(str(new_offset))
    except:
        pass

    return parse_log_lines(content)

# ============================================================
# Attack Type definitions
# ============================================================

SQLI_PAYLOADS = {
    "union_select": [
        "1' UNION SELECT username, password FROM users--",
        "1' UNION ALL SELECT null, version()--",
        "' UNION SELECT * FROM information_schema.tables--",
        "-1 UNION SELECT 1,2,3--",
        "1 UNION SELECT user, password FROM mysql.user--",
        "1 UNION SELECT name, sql FROM sqlite_master--",
    ],
    "error_based": [
        "1' AND extractvalue(1, concat(0x7e, (SELECT @@version)))--",
        "1' AND updatexml(1, concat(0x7e, (SELECT database())), 1)--",
        "1' AND 1=convert(int, (SELECT @@version))--",
    ],
    "boolean_blind": [
        "1' AND 1=1--",
        "1' AND 1=2--",
        "1' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>64--",
        "1' AND (SELECT COUNT(*) FROM users)>0--",
    ],
    "time_blind": [
        "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
        "1' AND pg_sleep(5)--",
        "1' AND benchmark(10000000, md5('test'))--",
    ],
    "stacked": [
        "1; DROP TABLE users--",
        "1; DELETE FROM users WHERE '1'='1'--",
        "1; UPDATE users SET password='hacked' WHERE username='admin'--",
    ],
    "comment_bypass": [
        "1/**/UNION/**/SELECT/**/username,password/**/FROM/**/users--",
        "1'/*!50000UNION*/ SELECT username, password FROM users--",
    ],
    "encoded": [
        "1%27%20UNION%20SELECT%20*%20FROM%20users--",
        "1'+%55%4E%49%4F%4E+SELECT+*+FROM+users--",
        "1%2527%2520UNION%2520SELECT%2520*%2520FROM%2520users--",
    ],
    "header_cookie": [
        # These will be sent via custom headers
        ("X-Forwarded-For", "1' UNION SELECT * FROM users--"),
        ("User-Agent", "1' OR '1'='1"),
        ("Cookie", "session=1' OR '1'='1"),
        ("Referer", "1' AND extractvalue(1,concat(0x7e,database()))"),
    ],
    "mid_extractvalue_updatexml": [
        "1' AND mid(@@version,1,1)='5'--",
        "1' AND extractvalue(1,concat(0x7e,mid(database(),1,10)))--",
        "1' AND updatexml(1,concat(0x7e,mid(user(),1,10)),1)--",
    ],
    "no_space": [
        "1'/**/AND/**/1=1--",
        "1'/*comment*/OR/*comment*/'1'='1",
        "1'%0AAND%0A1=1--",
    ],
}

XSS_PAYLOADS = {
    "basic_script": [
        "<script>alert('xss')</script>",
        "<script>alert(document.cookie)</script>",
        "<ScRiPt>alert(1)</ScRiPt>",
        "<script >alert(1)</script >",
    ],
    "event_handlers": [
        "<img src=x onerror=alert(1)>",
        "<body onload=alert('xss')>",
        "<svg onload=alert(1)>",
        "<input onfocus=alert(1) autofocus>",
        "<details open ontoggle=alert(1)>",
        "<video><source onerror=alert(1)>",
        "<iframe onload=alert(1)>",
    ],
    "pseudo_protocol": [
        "javascript:alert(1)",
        "java\\u0000script:alert(1)",
        "data:text/html,<script>alert(1)</script>",
        "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
    ],
    "encoded": [
        "%3Cscript%3Ealert(1)%3C%2Fscript%3E",
        "&#60;&#115;&#99;&#114;&#105;&#112;&#116;&#62;alert(1)&#60;/&#115;&#99;&#114;&#105;&#112;&#116;&#62;",
        "\\x3cscript\\x3ealert(1)\\x3c/script\\x3e",
    ],
    "dom_based": [
        "#' onclick=alert(1)//",
        "#' onmouseover=alert(1)//",
        "<img src=\"x\" onerror=\"alert(1)\">",
    ],
    "html5_vectors": [
        "<svg><script>alert&#40;1&#41;</script></svg>",
        "<object data=\"javascript:alert(1)\">",
        "<form><button formaction=\"javascript:alert(1)\">X</button></form>",
    ],
    "template_injection": [
        "{{constructor.constructor('alert(1)')()}}",
        "${alert(1)}",
        "#{alert(1)}",
    ],
    "header_cookie_xss": [
        ("X-Forwarded-For", "<script>alert(1)</script>"),
        ("User-Agent", "<img src=x onerror=alert(1)>"),
        ("Cookie", "session=<script>alert(document.cookie)</script>"),
        ("Referer", "javascript:alert(1)"),
    ],
}

WEBSHELL_PAYLOADS = {
    "php_simple": (
        "shell.php",
        b'<?php eval($_POST["cmd"]); ?>',
        "application/x-php"
    ),
    "php_advanced": (
        "info.php",
        b'<?php system($_GET["c"]); ?>',
        "application/x-php"
    ),
    "php_obfuscated": (
        "about.php",
        b'<?php @eval(base64_decode($_POST["x"])); ?>',
        "application/x-php"
    ),
    "jsp_shell": (
        "cmd.jsp",
        b'<% Runtime.getRuntime().exec(request.getParameter("c")); %>',
        "application/octet-stream"
    ),
    "asp_shell": (
        "shell.asp",
        b'<% Set s=Server.CreateObject("WScript.Shell"); s.Exec("cmd /c " & Request("c")); %>',
        "application/octet-stream"
    ),
    "phtml": (
        "default.phtml",
        b'<?php passthru($_GET["cmd"]); ?>',
        "application/x-httpd-php"
    ),
    "double_ext_bypass": (
        "image.php.jpg",
        b'<?php echo shell_exec($_GET["e"]); ?>',
        "image/jpeg"
    ),
    "image_with_code": (
        "avatar.jpg",
        b'\xff\xd8\xff\xe0<?php system($_GET["x"]); ?>',
        "image/jpeg"
    ),
    "null_byte_bypass": (
        "shell.php%00.jpg",
        b'<?php eval($_REQUEST["c"]); ?>',
        "application/x-php"
    ),
    "phar": (
        "test.phar",
        b'<?php @assert($_POST["x"]); ?>',
        "application/octet-stream"
    ),
}

BRUTE_FORCE_PATHS = [
    "/login",
    "/admin",
    "/wp-login",
    "/api/login",
    "/api/auth",
    "/signin",
    "/auth",
    "/oauth",
    "/api/v1/login",
    "/api/v1/auth",
    "/user/login",
    "/users/login",
    "/account/login",
]

BRUTE_FORCE_CREDENTIALS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "123456"),
    ("admin", "admin123"),
    ("root", "root"),
    ("root", "toor"),
    ("user", "password"),
    ("test", "test"),
    ("administrator", "administrator"),
    ("admin", "passw0rd"),
    ("admin", "letmein"),
    ("admin", "qwerty"),
    ("admin", "monkey"),
    ("admin", "dragon"),
    ("admin", "master"),
]

DIRECTORY_SCAN_PATHS = [
    "/admin",
    "/wp-admin",
    "/administrator",
    "/phpmyadmin",
    "/.git/HEAD",
    "/.env",
    "/config.php",
    "/backup",
    "/sql",
    "/db",
    "/api/v1/users",
    "/api/v1/admin",
    "/swagger",
    "/docs",
    "/debug",
    "/console",
    "/actuator",
    "/metrics",
    "/status",
    "/server-status",
    "/test",
    "/tmp",
    "/old",
    "/backup.zip",
    "/dump.sql",
]

# Normal (benign) requests for false positive testing
BENIGN_REQUESTS = [
    ("GET", "/", None, None),
    ("GET", "/?page=1", None, None),
    ("GET", "/?search=hello", None, None),
    ("GET", "/?id=123", None, None),
    ("GET", "/?name=John", None, None),
    ("GET", "/?category=books&price=10-20", None, None),
    ("POST", "/", {"name": "John Doe", "email": "john@example.com"}, None),
    ("POST", "/", {"comment": "Great product, love it!"}, None),
    ("POST", "/", {"search": "normal search query"}, None),
    ("POST", "/", {"contact": "Support ticket: need help with login"}, None),
]

# ============================================================
# Test functions for each attack type
# ============================================================

class AttackResult:
    def __init__(self):
        self.lock = threading.Lock()
        base = {"tested": 0, "blocked": 0, "passed": 0, "challenged": 0, "ratelimited": 0, "other": 0, "error": 0, "details": []}
        self.results = {
            "sql_injection": dict(base),
            "xss": dict(base),
            "webshell_upload": dict(base),
            "cc_attack": dict(base),
            "ddos": dict(base),
            "brute_force": dict(base),
            "benign": dict(base),
            "log_type_analysis": {"correct": 0, "wrong": 0, "errors": []},
        }

    def record(self, category, payload_key, result, extra=None):
        with self.lock:
            cat = self.results[category]
            cat["tested"] += 1
            if result in cat:
                cat[result] += 1
            else:
                cat["other"] += 1
            detail = {"payload": payload_key, "result": result}
            if extra:
                detail.update(extra)
            cat["details"].append(detail)

    def summary(self):
        s = {}
        for cat, data in self.results.items():
            if cat == "log_type_analysis":
                continue
            d = data
            total = d["tested"]
            blocked = d["blocked"] + d.get("challenged", 0) + d.get("ratelimited", 0)
            passed = d["passed"] + d.get("error", 0) + d.get("other", 0)
            if total > 0:
                rate = blocked / total * 100
            else:
                rate = 0
            s[cat] = {
                "tested": total,
                "blocked": blocked,
                "passed": passed,
                "rate": round(rate, 1),
            }
        return s


def test_sql_injection(ar):
    """Test all SQL injection payloads."""
    print("[*] Testing SQL Injection...")

    # URL parameter injection
    for subcat, payloads in SQLI_PAYLOADS.items():
        if subcat == "header_cookie":
            continue  # Handled separately

        for payload in payloads:
            # GET with query parameter
            resp, classification = send_request("GET", "/", params={"id": payload})
            ar.record("sql_injection", f"{subcat}|GET|{payload[:50]}", classification)

            # POST with body parameter
            resp, classification = send_request("POST", "/", data={"id": payload, "q": "1"})
            ar.record("sql_injection", f"{subcat}|POST|{payload[:50]}", classification)

            time.sleep(0.02)  # Rate limiting avoidance

    # Header/Cookie injection
    for header_name, payload in SQLI_PAYLOADS.get("header_cookie", []):
        headers = {header_name: payload}
        resp, classification = send_request("GET", "/", headers=headers)
        ar.record("sql_injection", f"header|{header_name}|{payload[:50]}", classification)
        time.sleep(0.03)

    # Direct URI injection
    uri_payloads = [
        "/?id=1' OR '1'='1",
        "/?id=1 UNION SELECT 1,2,3--",
        "/?q=admin'--",
    ]
    for payload in uri_payloads:
        resp, classification = send_request("GET", payload)
        ar.record("sql_injection", f"uri|{payload[:60]}", classification)
        time.sleep(0.03)

    print(f"    SQL Injection: {ar.results['sql_injection']['tested']} tests")


def test_xss(ar):
    """Test all XSS payloads."""
    print("[*] Testing XSS...")

    for subcat, payloads in XSS_PAYLOADS.items():
        if subcat == "header_cookie_xss":
            continue

        for payload in payloads:
            # GET URL parameter
            resp, classification = send_request("GET", "/", params={"q": payload})
            ar.record("xss", f"{subcat}|GET|{payload[:50]}", classification)

            # POST body
            resp, classification = send_request("POST", "/", data={"comment": payload})
            ar.record("xss", f"{subcat}|POST|{payload[:50]}", classification)

            time.sleep(0.02)

    # Header/Cookie XSS
    for header_name, payload in XSS_PAYLOADS.get("header_cookie_xss", []):
        headers = {header_name: payload}
        resp, classification = send_request("GET", "/", headers=headers)
        ar.record("xss", f"header|{header_name}|{payload[:50]}", classification)
        time.sleep(0.03)

    # URI-based XSS
    uri_payloads = [
        "/?q=<script>alert(1)</script>",
        "/?search=<img src=x onerror=alert(1)>",
        "/?name=<svg onload=alert(1)>",
    ]
    for payload in uri_payloads:
        resp, classification = send_request("GET", payload)
        ar.record("xss", f"uri|{payload[:60]}", classification)
        time.sleep(0.03)

    print(f"    XSS: {ar.results['xss']['tested']} tests")


def test_webshell_upload(ar):
    """Test WebShell file upload attacks."""
    print("[*] Testing WebShell Upload...")

    for name, (filename, content, mime_type) in WEBSHELL_PAYLOADS.items():
        # Standard upload
        files_data = {"file": (filename, content, mime_type)}
        resp, classification = send_request("POST", "/upload", files=files_data)
        ar.record("webshell_upload", f"{name}|Standard", classification)
        time.sleep(0.05)

        # Alternative field name
        files_data = {"image": (filename, content, mime_type)}
        resp, classification = send_request("POST", "/upload", files=files_data)
        ar.record("webshell_upload", f"{name}|AltField", classification)
        time.sleep(0.05)

        # With additional form data
        files_data = {"file": (filename, content, mime_type)}
        form_data = {"description": "test upload", "type": "profile_photo"}
        resp, classification = send_request("POST", "/upload", files=files_data, data=form_data)
        ar.record("webshell_upload", f"{name}|WithForm", classification)
        time.sleep(0.05)

    # POST to other paths
    for name, (filename, content, mime_type) in list(WEBSHELL_PAYLOADS.items())[:5]:
        files_data = {"file": (filename, content, mime_type)}
        resp, classification = send_request("POST", "/api/upload", files=files_data)
        ar.record("webshell_upload", f"{name}|AltPath", classification)
        time.sleep(0.05)

    print(f"    WebShell Upload: {ar.results['webshell_upload']['tested']} tests")


def test_cc_attack(ar):
    """Test CC attack detection - high frequency requests from single IP."""
    print("[*] Testing CC Attack...")

    # Burst of rapid requests from single IP
    num_requests = 30
    results = []

    def send_cc_request(i):
        resp, classification = send_request("GET", f"/?cc_test={i}&ts={int(time.time())}")
        return classification

    # Rapid fire without delay
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(send_cc_request, i) for i in range(num_requests)]
        for future in as_completed(futures):
            results.append(future.result())

    for r in results:
        ar.record("cc_attack", f"burst|req", r)

    # Second wave after short pause
    time.sleep(2)
    results2 = []
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(send_cc_request, i + 100) for i in range(num_requests)]
        for future in as_completed(futures):
            results2.append(future.result())

    for r in results2:
        ar.record("cc_attack", f"burst2|req", r)

    print(f"    CC Attack: {ar.results['cc_attack']['tested']} requests")


def test_ddos_simulation(ar):
    """Test DDoS detection - application layer HTTP flood."""
    print("[*] Testing DDoS Simulation (HTTP Flood)...")

    # Moderate HTTP flood - resource restricted
    num_requests = 50
    results = []

    def send_ddos_request(i):
        url = f"{WAF_URL}/?ddos_test={i}&random={random.randint(1,100000)}"
        try:
            resp = session.get(url, timeout=5, allow_redirects=False)
            return classify_waf_response_for_ddos(resp)
        except:
            return 'error'

    def classify_waf_response_for_ddos(resp):
        if resp is None:
            return 'error'
        status = resp.status_code
        if status == 403:
            return 'blocked'
        if status == 429:
            return 'ratelimited'
        if status == 200:
            text = resp.text[:500]
            if 'Verifying your browser' in text:
                return 'challenged'
            return 'passed'
        return 'other_%d' % status

    # Concurrent flood
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(send_ddos_request, i) for i in range(num_requests)]
        for future in as_completed(futures):
            results.append(future.result())

    for r in results:
        ar.record("ddos", f"flood|req", r)

    print(f"    DDoS Simulation: {num_requests} requests")


def test_brute_force(ar):
    """Test brute force attack detection."""
    print("[*] Testing Brute Force Attack...")

    # Dictionary attack on login endpoints
    for path in BRUTE_FORCE_PATHS:
        for username, password in BRUTE_FORCE_CREDENTIALS:
            data = {"username": username, "password": password}
            resp, classification = send_request("POST", path, data=data)
            ar.record("brute_force", f"login|{path}|{username}:{password}", classification)
            time.sleep(0.03)  # Small delay to avoid rate limit

    # Directory scanning
    for path in DIRECTORY_SCAN_PATHS:
        resp, classification = send_request("GET", path)
        ar.record("brute_force", f"dirscan|{path}", classification)
        time.sleep(0.02)

    # HEAD requests (common in scanning)
    for path in DIRECTORY_SCAN_PATHS[:10]:
        resp, classification = send_request("HEAD", path)
        ar.record("brute_force", f"headscan|{path}", classification)
        time.sleep(0.02)

    print(f"    Brute Force: {ar.results['brute_force']['tested']} requests")


def test_benign_traffic(ar):
    """Test benign traffic for false positive detection."""
    print("[*] Testing Benign Traffic (False Positive Check)...")

    for method, path, params, data in BENIGN_REQUESTS:
        if method == "GET":
            resp, classification = send_request("GET", path, params=params)
        else:
            resp, classification = send_request("POST", path, data=data)
        ar.record("benign", f"{method}|{path}|benign", classification)
        time.sleep(0.1)

    print(f"    Benign Traffic: {ar.results['benign']['tested']} tests")


def analyze_log_type_identification(ar, log_entries):
    """
    Analyze WAF logs to check attack type identification accuracy.
    Maps log entries to attack types and checks if they match.
    """
    type_mapping = {
        "sql_injection": ["sql_injection", "sqlinject", "sql_inject"],
        "xss": ["xss"],
        "webshell_upload": ["webshell", "upload", "file_upload"],
        "cc_attack": ["cc_attack", "cc"],
        "ddos": ["ddos"],
        "brute_force": ["brute_force", "bruteforce", "brute"],
    }

    attack_logs = []
    for entry in log_entries:
        msg = entry.get("message", "")
        attack_type = entry.get("attack_type", "")
        if "blocked" in msg or attack_type:
            attack_logs.append(entry)

    # For each blocked log, check if attack_type is set and meaningful
    for entry in attack_logs:
        msg = entry.get("message", "")
        attack_type = entry.get("attack_type", "")
        level = entry.get("level", "")

        if not attack_type and "blocked" not in msg:
            continue

        if attack_type:
            ar.results["log_type_analysis"]["correct"] += 1
        elif "blocked" in msg and not attack_type:
            ar.results["log_type_analysis"]["wrong"] += 1
            ar.results["log_type_analysis"]["errors"].append({
                "message": msg,
                "entry": entry
            })

    return len(attack_logs)


# ============================================================
# Main execution
# ============================================================

def main():
    print("=" * 60)
    print("Round 13 RedTeam Attack Suite")
    print(f"Target: {WAF_URL}")
    print(f"Time: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)

    # Get initial metrics
    initial_metrics = get_initial_metrics()
    print(f"\n[*] Initial WAF Metrics: {json.dumps(initial_metrics, indent=2)}")

    # Reset log tracking
    log_offset_reset()

    # Results tracker
    ar = AttackResult()

    # Phase 1: Benign traffic first (before attacks distort WAF state)
    print("\n--- Phase 1: Benign Traffic ---")
    test_benign_traffic(ar)

    # Phase 2: SQL Injection
    print("\n--- Phase 2: SQL Injection ---")
    test_sql_injection(ar)

    # Phase 3: XSS
    print("\n--- Phase 3: XSS ---")
    test_xss(ar)

    # Phase 4: WebShell Upload
    print("\n--- Phase 4: WebShell Upload ---")
    test_webshell_upload(ar)

    # Phase 5: Brute Force
    print("\n--- Phase 5: Brute Force ---")
    test_brute_force(ar)

    # Phase 6: CC Attack
    print("\n--- Phase 6: CC Attack ---")
    test_cc_attack(ar)

    # Phase 7: DDoS Simulation
    print("\n--- Phase 7: DDoS Simulation ---")
    test_ddos_simulation(ar)

    # Wait for logs to flush
    time.sleep(2)

    # Get final metrics
    final_metrics = get_metrics()
    print(f"\n[*] Final WAF Metrics: {json.dumps(final_metrics, indent=2)}")

    # Read logs
    log_entries = log_offset_read()
    attack_log_count = analyze_log_type_identification(ar, log_entries)
    print(f"\n[*] Log entries analyzed: {len(log_entries)}, attack-related: {attack_log_count}")

    # Compile summary
    summary = ar.summary()

    print("\n" + "=" * 60)
    print("ATTACK RESULTS SUMMARY")
    print("=" * 60)

    overall_tested = 0
    overall_blocked = 0
    overall_passed = 0

    for cat in ["sql_injection", "xss", "webshell_upload", "cc_attack", "ddos", "brute_force", "benign"]:
        s = summary[cat]
        overall_tested += s["tested"]
        overall_blocked += s["blocked"]
        overall_passed += s["passed"]

        status = "✓" if s["rate"] >= 95 else ("⚠" if s["rate"] >= 80 else "✗")
        print(f"  {status} {cat:25s}: tested={s['tested']:4d} blocked={s['blocked']:4d} passed={s['passed']:4d} rate={s['rate']:5.1f}%")

    overall_rate = (overall_blocked / overall_tested * 100) if overall_tested > 0 else 0
    print(f"\n  {'='*55}")
    print(f"  OVERALL: tested={overall_tested} blocked={overall_blocked} passed={overall_passed} rate={overall_rate:.1f}%")

    # False positive check
    benign = summary["benign"]
    if benign["passed"] == benign["tested"]:
        fp_rate = 0
        print(f"\n  ✓ False Positive Rate: 0% (all {benign['tested']} benign requests passed)")
    else:
        fp_rate = (benign["blocked"] / benign["tested"] * 100) if benign["tested"] > 0 else 0
        print(f"\n  ⚠ False Positive Rate: {fp_rate:.1f}% ({benign['blocked']}/{benign['tested']} benign requests blocked)")

    # Type identification accuracy
    ta = ar.results["log_type_analysis"]
    total_typed = ta["correct"] + ta["wrong"]
    if total_typed > 0:
        type_acc = ta["correct"] / total_typed * 100
        print(f"\n  Attack Type Identification:")
        print(f"    Correct: {ta['correct']}, Wrong: {ta['wrong']}")
        print(f"    Accuracy: {type_acc:.1f}%")
        if ta["errors"]:
            print(f"    Type identification errors:")
            for err in ta["errors"][:10]:
                print(f"      - {err['message']}")
    else:
        print(f"\n  Attack Type Identification: No typed log entries found (info level may be too low)")

    # Save detailed results
    full_results = {
        "round": 13,
        "timestamp": time.strftime('%Y-%m-%dT%H:%M:%SZ'),
        "target": WAF_URL,
        "initial_metrics": initial_metrics,
        "final_metrics": final_metrics,
        "summary": summary,
        "overall": {
            "tested": overall_tested,
            "blocked": overall_blocked,
            "passed": overall_passed,
            "rate": round(overall_rate, 1),
        },
        "false_positive_rate": round(fp_rate, 1),
        "type_identification": {
            "correct": ta["correct"],
            "wrong": ta["wrong"],
            "accuracy": round(type_acc, 1) if total_typed > 0 else 0,
            "error_samples": ta["errors"][:20],
        },
        "detailed_results": ar.results,
        "log_sample": log_entries[-30:] if log_entries else [],
    }

    with open(RESULTS_FILE, 'w') as f:
        json.dump(full_results, f, indent=2, default=str)

    print(f"\n[*] Detailed results saved to: {RESULTS_FILE}")
    return full_results

if __name__ == "__main__":
    results = main()
