#!/usr/bin/env python3
"""
Round 13 Phase 2 - Slow-rate targeted test to isolate content scanners.
Sends requests slowly (500ms delay) to avoid DDoS/rate-limiting interference.
"""
import requests
import time
import json
import os

WAF_URL = "http://127.0.0.1:8081"
ADMIN_URL = "http://127.0.0.1:9090"
SHIELD_LOG = "/opt/shield/logs/shield.log"
SLOW_RESULTS = "/tmp/round13_slow_results.json"

session = requests.Session()
session.headers.update({"User-Agent": "RedTeam-Round13-Slow/1.0"})

def classify_response(resp):
    if resp is None: return 'error'
    s = resp.status_code
    if s == 403: return 'blocked'
    if s == 429: return 'ratelimited'
    if s == 200:
        if 'Verifying your browser' in resp.text[:500]:
            return 'challenged'
        return 'passed'
    return f'other_{s}'

def send(path, params=None, data=None, headers=None, files=None):
    try:
        if files:
            resp = session.post(f"{WAF_URL}{path}", files=files, data=data, headers=headers, timeout=10, allow_redirects=False)
        elif data:
            resp = session.post(f"{WAF_URL}{path}", data=data, headers=headers, timeout=10, allow_redirects=False)
        else:
            resp = session.get(f"{WAF_URL}{path}", params=params, headers=headers, timeout=10, allow_redirects=False)
        return resp, classify_response(resp)
    except:
        return None, 'error'

# Get log baseline
log_start = os.path.getsize(SHIELD_LOG)
m_start = requests.get(f"{ADMIN_URL}/stats").json()

results = {}
total = 0

def test_batch(label, tests, delay=0.5):
    global total
    blocked, passed, challenged = 0, 0, 0
    for t in tests:
        resp, cls = send(*t) if isinstance(t, tuple) else (None, 'error')
        if cls in ('blocked', 'challenged', 'ratelimited'):
            blocked += 1
        else:
            passed += 1
        total += 1
        time.sleep(delay)
    results[label] = {"tested": len(tests), "blocked": blocked, "passed": passed, "rate": round(blocked/len(tests)*100, 1) if tests else 0}
    print(f"  {label}: {blocked}/{len(tests)} blocked ({results[label]['rate']}%)")

# === SQL Injection (slow) ===
print("=== SQL Injection (slow rate) ===")
sqli = [
    ("/?id=1' UNION SELECT username, password FROM users--", None, None, None),
    ("/?id=1' AND extractvalue(1, concat(0x7e, (SELECT @@version)))--", None, None, None),
    ("/?id=1' AND updatexml(1, concat(0x7e, (SELECT database())), 1)--", None, None, None),
    ("/?id=1' AND 1=1--", None, None, None),
    ("/?id=1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--", None, None, None),
    ("/?id=1; DROP TABLE users--", None, None, None),
    ("/?id=1/**/UNION/**/SELECT/**/username,password/**/FROM/**/users--", None, None, None),
    ("/?id=1%27%20UNION%20SELECT%20*%20FROM%20users--", None, None, None),
    ("/?id=1' AND mid(@@version,1,1)='5'--", None, None, None),
    ("/?id=1' AND extractvalue(1,concat(0x7e,mid(database(),1,10)))--", None, None, None),
    ("/", None, {"id": "1' UNION SELECT * FROM users--"}, None),
    ("/", None, {"id": "1' AND 1=convert(int,@@version)--"}, None),
    # Header injection
    ("/", None, None, {"X-Forwarded-For": "1' UNION SELECT * FROM users--"}),
    ("/", None, None, {"User-Agent": "1' OR '1'='1"}),
    ("/", None, None, {"Cookie": "session=1' OR '1'='1"}),
]
test_batch("sql_injection_slow", sqli)

# === XSS (slow) ===
print("\n=== XSS (slow rate) ===")
xss_tests = [
    ("/?q=<script>alert('xss')</script>", None, None, None),
    ("/?q=<img src=x onerror=alert(1)>", None, None, None),
    ("/?q=<svg onload=alert(1)>", None, None, None),
    ("/?q=<body onload=alert('xss')>", None, None, None),
    ("/?q=javascript:alert(1)", None, None, None),
    ("/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E", None, None, None),
    ("/?q={{constructor.constructor('alert(1)')()}}", None, None, None),
    ("/", None, {"comment": "<script>alert(document.cookie)</script>"}, None),
    ("/", None, {"name": "<iframe onload=alert(1)>"}, None),
    ("/", None, None, {"X-Forwarded-For": "<script>alert(1)</script>"}),
    ("/", None, None, {"User-Agent": "<img src=x onerror=alert(1)>"}),
    ("/", None, None, {"Cookie": "session=<script>alert(1)</script>"}),
]
test_batch("xss_slow", xss_tests)

# === WebShell Upload (slow) ===
print("\n=== WebShell Upload (slow rate) ===")
ws_tests = [
    ("/upload", None, None, {"file": ("shell.php", b'<?php eval($_POST["cmd"]); ?>', "application/x-php")}),
    ("/upload", None, None, {"file": ("info.php", b'<?php system($_GET["c"]); ?>', "application/x-php")}),
    ("/upload", None, None, {"file": ("cmd.jsp", b'<% Runtime.getRuntime().exec(request.getParameter("c")); %>', "application/octet-stream")}),
    ("/upload", None, None, {"file": ("shell.asp", b'<% Set s=Server.CreateObject("WScript.Shell"); s.Exec("cmd /c " & Request("c")); %>', "application/octet-stream")}),
    ("/upload", None, None, {"file": ("image.php.jpg", b'<?php echo shell_exec($_GET["e"]); ?>', "image/jpeg")}),
    ("/upload", None, None, {"file": ("avatar.jpg", b'<?php system($_GET["x"]); ?>', "image/jpeg")}),
    ("/upload", None, None, {"file": ("default.phtml", b'<?php passthru($_GET["cmd"]); ?>', "application/x-httpd-php")}),
    ("/upload", None, None, {"file": ("test.phar", b'<?php @assert($_POST["x"]); ?>', "application/octet-stream")}),
]
test_batch("webshell_slow", ws_tests, delay=0.6)

# === Brute Force (slow) ===
print("\n=== Brute Force (slow rate) ===")
bf_paths = ["/login", "/admin", "/wp-login", "/api/login", "/api/auth", "/signin", "/auth", "/api/v1/login", "/user/login"]
bf_tests = []
for path in bf_paths:
    for i in range(5):  # 5 attempts per path
        bf_tests.append((path, None, {"username": f"admin", "password": f"pass{i}"}, None))
# Directory scan
for path in ["/admin", "/.git/HEAD", "/.env", "/config.php", "/phpmyadmin", "/backup.zip", "/dump.sql"]:
    bf_tests.append((path, None, None, None))
test_batch("bruteforce_slow", bf_tests, delay=0.4)

time.sleep(2)

# Analyze logs
m_end = requests.get(f"{ADMIN_URL}/stats").json()
log_content = ""
with open(SHIELD_LOG, 'r') as f:
    f.seek(log_start)
    log_content = f.read()

log_entries = []
for line in log_content.strip().split('\n'):
    if line.strip():
        try: log_entries.append(json.loads(line))
        except: pass

# Count attack types in log
from collections import Counter
type_counts = Counter()
for e in log_entries:
    at = e.get("attack_type", "")
    msg = e.get("message", "")
    if at:
        type_counts[at] += 1

print("\n=== Log Attack Types ===")
for at, cnt in type_counts.most_common():
    print(f"  {at}: {cnt}")

# Specific detection counts
detect_msgs = Counter()
for e in log_entries:
    msg = e.get("message", "")
    if any(kw in msg for kw in ["detected", "block"]):
        detect_msgs[msg] += 1

print("\n=== Detection Messages ===")
for msg, cnt in detect_msgs.most_common():
    print(f"  {msg}: {cnt}")

# Type identification accuracy
# For slow testing, every blocked request should have the correct attack_type
content_to_expected_type = {
    "sqlinject": "sql_injection",
    "xss": "xss",
    "webshell": "webshell_upload",
    "brute_force": "brute_force",
    "bruteforce": "brute_force",
}

correct_type, wrong_type, no_type = 0, 0, 0
for e in log_entries:
    at = e.get("attack_type", "")
    msg = e.get("message", "")
    if "blocked" not in msg:
        continue
    # Determine expected type from message
    expected = None
    for kw, exp in content_to_expected_type.items():
        if kw in msg:
            expected = exp
            break
    if not expected:
        expected = "unknown"

    if not at:
        no_type += 1
    elif at == expected:
        correct_type += 1
    else:
        wrong_type += 1
        print(f"  MISMATCH: msg={msg} got attack_type={at} expected={expected}")

print(f"\n=== Type Identification ===")
print(f"  Correct: {correct_type}, Wrong: {wrong_type}, No Type: {no_type}")
total_typed = correct_type + wrong_type
if total_typed > 0:
    print(f"  Accuracy: {round(correct_type/total_typed*100, 1)}%")

# Save results
with open(SLOW_RESULTS, 'w') as f:
    json.dump({
        "results": results,
        "metrics_start": m_start,
        "metrics_end": m_end,
        "type_analysis": {
            "correct": correct_type,
            "wrong": wrong_type,
            "no_type": no_type,
            "accuracy": round(correct_type/total_typed*100, 1) if total_typed > 0 else 0
        },
        "detection_messages": dict(detect_msgs),
        "attack_types": dict(type_counts),
    }, f, indent=2)

print(f"\nResults saved to {SLOW_RESULTS}")
