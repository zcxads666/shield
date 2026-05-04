#!/usr/bin/env python3
"""
Round 13 Batch-Separated Attack Suite
Each attack type runs as a completely separate batch with 60s cooldown intervals.
Uses browser-like headers to avoid CC challenge interference.
Measures per-batch WAF metric deltas for accurate type identification analysis.
"""
import requests
import threading
import time
import json
import os
import random
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict

WAF_URL = "http://127.0.0.1:8081"
ADMIN_URL = "http://127.0.0.1:9090"
SHIELD_LOG = "/opt/shield/logs/shield.log"
RESULTS_FILE = "/tmp/round13_batch_results.json"

# Browser-like session
def make_session():
    s = requests.Session()
    s.headers.update({
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
    })
    return s

def get_metrics():
    try:
        r = requests.get(f"{ADMIN_URL}/stats", timeout=5)
        if r.status_code == 200:
            return r.json()
    except:
        pass
    return {}

def classify_response(resp):
    if resp is None: return 'error'
    s = resp.status_code
    if s == 403: return 'blocked'
    if s == 429: return 'ratelimited'
    if s == 200:
        if 'Verifying your browser' in resp.text[:500] or 'Security Check' in resp.text[:500]:
            return 'challenged'
        return 'passed'
    if 500 <= s < 600: return 'error'
    return f'other_{s}'

def send(session, method, path, params=None, data=None, headers=None, files=None, timeout=10):
    url = f"{WAF_URL}{path}"
    try:
        if files:
            resp = session.post(url, files=files, data=data, headers=headers, timeout=timeout, allow_redirects=False)
        elif data:
            resp = session.post(url, data=data, headers=headers, timeout=timeout, allow_redirects=False)
        else:
            resp = session.request(method, url, params=params, headers=headers, timeout=timeout, allow_redirects=False)
        return resp, classify_response(resp)
    except Exception as e:
        return None, 'error'

def get_log_since(offset_file):
    """Get new log content since last checkpoint."""
    try:
        with open(offset_file, 'r') as f:
            start = int(f.read().strip())
    except:
        start = 0
    try:
        size = os.path.getsize(SHIELD_LOG)
        with open(SHIELD_LOG, 'r') as f:
            f.seek(start)
            content = f.read()
        with open(offset_file, 'w') as f:
            f.write(str(size))
        return content
    except:
        return ""

def parse_logs(content):
    entries = []
    for line in content.strip().split('\n'):
        if line.strip():
            try: entries.append(json.loads(line))
            except: pass
    return entries

def cooldown(seconds, reason=""):
    """Wait for WAF state to clear between batches."""
    print(f"  ⏳ Cooling down {seconds}s {reason}...")
    for i in range(seconds):
        time.sleep(1)
        if i % 15 == 14:
            print(f"    ... {i+1}s elapsed")

def run_batch(name, attack_type, requests_list, delay=0.1, concurrent=False, max_workers=5):
    """
    Run a batch of attacks, return results.
    Each request in the list is a tuple: (method, path, params_or_data, headers, files)
    If concurrent=True, sends requests in parallel threads (for CC/DDoS).
    """
    print(f"\n{'='*60}")
    print(f"  BATCH: {name}")
    print(f"  Type: {attack_type}, Count: {len(requests_list)}, Concurrent: {concurrent}")
    print(f"{'='*60}")

    # Get baseline metrics
    m_before = get_metrics()

    # Log offset
    log_offset_file = f"/tmp/batch_log_offset_{name.replace(' ', '_')}.txt"
    try: os.remove(log_offset_file)
    except: pass

    results_lock = threading.Lock()
    results = {"blocked": 0, "passed": 0, "challenged": 0, "ratelimited": 0, "error": 0, "other": 0}
    details = []

    if concurrent:
        # Concurrent execution for CC/DDoS
        def send_one(req):
            session = make_session()
            method, path = req[0], req[1]
            params_or_data = req[2] if len(req) > 2 else None
            headers = req[3] if len(req) > 3 else None
            files = req[4] if len(req) > 4 else None
            resp, cls = send(session, method, path,
                           params=params_or_data,
                           data=params_or_data if method == "POST" and not files else None,
                           headers=headers, files=files, timeout=10)
            with results_lock:
                results[cls] = results.get(cls, 0) + 1
            return cls

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(send_one, req) for req in requests_list]
            for f in as_completed(futures):
                try:
                    f.result()
                except:
                    with results_lock:
                        results["error"] += 1

        print(f"  [{name}] Done: blocked={results['blocked']} passed={results['passed']} challenged={results['challenged']} ratelimited={results.get('ratelimited', 0)}")
    else:
        # Sequential execution for content-based attacks
        session = make_session()
        for i, req in enumerate(requests_list):
            method = req[0]
            path = req[1]
            params_or_data = req[2] if len(req) > 2 else None
            headers = req[3] if len(req) > 3 else None
            files = req[4] if len(req) > 4 else None

            resp, cls = send(session, method, path,
                           params=params_or_data,
                           data=params_or_data if method == "POST" and not files else None,
                           headers=headers, files=files, timeout=10)
            results[cls] = results.get(cls, 0) + 1
            details.append({"req": i, "path": path, "result": cls, "status": resp.status_code if resp else None})

            if (i + 1) % 20 == 0:
                print(f"  [{name}] {i+1}/{len(requests_list)}: blocked={results['blocked']} passed={results['passed']} challenged={results['challenged']}")

            time.sleep(delay)

        print(f"  [{name}] Done: blocked={results['blocked']} passed={results['passed']} challenged={results['challenged']} ratelimited={results.get('ratelimited', 0)}")

    # Get after metrics
    time.sleep(1)  # Let metrics flush
    m_after = get_metrics()

    # Analyze logs
    log_content = get_log_since(log_offset_file)
    log_entries = parse_logs(log_content)

    # Count attack types in log
    log_types = defaultdict(int)
    log_messages = defaultdict(int)
    for e in log_entries:
        at = e.get("attack_type", "")
        msg = e.get("message", "")
        if at:
            log_types[at] += 1
        if "block" in msg or "detect" in msg:
            log_messages[msg] += 1

    # Metric deltas
    metric_keys = ["total_requests", "blocked_requests", "allowed_requests",
                   "sql_injections", "xss_attempts", "webshell_uploads",
                   "cc_blocks", "ddos_blocks", "brute_force_blocks"]
    deltas = {}
    for k in metric_keys:
        before = m_before.get(k, 0)
        after = m_after.get(k, 0)
        deltas[k] = after - before

    print(f"  [{name}] Done: blocked={results['blocked']} passed={results['passed']} challenged={results['challenged']} ratelimited={results.get('ratelimited', 0)}")
    print(f"  [{name}] Metrics delta: {json.dumps({k:v for k,v in deltas.items() if v != 0})}")
    print(f"  [{name}] Log attack_types: {dict(log_types)}")
    print(f"  [{name}] Log messages: {dict(log_messages)}")

    return {
        "name": name,
        "attack_type": attack_type,
        "count": len(requests_list),
        "http_results": results,
        "metric_deltas": deltas,
        "log_attack_types": dict(log_types),
        "log_messages": dict(log_messages),
        "log_entries_count": len(log_entries),
        "details": details,
    }

# ============================================================
# Payload Definitions
# ============================================================

def sql_injection_requests():
    """SQL injection payloads - focused on what Round 12 fixed."""
    payloads = [
        # Union select
        ("GET", "/", {"id": "1' UNION SELECT username, password FROM users--"}, None, None),
        ("GET", "/", {"id": "1' UNION ALL SELECT null, version()--"}, None, None),
        ("GET", "/", {"id": "-1 UNION SELECT 1,2,3--"}, None, None),
        ("GET", "/", {"id": "1 UNION SELECT user, password FROM mysql.user--"}, None, None),
        # Error-based (extractvalue/updatexml/mid - Round 12 focus)
        ("GET", "/", {"id": "1' AND extractvalue(1, concat(0x7e, (SELECT @@version)))--"}, None, None),
        ("GET", "/", {"id": "1' AND updatexml(1, concat(0x7e, (SELECT database())), 1)--"}, None, None),
        ("GET", "/", {"id": "1' AND mid(@@version,1,1)='5'--"}, None, None),
        ("GET", "/", {"id": "1' AND extractvalue(1,concat(0x7e,mid(database(),1,10)))--"}, None, None),
        ("GET", "/", {"id": "1' AND updatexml(1,concat(0x7e,mid(user(),1,10)),1)--"}, None, None),
        # Boolean blind
        ("GET", "/", {"id": "1' AND 1=1--"}, None, None),
        ("GET", "/", {"id": "1' AND 1=2--"}, None, None),
        ("GET", "/", {"id": "1' AND (SELECT COUNT(*) FROM users)>0--"}, None, None),
        # Time blind
        ("GET", "/", {"id": "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--"}, None, None),
        ("GET", "/", {"id": "1' AND pg_sleep(5)--"}, None, None),
        ("GET", "/", {"id": "1' AND benchmark(10000000, md5('test'))--"}, None, None),
        # Stacked queries
        ("GET", "/", {"id": "1; DROP TABLE users--"}, None, None),
        ("GET", "/", {"id": "1; DELETE FROM users WHERE '1'='1'--"}, None, None),
        # Comment bypass
        ("GET", "/", {"id": "1/**/UNION/**/SELECT/**/username,password/**/FROM/**/users--"}, None, None),
        ("GET", "/", {"id": "1'/*!50000UNION*/ SELECT username, password FROM users--"}, None, None),
        # Encoded
        ("GET", "/", {"id": "1%27%20UNION%20SELECT%20*%20FROM%20users--"}, None, None),
        ("GET", "/", {"id": "1'+%55%4E%49%4F%4E+SELECT+*+FROM+users--"}, None, None),
        # No-space bypass
        ("GET", "/", {"id": "1'/**/AND/**/1=1--"}, None, None),
        # POST body
        ("POST", "/", {"id": "1' UNION SELECT * FROM users--", "q": "test"}, None, None),
        ("POST", "/", {"id": "1' OR '1'='1", "pass": "x"}, None, None),
        ("POST", "/", {"id": "1' AND extractvalue(1,concat(0x7e,database()))--"}, None, None),
        # Header/Cookie injection (Round 12 focus)
        ("GET", "/", None, {"X-Forwarded-For": "1' UNION SELECT * FROM users--"}, None),
        ("GET", "/", None, {"User-Agent": "1' OR '1'='1"}, None),
        ("GET", "/", None, {"Cookie": "session=1' OR '1'='1"}, None),
        ("GET", "/", None, {"Referer": "1' AND extractvalue(1,concat(0x7e,database()))"}, None),
        # OR tautology
        ("GET", "/", {"id": "1' OR 'x'='x"}, None, None),
        ("GET", "/", {"id": "-1' OR 1=1--"}, None, None),
        # INFORMATION_SCHEMA
        ("GET", "/", {"id": "' UNION SELECT * FROM information_schema.tables--"}, None, None),
        # xp_cmdshell
        ("GET", "/", {"id": "1'; EXEC master..xp_cmdshell 'whoami'--"}, None, None),
        # ORDER BY
        ("GET", "/", {"id": "1 ORDER BY 10--"}, None, None),
    ]
    return payloads

def xss_requests():
    """XSS payloads - focused on Header/Cookie XSS (Round 12 fix)."""
    payloads = [
        # Basic script
        ("GET", "/", {"q": "<script>alert('xss')</script>"}, None, None),
        ("GET", "/", {"search": "<script>alert(document.cookie)</script>"}, None, None),
        ("GET", "/", {"q": "<ScRiPt>alert(1)</ScRiPt>"}, None, None),
        # Event handlers
        ("GET", "/", {"q": "<img src=x onerror=alert(1)>"}, None, None),
        ("GET", "/", {"q": "<body onload=alert('xss')>"}, None, None),
        ("GET", "/", {"q": "<svg onload=alert(1)>"}, None, None),
        ("GET", "/", {"q": "<input onfocus=alert(1) autofocus>"}, None, None),
        ("GET", "/", {"q": "<details open ontoggle=alert(1)>"}, None, None),
        ("GET", "/", {"q": "<iframe onload=alert(1)>"}, None, None),
        # Pseudo protocol
        ("GET", "/", {"q": "javascript:alert(1)"}, None, None),
        ("GET", "/", {"q": "data:text/html,<script>alert(1)</script>"}, None, None),
        # Encoded
        ("GET", "/", {"q": "%3Cscript%3Ealert(1)%3C%2Fscript%3E"}, None, None),
        ("GET", "/", {"q": "&#60;&#115;&#99;&#114;&#105;&#112;&#116;&#62;alert(1)"}, None, None),
        # DOM-based
        ("GET", "/", {"q": "#' onclick=alert(1)//"}, None, None),
        ("GET", "/", {"q": "<img src=\"x\" onerror=\"alert(1)\">"}, None, None),
        # HTML5 vectors
        ("GET", "/", {"q": "<svg><script>alert&#40;1&#41;</script></svg>"}, None, None),
        ("GET", "/", {"q": "<form><button formaction=\"javascript:alert(1)\">X</button></form>"}, None, None),
        # Template injection
        ("GET", "/", {"q": "{{constructor.constructor('alert(1)')()}}"}, None, None),
        ("GET", "/", {"q": "${alert(1)}"}, None, None),
        # POST body
        ("POST", "/", {"comment": "<script>alert(document.cookie)</script>"}, None, None),
        ("POST", "/", {"name": "<iframe onload=alert(1)>"}, None, None),
        ("POST", "/", {"data": "<img src=x onerror=alert(1)>"}, None, None),
        # Header/Cookie XSS (Round 12 focus)
        ("GET", "/", None, {"X-Forwarded-For": "<script>alert(1)</script>"}, None),
        ("GET", "/", None, {"User-Agent": "<img src=x onerror=alert(1)>"}, None),
        ("GET", "/", None, {"Cookie": "session=<script>alert(document.cookie)</script>"}, None),
        ("GET", "/", None, {"Referer": "javascript:alert(1)"}, None),
        # Filter bypass
        ("GET", "/", {"q": "<scr<script>ipt>alert(1)</scr<script>ipt>"}, None, None),
        ("GET", "/", {"q": "<<script>alert(1);//<</script>"}, None, None),
        # Unicode/special chars
        ("GET", "/", {"q": "<ſcript>alert(1)</ſcript>"}, None, None),
    ]
    return payloads

def webshell_requests():
    """WebShell upload payloads."""
    payloads = [
        # PHP webshells
        ("POST", "/upload", {"desc": "test"}, None, {"file": ("shell.php", b'<?php eval($_POST["cmd"]); ?>', "application/x-php")}),
        ("POST", "/upload", None, None, {"file": ("info.php", b'<?php system($_GET["c"]); ?>', "application/x-php")}),
        ("POST", "/upload", None, None, {"file": ("about.php", b'<?php @eval(base64_decode($_POST["x"])); ?>', "application/x-php")}),
        ("POST", "/upload", None, None, {"file": ("default.phtml", b'<?php passthru($_GET["cmd"]); ?>', "application/x-httpd-php")}),
        ("POST", "/upload", None, None, {"file": ("test.phar", b'<?php @assert($_POST["x"]); ?>', "application/octet-stream")}),
        # JSP/ASP
        ("POST", "/upload", None, None, {"file": ("cmd.jsp", b'<% Runtime.getRuntime().exec(request.getParameter("c")); %>', "application/octet-stream")}),
        ("POST", "/upload", None, None, {"file": ("shell.asp", b'<% Set s=Server.CreateObject("WScript.Shell"); s.Exec("cmd /c " & Request("c")); %>', "application/octet-stream")}),
        # Bypass techniques
        ("POST", "/upload", None, None, {"file": ("image.php.jpg", b'<?php echo shell_exec($_GET["e"]); ?>', "image/jpeg")}),
        ("POST", "/upload", None, None, {"file": ("photo.jpg.php", b'<?php system($_GET["x"]); ?>', "image/jpeg")}),
        ("POST", "/upload", None, None, {"file": ("avatar.jpg", b'\xff\xd8\xff\xe0<?php system($_GET["x"]); ?>', "image/jpeg")}),
        # Different upload paths
        ("POST", "/api/upload", None, None, {"file": ("test.php", b'<?php eval($_POST["x"]); ?>', "application/x-php")}),
        ("POST", "/admin/upload", None, None, {"file": ("shell.php", b'<?php passthru($_GET["cmd"]); ?>', "application/x-php")}),
        # Obfuscated
        ("POST", "/upload", None, None, {"file": ("config.php", b'<?php @eval(gzinflate(base64_decode("S0NVUQA="))); ?>', "application/x-php")}),
        # Double extension
        ("POST", "/upload", None, None, {"file": ("shell.php5.jpg", b'<?php eval($_REQUEST["c"]); ?>', "image/jpeg")}),
    ]
    return payloads

def bruteforce_requests():
    """Brute force attack payloads - dictionary attack + directory scanning."""
    protected_paths = [
        "/login", "/admin", "/wp-login", "/api/login", "/api/auth",
        "/signin", "/auth", "/oauth", "/api/v1/login", "/api/v1/auth",
        "/user/login", "/users/login", "/account/login",
    ]
    credentials = [
        ("admin", "admin"), ("admin", "password"), ("admin", "123456"),
        ("root", "root"), ("root", "toor"), ("user", "password"),
        ("test", "test"), ("administrator", "administrator"),
        ("admin", "passw0rd"), ("admin", "letmein"),
    ]
    scan_paths = [
        "/admin", "/wp-admin", "/phpmyadmin", "/.git/HEAD", "/.env",
        "/config.php", "/backup", "/backup.zip", "/dump.sql",
        "/api/v1/users", "/swagger", "/docs", "/debug", "/console",
    ]

    reqs = []
    # Login attempts (2 per path to stay under failure threshold)
    for path in protected_paths[:6]:
        for user, pwd in credentials[:3]:
            reqs.append(("POST", path, {"username": user, "password": pwd}, None, None))

    # Directory scanning
    for path in scan_paths:
        reqs.append(("GET", path, None, None, None))

    # HEAD requests
    for path in scan_paths[:5]:
        reqs.append(("HEAD", path, None, None, None))

    return reqs

def cc_requests():
    """CC attack - rapid concurrent requests from single IP."""
    # Generate unique URLs for each request
    reqs = [("GET", f"/?cc_test={i}&r={random.randint(1,99999)}", None, None, None) for i in range(40)]
    return reqs

def ddos_requests():
    """DDoS simulation - application layer HTTP flood."""
    reqs = [("GET", f"/?ddos_test={i}&r={random.randint(1,99999)}", None, None, None) for i in range(30)]
    return reqs

def benign_requests():
    """Benign traffic for false positive check."""
    return [
        ("GET", "/", None, None, None),
        ("GET", "/", {"page": "1"}, None, None),
        ("GET", "/", {"search": "hello world"}, None, None),
        ("GET", "/", {"id": "123", "name": "John"}, None, None),
        ("POST", "/", {"name": "John Doe", "email": "john@example.com"}, None, None),
        ("POST", "/", {"comment": "Great product! Really love it."}, None, None),
        ("POST", "/", {"search": "normal search query"}, None, None),
    ]

# ============================================================
# Main
# ============================================================
def main():
    print("=" * 60)
    print("Round 13 Batch-Separated Attack Suite")
    print(f"Target: {WAF_URL}")
    print(f"Time: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)

    m0 = get_metrics()
    print(f"\nInitial Metrics: {json.dumps(m0, indent=2)}")

    all_results = []
    batches = [
        ("sql_injection",  "SQL注入",   sql_injection_requests(),  0.15, False),
        ("xss",            "XSS攻击",   xss_requests(),            0.15, False),
        ("webshell",       "木马上传",  webshell_requests(),        0.4,  False),
        ("bruteforce",     "爆破攻击",  bruteforce_requests(),      0.25, False),
        ("cc_attack",      "CC攻击",    cc_requests(),             0,    True),
        ("ddos",           "DDoS模拟",  ddos_requests(),           0,    True),
        ("benign",         "正常流量",  benign_requests(),          0.3,  False),
    ]

    for batch_id, batch_name, requests_list, delay, concurrent in batches:
        result = run_batch(batch_id, batch_name, requests_list, delay, concurrent=concurrent)
        all_results.append(result)

        # Check if we're being rate-limited
        test_resp = requests.get(f"{WAF_URL}/", headers=make_session().headers, timeout=5, allow_redirects=False)
        if test_resp.status_code == 429:
            print(f"  ⚠ Rate limited detected, extending cooldown...")
            cooldown(90, "extended due to rate limit")
        else:
            cooldown(30, "batch interval")

    # Final metrics
    m_final = get_metrics()
    print(f"\n\nFinal Metrics: {json.dumps(m_final, indent=2)}")

    # ============================================================
    # Compile report
    # ============================================================
    print("\n" + "=" * 60)
    print("BATCH-SEPARATED ATTACK REPORT")
    print("=" * 60)

    # Read ALL logs since test start
    log_content = get_log_since("/tmp/batch_log_offset_sql_injection.txt")
    # Actually let me re-read all logs more carefully
    all_logs = []
    try:
        with open(SHIELD_LOG, 'r') as f:
            for line in f:
                if line.strip():
                    try:
                        e = json.loads(line)
                        if e.get("time", "") >= "2026-05-03T10:00:":
                            # Filter: only log entries related to attack detection
                            msg = e.get("message", "")
                            if any(kw in msg for kw in ["block", "detect"]):
                                all_logs.append(e)
                    except:
                        pass
    except:
        pass

    # Type identification analysis from logs
    type_correct = {
        "SQL注入": 0, "XSS": 0, "木马上传": 0, "CC攻击": 0, "DDoS": 0, "爆破攻击": 0
    }
    type_wrong = {
        "SQL注入": 0, "XSS": 0, "木马上传": 0, "CC攻击": 0, "DDoS": 0, "爆破攻击": 0
    }

    # Map attack_type values to categories
    atype_map = {
        "sql_injection": "SQL注入",
        "xss": "XSS",
        "webshell_upload": "木马上传",
        "cc_attack": "CC攻击",
        "brute_force": "爆破攻击",
    }

    for e in all_logs:
        at = e.get("attack_type", "")
        msg = e.get("message", "")

        # Determine the actual attack from the block message
        actual = None
        if "sqlinject" in msg: actual = "SQL注入"
        elif "xss" in msg: actual = "XSS"
        elif "webshell" in msg: actual = "木马上传"
        elif "cc_attack" in msg and "blocked_cc" in msg: actual = "CC攻击"
        elif "bruteforce" in msg: actual = "爆破攻击"
        elif "ddos" in msg: actual = "DDoS"

        if actual is None:
            continue

        if actual == "DDoS":
            at_label = at
            if at_label and at_label.startswith("ddos"):
                type_correct["DDoS"] += 1
            else:
                type_wrong["DDoS"] += 1
        else:
            # Check if labeled correctly
            expected = [k for k, v in atype_map.items() if v == actual]
            if expected and at in expected:
                type_correct[actual] += 1
            else:
                type_wrong[actual] += 1

    print(f"\n{'攻击类型':<15} {'测试数':>6} {'拦截数':>6} {'穿透数':>6} {'拦截率':>8} {'识别正确':>8} {'识别错误':>8}")
    print("-" * 70)

    total_tested = 0
    total_blocked = 0
    total_passed = 0
    total_correct = 0
    total_wrong = 0

    for r in all_results:
        bt = r["attack_type"]
        tested = r["count"]
        blocked = r["http_results"]["blocked"] + r["http_results"].get("challenged", 0) + r["http_results"].get("ratelimited", 0)
        passed = r["http_results"]["passed"]
        correct = type_correct.get(bt, r["metric_deltas"].get(f"{r['name']}_blocks", 0))
        wrong = max(0, blocked - correct)

        total_tested += tested
        total_blocked += blocked
        total_passed += passed
        total_correct += correct
        total_wrong += wrong

        rate = blocked / tested * 100 if tested > 0 else 0
        print(f"{bt:<15} {tested:>6} {blocked:>6} {passed:>6} {rate:>7.1f}% {correct:>8} {wrong:>8}")

    print("-" * 70)
    overall_rate = total_blocked / total_tested * 100 if total_tested > 0 else 0
    type_acc = total_correct / (total_correct + total_wrong) * 100 if (total_correct + total_wrong) > 0 else 0
    print(f"{'合计':<15} {total_tested:>6} {total_blocked:>6} {total_passed:>6} {overall_rate:>7.1f}% {total_correct:>8} {total_wrong:>8}")

    print(f"\n  整体拦截率: {overall_rate:.1f}%")
    print(f"  类型识别准确率: {type_acc:.1f}% (正确{total_correct}, 错误{total_wrong})")

    # Save results
    final_results = {
        "round": 13,
        "batch_separated": True,
        "timestamp": time.strftime('%Y-%m-%dT%H:%M:%SZ'),
        "target": WAF_URL,
        "initial_metrics": m0,
        "final_metrics": m_final,
        "batches": [],
        "overall": {
            "tested": total_tested,
            "blocked": total_blocked,
            "passed": total_passed,
            "rate": round(overall_rate, 1),
            "type_correct": total_correct,
            "type_wrong": total_wrong,
            "type_accuracy": round(type_acc, 1),
        },
    }

    for r in all_results:
        final_results["batches"].append({
            "name": r["name"],
            "attack_type": r["attack_type"],
            "count": r["count"],
            "http_results": r["http_results"],
            "metric_deltas": r["metric_deltas"],
            "log_attack_types": r["log_attack_types"],
            "log_messages": r["log_messages"],
        })

    with open(RESULTS_FILE, 'w') as f:
        json.dump(final_results, f, indent=2, default=str)

    print(f"\nResults saved to: {RESULTS_FILE}")
    return final_results

if __name__ == "__main__":
    main()
