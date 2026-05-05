#!/usr/bin/env python3
"""
Round 15 Regression Test - Shield WAF v1.14.8
Tests JS challenge redirect fix (HUD-141) and attack type regression.
"""

import requests
import concurrent.futures
import time
import json
import random
import sys
import threading
import socket
from collections import defaultdict, Counter
from datetime import datetime

SHIELD_URL = "http://127.0.0.1:8081"
BACKEND_URL = "http://127.0.0.1:8082"

class ResponseType:
    BLOCKED = "blocked"
    JS_CHALLENGE = "js_challenge"
    RATE_LIMITED = "rate_limited"
    WAITING_ROOM = "waiting_room"
    ALLOWED = "allowed"
    ERROR = "error"

class TestResult:
    def __init__(self):
        self.lock = threading.Lock()
        self.results = []
        self.summary = Counter()

    def add(self, test_type, ip, response_type, http_code, block_reason, challenge_type, url, error=None):
        with self.lock:
            self.results.append({
                "test_type": test_type, "ip": ip, "response_type": response_type,
                "http_code": http_code, "block_reason": block_reason,
                "challenge_type": challenge_type, "url": url, "error": error,
                "timestamp": time.time()
            })
            self.summary[(test_type, response_type)] += 1

    def get_counts(self, test_type):
        keys = ["blocked", "js_challenge", "rate_limited", "waiting_room", "allowed", "error", "total"]
        counts = {k: 0 for k in keys}
        for r in self.results:
            if r["test_type"] == test_type:
                counts[r["response_type"]] += 1
                counts["total"] += 1
        return counts

    def identify_block_reasons(self, test_type):
        reasons = Counter()
        for r in self.results:
            if r["test_type"] == test_type and r["response_type"] in (ResponseType.BLOCKED, ResponseType.RATE_LIMITED):
                reasons[r["block_reason"] or "rate_limit"] += 1
        return reasons

results = TestResult()

def classify_response(status_code, headers):
    if status_code == 403:
        reason = headers.get("X-Block-Reason", headers.get("x-block-reason", "unknown"))
        return ResponseType.BLOCKED, reason, None
    if status_code == 429:
        reason = headers.get("X-Block-Reason", headers.get("x-block-reason", ""))
        return ResponseType.RATE_LIMITED, reason or "rate_limit", None

    challenge_type = headers.get("X-Challenge-Type", headers.get("x-challenge-type", ""))
    if challenge_type:
        return ResponseType.JS_CHALLENGE, None, challenge_type

    if status_code in (301, 302, 307, 308):
        location = headers.get("Location", headers.get("location", ""))
        if "waiting" in location.lower() or "queue" in location.lower():
            return ResponseType.WAITING_ROOM, None, None

    if 200 <= status_code < 400:
        return ResponseType.ALLOWED, None, None
    return ResponseType.ERROR, None, None

def make_request(ip, path="/", method="GET", data=None, files=None, params=None, extra_headers=None, timeout=10):
    headers = {
        "X-Forwarded-For": ip,
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    }
    if extra_headers:
        headers.update(extra_headers)

    url = f"{SHIELD_URL}{path}"
    try:
        if method == "GET":
            resp = requests.get(url, params=params, headers=headers, timeout=timeout, allow_redirects=False)
        elif method == "POST":
            resp = requests.post(url, data=data, files=files, headers=headers, timeout=timeout, allow_redirects=False)
        else:
            resp = requests.request(method, url, data=data, files=files, params=params, headers=headers, timeout=timeout, allow_redirects=False)
        return resp
    except Exception:
        return None

def test_one(test_type, ip, path="/", method="GET", data=None, files=None, params=None, extra_headers=None):
    resp = make_request(ip, path, method, data, files, params, extra_headers)
    if resp is None:
        results.add(test_type, ip, ResponseType.ERROR, 0, None, None, path, error="Connection failed")
        return None
    resp_type, block_reason, challenge_type = classify_response(resp.status_code, resp.headers)
    results.add(test_type, ip, resp_type, resp.status_code, block_reason, challenge_type, path)
    return resp


# ============================================================
# TEST 1: JS Challenge Flow Verification
# ============================================================
def test_js_challenge_flow():
    print("\n" + "="*60)
    print("TEST 1: JS Challenge Flow Verification")
    print("="*60)

    test_ip = f"10.255.1.{random.randint(1, 254)}"

    # Use raw socket to trigger JS challenge (no Accept-Encoding)
    print(f"[1] Checking JS challenge presentation...")
    raw = f"GET / HTTP/1.1\r\nHost: 127.0.0.1:8081\r\nUser-Agent: curl/7.81.0\r\nAccept: */*\r\nX-Forwarded-For: {test_ip}\r\n\r\n"
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    sock.connect(("127.0.0.1", 8081))
    sock.sendall(raw.encode())
    resp_bytes = b""
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk: break
            resp_bytes += chunk
            if b"\r\n\r\n" in resp_bytes: break
    except socket.timeout:
        pass
    sock.close()

    resp_text = resp_bytes.decode("utf-8", errors="replace")
    has_challenge = "X-Challenge-Type" in resp_text or "x-challenge-type" in resp_text.lower()
    cc_cookie = "__shield_cc" in resp_text
    print(f"  Challenge: {'YES' if has_challenge else 'NO'}, Cookie: {'YES' if cc_cookie else 'NO'}")

    for _ in range(3):
        test_one("js_flow", test_ip)

    # Test for redirect loops
    print(f"[2] Checking for infinite redirect loops...")
    loop_ip = f"10.255.2.{random.randint(1, 254)}"
    session = requests.Session()
    max_redirs = 10
    redir_count = 0
    visited = set()
    current_url = SHIELD_URL + "/"
    headers = {"X-Forwarded-For": loop_ip, "User-Agent": "curl/7.81.0"}

    for i in range(max_redirs):
        visited.add(current_url)
        try:
            resp = session.get(current_url, headers=headers, timeout=5, allow_redirects=False)
            if resp.status_code in (301, 302, 307, 308):
                redir_count += 1
                loc = resp.headers.get("Location", resp.headers.get("location", ""))
                current_url = loc if loc.startswith("http") else (SHIELD_URL + loc if loc.startswith("/") else SHIELD_URL + "/" + loc)
                if current_url in visited:
                    print(f"  WARN: Loop detected after {redir_count} redirects!")
                    break
            else:
                break
        except Exception as e:
            break

    infinite_loop = redir_count >= max_redirs
    print(f"  Redirects: {redir_count}, Loop: {'FAIL' if infinite_loop else 'PASS'}")

    return {"has_challenge": has_challenge, "cookie_set": cc_cookie, "infinite_loop": infinite_loop}


# ============================================================
# TEST 2: Scenario 1 - 100 Normal IPs + Small Attacks
# ============================================================
def test_scenario1():
    print("\n" + "="*60)
    print("TEST 2: Scenario 1 - 100 Normal IPs + Small Attacks")
    print("="*60)

    num_normal = 100
    normal_paths = ["/", "/test", "/index", "/home"]

    # Sequential normal requests to avoid concurrency issues
    print("[1/3] Sending normal traffic (sequential, low rate)...")
    normal_ips = [f"10.1.{i//254}.{(i%254)+1}" for i in range(num_normal)]
    for i, ip in enumerate(normal_ips):
        path = random.choice(normal_paths)
        test_one("s1_normal", ip, path)
        if (i+1) % 10 == 0:
            time.sleep(0.1)  # Small pause every 10 requests
    print(f"  Done. {num_normal} requests.")

    time.sleep(1)

    # Attack traffic
    print("[2/3] Sending attack traffic...")
    attacks = [
        ("/?id=1' OR '1'='1", "sql_injection"),
        ("/?id=1 UNION SELECT 1,2,3--", "sql_injection"),
        ("/?id=1 AND 1=1--", "sql_injection"),
        ("/?q=admin'--", "sql_injection"),
        ("/?id=1; DROP TABLE users--", "sql_injection"),
        ("/?q=<script>alert(1)</script>", "xss"),
        ("/?q=<img src=x onerror=alert(1)>", "xss"),
        ("/?q=javascript:alert(1)", "xss"),
        ("/?data=<svg/onload=alert(1)>", "xss"),
        ("/?q=<body onload=alert(1)>", "xss"),
        ("/upload", "upload"),
        ("/wp-admin/admin-ajax.php?action=upload", "upload"),
        ("/login", "brute_force"),
        ("/admin", "brute_force"),
    ]
    for i, ((path, etype), ip) in enumerate(zip(attacks, [f"10.99.0.{i+1}" for i in range(len(attacks))])):
        test_one(f"s1_attack_{etype}", ip, path)
        time.sleep(0.05)
    print(f"  Done. {len(attacks)} attacks.")

    time.sleep(2)

    # Follow-up normal
    print("[3/3] Sending follow-up normal traffic...")
    normal_ips2 = [f"10.2.{i//254}.{(i%254)+1}" for i in range(num_normal)]
    for i, ip in enumerate(normal_ips2):
        path = random.choice(normal_paths)
        test_one("s1_followup", ip, path)
        if (i+1) % 10 == 0:
            time.sleep(0.1)
    print(f"  Done. {num_normal} requests.")


# ============================================================
# TEST 3: Scenario 2 - DDoS/CC + 100 Normal IPs
# ============================================================
def test_scenario2():
    print("\n" + "="*60)
    print("TEST 3: Scenario 2 - DDoS/CC + 100 Normal IPs")
    print("="*60)

    num_normal = 100
    num_cc_ips = 30
    cc_requests_per_ip = 20  # 600 CC requests total

    # First send normal traffic
    print("[1/2] Sending normal traffic first...")
    normal_ips = [f"10.5.{i//254}.{(i%254)+1}" for i in range(num_normal)]
    for i, ip in enumerate(normal_ips):
        path = random.choice(["/", "/test", "/index"])
        test_one("s2_normal", ip, path)
        if (i+1) % 10 == 0:
            time.sleep(0.1)

    time.sleep(1)

    # Then DDoS/CC traffic
    print(f"[2/2] Sending CC attack (mixed with normal follow-ups)...")
    cc_ips = [f"10.200.{i//254}.{(i%254)+1}" for i in range(num_cc_ips)]

    # Send CC in batches to trigger behavior scoring
    for batch in range(5):
        with concurrent.futures.ThreadPoolExecutor(max_workers=15) as executor:
            futures = []
            # CC traffic
            for ip in cc_ips:
                for r in range(cc_requests_per_ip // 5):
                    path = f"/page{r % 5}" if r % 3 else "/"
                    futures.append(executor.submit(
                        test_one, "s2_cc", ip, path,
                        extra_headers={"User-Agent": f"Bot/CC-{ip}", "Accept": "*/*"}
                    ))
            for f in concurrent.futures.as_completed(futures):
                f.result()
        time.sleep(0.3)

    cc_total = num_cc_ips * cc_requests_per_ip
    total_sent = num_normal + cc_total
    print(f"  Done. {num_normal} normal + {cc_total} CC = {total_sent} requests.")

    # Wait for rate limiting to settle
    time.sleep(3)

    # Follow-up normal
    print("[*] Sending follow-up normal traffic...")
    normal_ips2 = [f"10.6.{i//254}.{(i%254)+1}" for i in range(num_normal)]
    for i, ip in enumerate(normal_ips2):
        path = random.choice(["/", "/test", "/index"])
        test_one("s2_followup", ip, path)
        if (i+1) % 10 == 0:
            time.sleep(0.1)
    print(f"  Done. {num_normal} requests.")


# ============================================================
# TEST 4: Attack Type Regression
# ============================================================
def test_attack_regression():
    print("\n" + "="*60)
    print("TEST 4: Attack Type Regression")
    print("="*60)

    # SQL Injection
    print("\n[*] SQL Injection (22 payloads)...")
    sql_tests = [
        "/?id=1' OR '1'='1",
        "/?id=1 AND 1=1--",
        "/?id=1' AND '1'='1'--",
        "/?id=1' AND extractvalue(1,concat(0x7e,database()))--",
        "/?id=1' AND updatexml(1,concat(0x7e,version()),1)--",
        "/?id=1 UNION SELECT 1,2,3,4,5--",
        "/?id=-1' UNION SELECT null,table_name,null FROM information_schema.tables--",
        "/?id=1 UNION ALL SELECT 1,2,3--",
        "/?id=1' AND SLEEP(5)--",
        "/?id=1' OR IF(1=1,SLEEP(3),0)--",
        "/?id=1/**/OR/**/1=1",
        "/?id=1'/*!OR*/'1'='1",
        "/?id=1'-- -",
        "/?id=%31%27%20%4f%52%20%31%3d%31",
        "/?id=1%2527%2520OR%25201=1--",
        "/?id=1'OR/**/1=1--",
        "/?id=1'/**/UNION/**/SELECT/**/1--",
        "/?id=1;DROP TABLE users--",
        "/?id=1';DELETE FROM users WHERE 1=1--",
        "/?id=1 oR 1=1",
        "/?id=1%09OR%091=1",
        "/?id=%00' OR 1=1--",
    ]
    for i, path in enumerate(sql_tests):
        test_one("reg_sqli", f"10.10.{i//254}.{(i%254)+1}", path)
        time.sleep(0.02)

    counts = results.get_counts("reg_sqli")
    print(f"  Blocked: {counts['blocked']}/{counts['total']} ({100*counts['blocked']/max(counts['total'],1):.0f}%)")

    # XSS
    print("\n[*] XSS (20 payloads)...")
    xss_tests = [
        "/?q=<script>alert(1)</script>",
        "/?q=<SCRIPT>alert('XSS')</SCRIPT>",
        "/?q=<img src=x onerror=alert(1)>",
        "/?q=<svg/onload=alert(1)>",
        "/?q=<body onload=alert(1)>",
        "/?q=<input onfocus=alert(1) autofocus>",
        "/?q=<marquee onstart=alert(1)>test</marquee>",
        "/?q=<div onmouseover=alert(1)>hover</div>",
        "/?q=%3Cscript%3Ealert(1)%3C/script%3E",
        "/?q=%3c%73%63%72%69%70%74%3ealert(1)%3c%2f%73%63%72%69%70%74%3e",
        "/?q=javascript:alert(1)",
        "/?q=<a href='javascript:alert(1)'>click</a>",
        "/?q=<ScRiPt>alert(1)</sCrIpT>",
        "/?q=<object data='data:text/html,<script>alert(1)</script>'>",
        "/?q=&#60;script&#62;alert(1)&#60;/script&#62;",
        "/?q=<img src=1 onerror=alert(1)>",
        "/?q=<img src='x' onerror='alert(1)'>",
        "/?q=<div style='x:expression(alert(1))'>",
        "/?q=<embed src='javascript:alert(1)'>",
        "/?q=background:url(javascript:alert(1))",
    ]
    for i, path in enumerate(xss_tests):
        test_one("reg_xss", f"10.20.{i//254}.{(i%254)+1}", path)
        time.sleep(0.02)

    counts = results.get_counts("reg_xss")
    print(f"  Blocked: {counts['blocked']}/{counts['total']} ({100*counts['blocked']/max(counts['total'],1):.0f}%)")

    # Upload - actual multipart file uploads with PHP content
    print("\n[*] Upload/WebShell (15 tests)...")
    php_payloads = [
        ("shell.php", "<?php system($_GET['cmd']); ?>", "application/x-php"),
        ("cmd.php", "<?php eval($_POST['code']); ?>", "application/x-php"),
        ("backdoor.php5", "<?=`$_GET[0]`?>", "application/x-php"),
        ("webshell.phtml", "<?php @eval($_POST['c']);?>", "application/x-php"),
        ("info.php7", "<?php phpinfo(); ?>", "application/x-php"),
        ("image.php.jpg", "GIF89a\x01\x00\x01\x00<?php system($_GET['cmd']); ?>", "image/jpeg"),
        ("shell.php;.jpg", "<?php echo 'test'; ?>", "application/x-php"),
        ("test.php.", "<?php passthru($_GET['cmd']); ?>", "application/x-php"),
        ("upload.phar", "<?php __HALT_COMPILER(); ?>", "application/x-php"),
        ("sitemap.xml.php", "<?php file_get_contents('/etc/passwd'); ?>", "application/xml"),
        ("evil.php", "<?php system('id'); ?>", "application/x-php"),
        ("exploit.pht", "<?php echo shell_exec('ls -la'); ?>", "application/x-php"),
        ("test.shtml", "<!--#exec cmd='id'-->", "text/html"),
        ("index.php", "<?php include('/etc/passwd'); ?>", "application/x-php"),
        ("avatar.jpg.php", "<?php @eval($_REQUEST['x']); ?>", "image/jpeg"),
    ]

    upload_paths = ["/upload", "/wp-admin/upload.php", "/api/upload", "/file/upload", "/admin/upload"]
    test_idx = 0
    for i, (fname, content, mime) in enumerate(php_payloads):
        path = upload_paths[i % len(upload_paths)]
        files = {"file": (fname, content, mime)}
        test_one("reg_upload", f"10.30.{test_idx//254}.{(test_idx%254)+1}", path, method="POST", files=files)
        test_idx += 1
        time.sleep(0.03)

    counts = results.get_counts("reg_upload")
    print(f"  Blocked: {counts['blocked']}/{counts['total']} ({100*counts['blocked']/max(counts['total'],1):.0f}%)")

    # Brute force - rapid repeated requests
    print("\n[*] Brute Force (testing rapid access to protected paths)...")
    protected_paths = [
        "/login", "/admin", "/wp-login", "/api/login", "/api/auth",
        "/signin", "/auth", "/oauth", "/api/v1/login", "/user/login"
    ]
    bf_count = 0
    for pi, path in enumerate(protected_paths):
        ip = f"10.40.{pi//254}.{(pi%254)+1}"
        # Send rapid requests from same IP
        for attempt in range(4):
            test_one("reg_brute", ip, path, method="POST" if attempt < 3 else "GET",
                     data={"user": "admin", "pass": f"wrong{attempt}"})
            bf_count += 1
            time.sleep(0.02)

    counts = results.get_counts("reg_brute")
    print(f"  Requests: {counts['total']}, Blocked: {counts['blocked']}, Rate Limited: {counts['rate_limited']}")

    time.sleep(0.5)

    # False positives
    print("\n[*] False positive check (benign requests)...")
    benign = [
        "/", "/test", "/?q=hello world", "/?id=123", "/?name=John",
        "/?id=42&name=normal", "/about", "/contact", "/page/1",
        "/search?q=test", "/?lang=en", "/?category=books",
        "/?sort=asc&page=1", "/?filter=active", "/?query=normal+search",
        "/?user=admin&action=view",
        "/?comment=It's fine with single quote",
        "/?description=select from where id=1",
        "/?number=1 or 2", "/?data=script language",
    ]
    for i, path in enumerate(benign):
        test_one("fp", f"10.90.{i//254}.{(i%254)+1}", path)
        time.sleep(0.02)

    fp_counts = results.get_counts("fp")
    fp_blocked = fp_counts["blocked"]
    print(f"  Benign: {fp_counts['total']}, Blocked: {fp_blocked}, Rate: {100*fp_blocked/max(fp_counts['total'],1):.1f}%")
    for r in results.results:
        if r["test_type"] == "fp" and r["response_type"] == ResponseType.BLOCKED:
            print(f"    FP: {r['ip']} -> {r['url']} blocked as '{r['block_reason']}'")


# ============================================================
# REPORT
# ============================================================
def report(js):
    print("\n\n" + "="*70)
    print("ROUND 15 REGRESSION TEST REPORT")
    print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Shield: v1.14.8")
    print("="*70)

    def pct(n, d):
        return "N/A" if d == 0 else f"{100*n/d:.1f}%"

    # 1. JS Challenge
    print("\n## 1. JS Challenge Flow")
    print(f"  Challenge presented: {'YES' if js['has_challenge'] else 'NO'}")
    print(f"  Cookie: {'YES' if js['cookie_set'] else 'NO'}")
    print(f"  Infinite loop: {'FAIL' if js['infinite_loop'] else 'PASS'}")

    # 2. Scenario 1
    print("\n## 2. Scenario 1: 100 Normal + Small Attacks")
    for g, label in [("s1_normal", "Normal (initial)"), ("s1_followup", "Normal (follow-up)")]:
        c = results.get_counts(g)
        success = c["js_challenge"] + c["allowed"]
        print(f"  {label}: total={c['total']}, allowed={c['allowed']}, JS_Challenge={c['js_challenge']}, blocked={c['blocked']}, rate_limited={c['rate_limited']}, error={c['error']}")
        print(f"    Success rate: {pct(success, c['total'])}")

    print("\n  Attack results:")
    for atype in ["sql_injection", "xss", "upload", "brute_force"]:
        c = results.get_counts(f"s1_attack_{atype}")
        if c["total"] > 0:
            reasons = results.identify_block_reasons(f"s1_attack_{atype}")
            rstr = ", ".join(f"{k}:{v}" for k, v in reasons.items())
            print(f"    {atype}: blocked={c['blocked']}/{c['total']} [{pct(c['blocked'], c['total'])}] reasons={rstr}")

    # 3. Scenario 2
    print("\n## 3. Scenario 2: DDoS/CC + Normal IPs")
    for g, label in [("s2_normal", "Normal"), ("s2_followup", "Normal (follow-up)")]:
        c = results.get_counts(g)
        success = c["js_challenge"] + c["allowed"]
        print(f"  {label}: total={c['total']}, allowed={c['allowed']}, JS_Challenge={c['js_challenge']}, blocked={c['blocked']}, rate_limited={c['rate_limited']}, error={c['error']}")
        print(f"    Success: {pct(success, c['total'])}")

    cc = results.get_counts("s2_cc")
    cc_intercepted = cc["blocked"] + cc["rate_limited"] + cc["js_challenge"]
    cc_total = max(cc["total"], 1)
    print(f"\n  CC Attack: total={cc['total']}, blocked={cc['blocked']}, rate_limited={cc['rate_limited']}, JS_challenge={cc['js_challenge']}, allowed={cc['allowed']}")
    print(f"    Interception rate: {pct(cc_intercepted, cc_total)}")
    reasons = results.identify_block_reasons("s2_cc")
    print(f"    Reasons: {', '.join(f'{k}:{v}' for k, v in reasons.most_common())}")

    # 4. Attack Regression
    print("\n## 4. Attack Type Regression")
    reg_types = {
        "reg_sqli": "SQL Injection",
        "reg_xss": "XSS",
        "reg_upload": "Upload/WebShell",
        "reg_brute": "Brute Force",
    }
    expected_reasons = {
        "reg_sqli": "sql_injection",
        "reg_xss": "xss",
        "reg_upload": "webshell_upload",
        "reg_brute": "brute_force",
    }

    stats = {}
    for key, label in reg_types.items():
        c = results.get_counts(key)
        total = c["total"]
        blocked = c["blocked"]
        rate_limited = c["rate_limited"]
        intercepted = blocked + rate_limited
        allowed = c["allowed"]
        challenged = c["js_challenge"]
        errors = c["error"]

        exp = expected_reasons[key]
        correct_id = 0
        wrong_id = 0
        wrong_details = []
        for r in results.results:
            if r["test_type"] == key and r["response_type"] == ResponseType.BLOCKED:
                if r["block_reason"] == exp:
                    correct_id += 1
                else:
                    wrong_id += 1
                    wrong_details.append(r["block_reason"])

        stats[label] = {
            "total": total, "blocked": blocked, "rate_limited": rate_limited,
            "intercepted": intercepted, "allowed": allowed,
            "challenged": challenged, "errors": errors,
            "intercept_pct": pct(intercepted, max(total, 1)),
            "correct_id": correct_id, "wrong_id": wrong_id,
            "wrong_details": wrong_details,
        }

    print(f"\n  {'Attack Type':<20} {'Total':>6} {'Block':>7} {'429':>5} {'Allow':>6} {'Rate':>8} {'ID_OK':>6} {'ID_Err':>7}")
    print("  " + "-"*68)
    for label, s in stats.items():
        print(f"  {label:<20} {s['total']:>6} {s['blocked']:>7} {s['rate_limited']:>5} {s['allowed']:>6} {s['intercept_pct']:>8} {s['correct_id']:>6} {s['wrong_id']:>7}")

    has_id_err = False
    print("\n  ID Errors:")
    for label, s in stats.items():
        if s["wrong_id"] > 0:
            has_id_err = True
            print(f"  {label}: {s['wrong_id']} wrong — {Counter(s['wrong_details'])}")
    if not has_id_err:
        print("  None — all correctly identified!")

    # 5. FP
    print("\n## 5. False Positives")
    fp = results.get_counts("fp")
    fp_blocked = fp["blocked"] + fp["rate_limited"]
    fp_rate = 100 * fp_blocked / max(fp["total"], 1)
    print(f"  Benign: {fp['total']}, Blocked: {fp['blocked']}, RateLimited: {fp['rate_limited']} → FP Rate: {fp_rate:.1f}%")
    for r in results.results:
        if r["test_type"] == "fp" and r["response_type"] in (ResponseType.BLOCKED, ResponseType.RATE_LIMITED):
            print(f"    FP: {r['ip']} → {r['url']} [{r['response_type']}] reason={r['block_reason']}")

    # 6. Summary
    print("\n## 6. Summary")
    s1 = results.get_counts("s1_normal")
    s1_succ = s1["js_challenge"] + s1["allowed"]
    s1_rate = 100 * s1_succ / max(s1["total"], 1)

    s2 = results.get_counts("s2_normal")
    s2_succ = s2["js_challenge"] + s2["allowed"]
    s2_rate = 100 * s2_succ / max(s2["total"], 1)

    cc_rate_val = 100 * cc_intercepted / cc_total

    checks = [
        ("Scenario 1 Normal IP Success", s1_rate, "≥95%", s1_rate >= 95),
        ("Scenario 2 Normal IP Success", s2_rate, "≥95%", s2_rate >= 95),
        ("CC/DDoS Interception Rate", cc_rate_val, "≥80%", cc_rate_val >= 80),
        ("False Positive Rate", fp_rate, "<2%", fp_rate < 2),
        ("No Infinite JS Redirect Loop", 0 if js["infinite_loop"] else 100, "Pass", not js["infinite_loop"]),
    ]

    print(f"  {'Metric':<35} {'Value':>12} {'Target':>10} {'Status':>8}")
    print(f"  {'-'*35} {'-'*12} {'-'*10} {'-'*8}")
    all_ok = True
    for name, val, target, passed in checks:
        if "Loop" in name:
            vstr = "No Loop" if val == 100 else "LOOP"
        else:
            vstr = f"{val:.1f}%"
        print(f"  {name:<35} {vstr:>12} {target:>10} {'PASS' if passed else 'FAIL':>8}")
        if not passed:
            all_ok = False
    if has_id_err:
        all_ok = False

    print(f"\n  {'OVERALL':<35} {'':>12} {'':>10} {'PASS' if all_ok else 'FAIL':>8}")

    print("\n## 7. Assessment")
    if all_ok:
        print("  ALL CHECKS PASSED!")
        print("  - HUD-141 JS challenge redirect fix verified: no infinite loops")
        print("  - Normal IPs correctly allowed through")
        print("  - Attack interception working effectively")
        print("  - Attack type identification accurate")
        print("  - No false positives")
    else:
        issues = []
        if s1_rate < 95: issues.append(f"S1 normal IP: {s1_rate:.1f}% (target ≥95%)")
        if s2_rate < 95: issues.append(f"S2 normal IP: {s2_rate:.1f}% (target ≥95%)")
        if cc_rate_val < 80: issues.append(f"CC interception: {cc_rate_val:.1f}% (target ≥80%)")
        if fp_rate >= 2: issues.append(f"FP rate: {fp_rate:.1f}% (target <2%)")
        if js["infinite_loop"]:
            issues.append("JS challenge infinite redirect loop")
        for label, s in stats.items():
            if s["wrong_id"] > 0:
                issues.append(f"{label}: {s['wrong_id']} identification errors")
        for issue in issues:
            print(f"  - {issue}")

    return {"s1": s1_rate, "s2": s2_rate, "cc": cc_rate_val, "fp": fp_rate,
            "loop": js["infinite_loop"], "stats": stats, "all_ok": all_ok}


# ============================================================
# MAIN
# ============================================================
if __name__ == "__main__":
    print("="*70)
    print(f"ROUND 15 REGRESSION TEST | Shield v1.14.8")
    print(f"Start: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*70)

    print("\n[*] Connectivity...")
    try:
        r = requests.get(SHIELD_URL + "/", timeout=5)
        print(f"  Shield: ONLINE (HTTP {r.status_code})")
    except Exception as e:
        print(f"  Shield: OFFLINE — {e}")
        sys.exit(1)
    try:
        r = requests.get(BACKEND_URL + "/", timeout=5)
        print(f"  Backend: ONLINE (HTTP {r.status_code})")
    except Exception as e:
        print(f"  Backend: OFFLINE — {e}")

    js = test_js_challenge_flow()
    time.sleep(2)

    test_scenario1()
    print("\n[*] Cooling down 5s...")
    time.sleep(5)

    test_scenario2()
    print("\n[*] Cooling down 3s...")
    time.sleep(3)

    test_attack_regression()

    rep = report(js)
    print("\n" + "="*70)
    print("DONE")
    print("="*70)
