#!/usr/bin/env python3
"""
Shield WAF Mixed-Traffic Penetration Test
Verifies DDoS/CC fusion tag policy correctly distinguishes normal vs attack traffic.
Also tests SQLi, XSS, upload, brute-force recognition accuracy.
"""

import asyncio
import aiohttp
import time
import random
import json
import subprocess
from dataclasses import dataclass
from collections import defaultdict

TARGET = "http://127.0.0.1:8081"
LOG_PATH = "/root/shield/logs/shield.log"
TEST_DURATION = 310  # 5+ minutes

# --- IP Ranges (all unique, no overlap) ---
NORMAL_IPS = [f"10.1.0.{i}" for i in range(1, 101)]
CC_IPS = [f"192.168.200.{i}" for i in range(1, 51)]
PENTEST_IPS = [f"10.99.0.{i}" for i in range(1, 21)]

# DDoS IPs - generate ~1000 unique IPs across many subnets
DDOS_IPS = []
for a in range(172, 176):
    for c in range(1, 256):
        if len(DDOS_IPS) >= 1000:
            break
        DDOS_IPS.append(f"{a}.16.{c}")
    if len(DDOS_IPS) >= 1000:
        break

# Verify no overlap
all_ips = set(NORMAL_IPS) | set(CC_IPS) | set(PENTEST_IPS) | set(DDOS_IPS)
assert len(all_ips) == len(NORMAL_IPS) + len(CC_IPS) + len(PENTEST_IPS) + len(DDOS_IPS), \
    f"IP OVERLAP! Expected {len(NORMAL_IPS)+len(CC_IPS)+len(PENTEST_IPS)+len(DDOS_IPS)}, got {len(all_ips)}"

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:120.0) Gecko/20100101 Firefox/120.0",
]

NORMAL_PATHS = ["/", "/about", "/contact", "/api/data", "/static/style.css", "/favicon.ico"]

SQLI_PAYLOADS = [
    "/?id=1' OR '1'='1",
    "/?id=1' UNION SELECT 1,2,3--",
    "/?id=1 AND 1=1",
    "/?id=1' AND SLEEP(5)--",
    "/?id=1%27%20OR%20%271%27%3D%271",
    "/?id=1/**/OR/**/1=1",
    "/?id=admin'--",
    "/?id=1' AND '1'='1' /*",
    "/?id=1 OR 1=1--",
    "/?username=admin' OR '1'='1'--&password=test",
    "/?id=1' AND (SELECT 1 FROM (SELECT(SLEEP(3)))a)--",
    "/?id=1 UNION SELECT NULL,NULL,NULL--",
]

XSS_PAYLOADS = [
    "/?q=<script>alert(1)</script>",
    "/?q=<img src=x onerror=alert(1)>",
    "/?q=<svg onload=alert(1)>",
    "/?q=javascript:alert(1)",
    "/?q=<body onload=alert(1)>",
    "/?q=<iframe src=javascript:alert(1)>",
    "/?q=<ScRiPt>alert(1)</ScRiPt>",
    "/?q=<img src=x onerror=&#97;lert(1)>",
    "/?q=%3Cscript%3Ealert(1)%3C/script%3E",
    "/?q=<details open ontoggle=alert(1)>",
    "/?q=<div onmouseover=alert(1)>hover</div>",
]

UPLOAD_PAYLOADS = [
    ("shell.php", b'<?php system($_GET["cmd"]); ?>', "application/x-php"),
    ("shell.php5", b'<?php @eval($_POST["c"]); ?>', "application/x-php"),
    ("shell.phtml", b'<?php echo shell_exec("id"); ?>', "application/x-httpd-php"),
    ("img.jpg.php", b'GIF89a<?php system($_GET["c"]); ?>', "image/jpeg"),
    ("shell.jsp", b'<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>', "text/html"),
    ("shell.aspx", b'<%@ Page Language="C#" %><% System.Diagnostics.Process.Start("cmd.exe"); %>', "text/html"),
]

BRUTE_FORCE_PATHS = ["/login", "/admin", "/wp-login", "/api/login", "/api/auth", "/signin", "/auth"]
BRUTE_CREDENTIALS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "123456"), ("admin", "admin123"),
    ("root", "root"), ("test", "test"), ("user", "password"), ("admin", "passw0rd"),
    ("administrator", "admin"), ("guest", "guest"),
]

ATTACK_PATHS = ["/", "/api/data", "/search", "/api/v1/users", "/products", "/index.html"]


@dataclass
class RequestResult:
    ip: str
    group: str
    attack_type: str
    path: str
    status_code: int
    block_reason: str
    category: str  # pass, challenge, blocked, error
    duration_ms: float
    body_preview: str


class TestResults:
    def __init__(self):
        self.results: list[RequestResult] = []
        self.lock = asyncio.Lock()
        self.cpu_samples = []

    async def add(self, r: RequestResult):
        async with self.lock:
            self.results.append(r)

    def summary(self):
        def default_counts():
            return {"pass": 0, "challenge": 0, "blocked": 0, "error": 0, "other": 0, "total": 0}
        groups = defaultdict(default_counts)
        attack_types = defaultdict(default_counts)
        for r in self.results:
            groups[r.group]["total"] += 1
            groups[r.group][r.category] += 1
            attack_types[r.attack_type]["total"] += 1
            attack_types[r.attack_type][r.category] += 1
        return groups, attack_types


results = TestResults()
STOP_EVENT = asyncio.Event()


def get_cpu_mem():
    try:
        with open("/proc/loadavg") as f:
            load = float(f.read().split()[0])
        with open("/proc/meminfo") as f:
            meminfo = f.read()
        total = int([l for l in meminfo.splitlines() if "MemTotal" in l][0].split()[1])
        avail = int([l for l in meminfo.splitlines() if "MemAvailable" in l][0].split()[1])
        used_pct = (total - avail) / total * 100
        try:
            out = subprocess.check_output(
                "ps -p $(pgrep -f '/opt/shield/shield' | head -1) -o %cpu,%mem --no-headers 2>/dev/null || echo '0 0'",
                shell=True, text=True).strip()
            parts = out.split()
            shield_cpu = float(parts[0]) if parts else 0
            shield_mem = float(parts[1]) if len(parts) > 1 else 0
        except:
            shield_cpu = shield_mem = 0
        return {"ts": time.time(), "load_1min": load, "mem_used_pct": round(used_pct, 1),
                "shield_cpu_pct": shield_cpu, "shield_mem_pct": shield_mem}
    except:
        return {"ts": time.time(), "load_1min": 0, "mem_used_pct": 0, "shield_cpu_pct": 0, "shield_mem_pct": 0}


def categorize(status, body_preview):
    if 200 <= status < 400:
        return "pass"
    if status == 429:
        if any(kw in body_preview.lower() for kw in ["verifying", "canvas", "fp_canvas", "spinner", "security check"]):
            return "challenge"
        return "blocked"
    if status in (403, 503):
        return "blocked"
    if status < 0:
        return "error"
    return "other"


async def do_request(session, ip, method, path, headers=None, data=None, content_type=None):
    url = f"{TARGET}{path}"
    hdrs = headers or {}
    hdrs["X-Forwarded-For"] = ip
    if "User-Agent" not in hdrs:
        hdrs["User-Agent"] = random.choice(USER_AGENTS)

    start = time.time()
    try:
        if method == "GET":
            async with session.get(url, headers=hdrs, timeout=aiohttp.ClientTimeout(total=10), ssl=False) as resp:
                body = await resp.text()
                status = resp.status
                reason = resp.headers.get("X-Block-Reason", "")
        else:
            if data:
                hdrs["Content-Type"] = content_type or "application/x-www-form-urlencoded"
            async with session.post(url, headers=hdrs, data=data, timeout=aiohttp.ClientTimeout(total=10), ssl=False) as resp:
                body = await resp.text()
                status = resp.status
                reason = resp.headers.get("X-Block-Reason", "")
    except asyncio.TimeoutError:
        dur = (time.time() - start) * 1000
        return RequestResult(ip, "", "", path, -1, "", "error", dur, "timeout")
    except Exception as e:
        dur = (time.time() - start) * 1000
        return RequestResult(ip, "", "", path, -1, "", "error", dur, str(e)[:200])

    dur = (time.time() - start) * 1000
    preview = body[:300]
    return RequestResult(ip, "", "", path, status, reason, categorize(status, preview), dur, preview)


async def normal_user(session, ip, idx):
    """Normal browsing - continuous throughout test."""
    while not STOP_EVENT.is_set():
        path = random.choice(NORMAL_PATHS)
        headers = {
            "User-Agent": random.choice(USER_AGENTS),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Connection": "keep-alive",
        }
        r = await do_request(session, ip, "GET", path, headers)
        r.group = "normal"
        r.attack_type = "normal"
        await results.add(r)
        await asyncio.sleep(random.uniform(2.0, 30.0))


async def ddos_worker(session, ips_chunk):
    """DDoS flood worker - cycles through its IP chunk."""
    i = 0
    while not STOP_EVENT.is_set():
        ip = ips_chunk[i % len(ips_chunk)]
        path = random.choice(ATTACK_PATHS)
        headers = {"User-Agent": "", "Accept": "*/*"}
        r = await do_request(session, ip, "GET", path, headers)
        r.group = "ddos"
        r.attack_type = "ddos_flood"
        await results.add(r)
        i += 1
        await asyncio.sleep(0.02)


async def cc_worker(session, ips_chunk):
    """CC attack worker - concentrated high-rate to specific paths."""
    paths = ["/", "/api/data", "/search", "/products"]
    i = 0
    while not STOP_EVENT.is_set():
        ip = ips_chunk[i % len(ips_chunk)]
        path = random.choice(paths)
        headers = {"User-Agent": random.choice(USER_AGENTS), "Accept": "*/*"}
        r = await do_request(session, ip, "GET", path, headers)
        r.group = "cc"
        r.attack_type = "cc_attack"
        await results.add(r)
        i += 1
        await asyncio.sleep(random.uniform(0.02, 0.15))


async def sqli_attacker(session, ip):
    """Run SQL injection payloads in a loop."""
    while not STOP_EVENT.is_set():
        payload = random.choice(SQLI_PAYLOADS)
        headers = {"User-Agent": random.choice(USER_AGENTS), "Accept": "text/html,application/xhtml+xml"}
        r = await do_request(session, ip, "GET", payload, headers)
        r.group = "pentest"
        r.attack_type = "sqli"
        await results.add(r)
        await asyncio.sleep(random.uniform(0.1, 0.5))


async def xss_attacker(session, ip):
    """Run XSS payloads in a loop."""
    while not STOP_EVENT.is_set():
        payload = random.choice(XSS_PAYLOADS)
        headers = {"User-Agent": random.choice(USER_AGENTS), "Accept": "text/html,application/xhtml+xml"}
        r = await do_request(session, ip, "GET", payload, headers)
        r.group = "pentest"
        r.attack_type = "xss"
        await results.add(r)
        await asyncio.sleep(random.uniform(0.1, 0.5))


async def upload_attacker(session, ip):
    """Run file upload attacks in a loop."""
    while not STOP_EVENT.is_set():
        filename, content, content_type = random.choice(UPLOAD_PAYLOADS)
        headers = {"User-Agent": random.choice(USER_AGENTS), "Accept": "*/*"}
        r = await do_request(session, ip, "POST", "/upload", headers, data=content, content_type=content_type)
        r.group = "pentest"
        r.attack_type = "upload"
        await results.add(r)
        await asyncio.sleep(random.uniform(0.3, 1.0))


async def brute_attacker(session, ip):
    """Run brute force attacks in a loop."""
    while not STOP_EVENT.is_set():
        path = random.choice(BRUTE_FORCE_PATHS)
        username, password = random.choice(BRUTE_CREDENTIALS)
        headers = {"User-Agent": random.choice(USER_AGENTS), "Accept": "*/*"}
        data = f"username={username}&password={password}"
        r = await do_request(session, ip, "POST", path, headers, data=data.encode(),
                           content_type="application/x-www-form-urlencoded")
        r.group = "pentest"
        r.attack_type = "brute_force"
        await results.add(r)
        await asyncio.sleep(random.uniform(0.1, 0.5))


async def monitor_resources():
    while not STOP_EVENT.is_set():
        results.cpu_samples.append(get_cpu_mem())
        await asyncio.sleep(15)


async def main():
    print("=" * 70)
    print("  Shield WAF Mixed-Traffic Penetration Test")
    print("  HUD-148: Large-Scale Mixed Traffic Test")
    print("=" * 70)
    print(f"  Normal IPs: {len(NORMAL_IPS)}")
    print(f"  DDoS IPs: {len(DDOS_IPS)}")
    print(f"  CC IPs: {len(CC_IPS)}")
    print(f"  Pentest IPs: {len(PENTEST_IPS)}")
    print(f"  Total unique IPs: {len(all_ips)}")
    print(f"  Duration: {TEST_DURATION}s")

    baseline = get_cpu_mem()
    print(f"\n--- BASELINE ---")
    print(f"  Load: {baseline['load_1min']}, Mem: {baseline['mem_used_pct']}%, Shield CPU: {baseline['shield_cpu_pct']}%, MEM: {baseline['shield_mem_pct']}%")

    # Pre-test log count
    pre_log_lines = 0
    try:
        with open(LOG_PATH, "r") as f:
            pre_log_lines = len(f.readlines())
    except:
        pass

    # Start monitor
    monitor_task = asyncio.create_task(monitor_resources())

    start_time = time.time()

    connector = aiohttp.TCPConnector(limit=300, force_close=True)
    async with aiohttp.ClientSession(connector=connector) as session:
        all_tasks = []

        # Phase 1: Normal users first (staggered start)
        print("\n[Phase 1] Starting 100 normal users...")
        for i, ip in enumerate(NORMAL_IPS):
            all_tasks.append(asyncio.create_task(normal_user(session, ip, i)))
            await asyncio.sleep(0.25)

        # Phase 2: Pentest attackers
        print("[Phase 2] Starting penetration testers...")
        await asyncio.sleep(3)
        for ip in PENTEST_IPS[:4]:
            all_tasks.append(asyncio.create_task(sqli_attacker(session, ip)))
        for ip in PENTEST_IPS[4:8]:
            all_tasks.append(asyncio.create_task(xss_attacker(session, ip)))
        for ip in PENTEST_IPS[8:11]:
            all_tasks.append(asyncio.create_task(upload_attacker(session, ip)))
        for ip in PENTEST_IPS[11:17]:
            all_tasks.append(asyncio.create_task(brute_attacker(session, ip)))

        # Phase 3: CC attack workers
        print("[Phase 3] Starting CC attack...")
        await asyncio.sleep(5)
        chunk_size = 10
        for start in range(0, len(CC_IPS), chunk_size):
            chunk = CC_IPS[start:start + chunk_size]
            all_tasks.append(asyncio.create_task(cc_worker(session, chunk)))

        # Phase 4: DDoS flood workers
        print("[Phase 4] Starting DDoS HTTP flood...")
        await asyncio.sleep(5)
        ddos_chunk_size = 100
        for start in range(0, len(DDOS_IPS), ddos_chunk_size):
            chunk = DDOS_IPS[start:start + ddos_chunk_size]
            all_tasks.append(asyncio.create_task(ddos_worker(session, chunk)))

        print(f"\n[Running] {len(all_tasks)} concurrent tasks running for {TEST_DURATION}s...")
        print(f"[Running] Normal: 100 | DDoS workers: {len(DDOS_IPS)//ddos_chunk_size} | CC workers: {len(CC_IPS)//chunk_size} | Pentesters: 16")

        # Progress counter
        last_count = 0
        progress_start = time.time()
        while time.time() - start_time < TEST_DURATION:
            await asyncio.sleep(10)
            elapsed = time.time() - start_time
            total_reqs = len(results.results)
            rate = (total_reqs - last_count) / 10.0
            last_count = total_reqs
            sample = get_cpu_mem()
            print(f"  [{elapsed:6.1f}s] reqs={total_reqs:6d} rate={rate:.0f}/s load={sample['load_1min']:.2f} mem={sample['mem_used_pct']:.1f}% shield_cpu={sample['shield_cpu_pct']:.1f}%")

        elapsed = time.time() - start_time
        print(f"\n[Stopping] Test duration reached ({elapsed:.0f}s). Stopping all workers...")
        STOP_EVENT.set()

        # Wait for tasks to finish
        await asyncio.sleep(5)
        for t in all_tasks:
            if not t.done():
                t.cancel()
        await asyncio.sleep(3)

    await monitor_task
    end_time = time.time()
    test_duration = end_time - start_time
    final_res = get_cpu_mem()

    # --- Analysis ---
    pre_log2 = 0
    try:
        with open(LOG_PATH, "r") as f:
            log_lines = f.readlines()
        post_log_lines = len(log_lines)
        new_lines = log_lines[pre_log_lines:]
    except:
        new_lines = []
        post_log_lines = 0

    groups, attack_types = results.summary()

    # Normal IP analysis
    normal_blocked_ips = set()
    normal_challenged_ips = set()
    normal_passed_ips = set()
    for r in results.results:
        if r.group == "normal":
            if r.category == "blocked":
                normal_blocked_ips.add(r.ip)
            elif r.category == "challenge":
                normal_challenged_ips.add(r.ip)
            elif r.category == "pass":
                normal_passed_ips.add(r.ip)

    normal_ips_successful = normal_challenged_ips | normal_passed_ips
    normal_pass_rate = len(normal_ips_successful) / 100 * 100

    # DDoS/CC interception
    ddos_data = groups["ddos"]
    cc_data = groups["cc"]
    attack_total = ddos_data["total"] + cc_data["total"]
    attack_blocked = ddos_data["blocked"] + cc_data["blocked"]
    attack_challenged = ddos_data["challenge"] + cc_data["challenge"]
    attack_pass = ddos_data["pass"] + cc_data["pass"]
    attack_interception_rate = (attack_blocked + attack_challenged) / attack_total * 100 if attack_total > 0 else 0

    # Resource stats
    max_load = max((s.get("load_1min", 0) for s in results.cpu_samples), default=0)
    max_mem = max((s.get("mem_used_pct", 0) for s in results.cpu_samples), default=0)
    max_shield_cpu = max((s.get("shield_cpu_pct", 0) for s in results.cpu_samples), default=0)
    max_shield_mem = max((s.get("shield_mem_pct", 0) for s in results.cpu_samples), default=0)
    avg_load = sum(s.get("load_1min", 0) for s in results.cpu_samples) / len(results.cpu_samples) if results.cpu_samples else 0
    avg_mem = sum(s.get("mem_used_pct", 0) for s in results.cpu_samples) / len(results.cpu_samples) if results.cpu_samples else 0

    # Log analysis - extract attack type labels
    log_labels = defaultdict(int)
    ddos_cc_log_count = 0
    for line in new_lines:
        try:
            entry = json.loads(line.strip())
            module = entry.get("module", "")
            reason = entry.get("reason", "")
            # Count log entries by module
            if module:
                log_labels[module] += 1
            if "ddos" in (module + reason).lower() or "cc" in (module + reason).lower():
                ddos_cc_log_count += 1
        except:
            pass

    # --- Build Report ---
    report_lines = []
    def a(text=""):
        report_lines.append(text)

    a("=" * 70)
    a("  HUD-148: MASSIVE MIXED TRAFFIC TEST REPORT")
    a("  Shield WAF Penetration Test")
    a("=" * 70)
    a()
    a(f"**Test Duration**: {test_duration:.1f}s ({test_duration/60:.1f} min)")
    a(f"**Total Requests**: {len(results.results)}")
    a(f"**Unique IPs Used**: {len(all_ips)}")
    a()

    a("## 1. Traffic Groups Overview")
    a()
    a("| Group | Total | Pass | Challenge | Blocked | Error | Not-Blocked % | Blocked % |")
    a("|-------|-------|------|-----------|---------|-------|---------------|-----------|")
    for gname in ["normal", "ddos", "cc", "pentest"]:
        g = groups[gname]
        total = g["total"]
        if total == 0:
            continue
        nb = g["pass"] + g["challenge"]
        nb_pct = nb / total * 100 if total else 0
        b_pct = g["blocked"] / total * 100 if total else 0
        a(f"| {gname:7s} | {total:5d} | {g['pass']:4d} | {g['challenge']:9d} | {g['blocked']:7d} | {g['error']:5d} | {nb_pct:5.1f}% ({nb}) | {b_pct:5.1f}% |")
    a()

    a("## 2. Attack Type Breakdown")
    a()
    a("| Attack Type | Total | Blocked | Challenge | Pass | Error | Block % |")
    a("|-------------|-------|---------|-----------|------|-------|---------|")
    for atype in ["normal", "ddos_flood", "cc_attack", "sqli", "xss", "upload", "brute_force"]:
        at = attack_types[atype]
        total = at["total"]
        if total == 0:
            continue
        b_pct = at["blocked"] / total * 100 if total else 0
        a(f"| {atype:13s} | {total:5d} | {at['blocked']:7d} | {at['challenge']:9d} | {at['pass']:4d} | {at['error']:5d} | {b_pct:5.1f}% |")
    a()

    a("## 3. Key Metrics")
    a()

    normal_result = "PASS" if normal_pass_rate >= 95.0 else "FAIL"
    ddos_cc_result = "PASS" if attack_interception_rate >= 80.0 else "FAIL"

    a(f"### 3.1 Normal IP Success Rate: {normal_pass_rate:.1f}% [{normal_result}]")
    a(f"- Requirement: >=95% of 100 normal IPs succeed (JS challenge accepted as success)")
    a(f"- Result: {len(normal_ips_successful)}/100 IPs succeeded")
    a(f"- Direct pass (200): {len(normal_passed_ips)} IPs")
    a(f"- JS challenge (429 with challenge): {len(normal_challenged_ips)} IPs")
    a(f"- Blocked (403/503): {len(normal_blocked_ips)} IPs")
    if normal_blocked_ips:
        a(f"- Blocked IPs: {sorted(normal_blocked_ips)}")
    a()

    a(f"### 3.2 DDoS/CC Attack Interception Rate: {attack_interception_rate:.1f}% [{ddos_cc_result}]")
    a(f"- Requirement: >=80% of attack traffic intercepted")
    a(f"- Attack total: {attack_total} requests")
    a(f"- Blocked: {attack_blocked}, Challenged: {attack_challenged}, Passed: {attack_pass}")
    a(f"- DDoS stats: {ddos_data['total']} reqs, {ddos_data['blocked']} blocked, {ddos_data['challenge']} challenged, {ddos_data['pass']} passed")
    a(f"- CC stats:   {cc_data['total']} reqs, {cc_data['blocked']} blocked, {cc_data['challenge']} challenged, {cc_data['pass']} passed")
    a()

    a("### 3.3 Penetration Test Results")
    a()
    a("| Attack Type | Test Count | Blocked | Pass | Challenge | Block Rate |")
    a("|------------|-----------|---------|------|-----------|-----------|")
    for atype, label in [("sqli", "SQL Injection"), ("xss", "XSS"), ("upload", "File Upload"), ("brute_force", "Brute Force")]:
        at = attack_types[atype]
        total = at["total"]
        if total == 0:
            continue
        rate = at["blocked"] / total * 100 if total else 0
        a(f"| {label:12s} | {total:9d} | {at['blocked']:7d} | {at['pass']:4d} | {at['challenge']:9d} | {rate:5.1f}% |")
    a()

    a("### 3.4 Resource Impact")
    a()
    a("| Metric | Baseline | Peak | Average |")
    a("|--------|----------|------|---------|")
    a(f"| CPU Load (1min) | {baseline['load_1min']:.2f} | {max_load:.2f} | {avg_load:.2f} |")
    a(f"| Memory Used % | {baseline['mem_used_pct']}% | {max_mem}% | {avg_mem:.1f}% |")
    a(f"| Shield CPU % | {baseline['shield_cpu_pct']}% | {max_shield_cpu}% | - |")
    a(f"| Shield MEM % | {baseline['shield_mem_pct']}% | {max_shield_mem}% | - |")
    a()

    a("### 3.5 Log Analysis")
    a(f"- Pre-test log lines: {pre_log_lines}")
    a(f"- Post-test log lines: {post_log_lines}")
    a(f"- New log entries: {len(new_lines)}")
    if log_labels:
        a("- Log entries by module:")
        for module, count in sorted(log_labels.items(), key=lambda x: -x[1]):
            a(f"  - {module}: {count}")
    a()

    a("## 4. Overall Assessment")
    a()
    all_pass = normal_result == "PASS" and ddos_cc_result == "PASS"
    a(f"- **Normal IP Protection**: {normal_result} ({normal_pass_rate:.1f}%)")
    a(f"- **Attack Interception**: {ddos_cc_result} ({attack_interception_rate:.1f}%)")
    a(f"- **Overall Result**: {'PASS' if all_pass else 'PARTIAL PASS / FAIL'}")

    # Critical findings
    a()
    a("### Critical Findings")
    if normal_blocked_ips:
        a(f"- NORMAL IPs INCORRECTLY BLOCKED: {len(normal_blocked_ips)} IPs — {sorted(normal_blocked_ips)}")
    else:
        a("- No normal IPs were incorrectly blocked")
    a(f"- {len(normal_challenged_ips)} normal IPs received JS challenges (accepted as pass)")
    a(f"- Attack pass-through rate: {attack_pass}/{attack_total} = {attack_pass/attack_total*100:.1f}% " +
      f"(lower is better)" if attack_total > 0 else "")
    a(f"- Resource impact on 1H1G: {'Manageable' if max_load < 4 and max_mem < 80 else 'HIGH - check if sustainable'}")

    report_text = "\n".join(report_lines)
    print("\n" + report_text)

    # Save files
    with open("/tmp/shield_test_report.txt", "w") as f:
        f.write(report_text)

    json_data = {
        "test_duration_s": test_duration,
        "total_requests": len(results.results),
        "baseline": baseline,
        "final": final_res,
        "cpu_samples": results.cpu_samples,
        "normal_pass_rate": normal_pass_rate,
        "attack_interception_rate": attack_interception_rate,
        "normal_result": normal_result,
        "ddos_cc_result": ddos_cc_result,
        "group_summary": {k: dict(v) for k, v in groups.items()},
        "attack_type_summary": {k: dict(v) for k, v in attack_types.items()},
        "blocked_normal_ips": sorted(list(normal_blocked_ips)),
        "challenged_normal_ips": sorted(list(normal_challenged_ips)),
        "log_modules": dict(log_labels),
    }
    with open("/tmp/shield_test_results.json", "w") as f:
        json.dump(json_data, f, indent=2)

    print(f"\nReport: /tmp/shield_test_report.txt")
    print(f"JSON:   /tmp/shield_test_results.json")
    return json_data


if __name__ == "__main__":
    asyncio.run(main())
