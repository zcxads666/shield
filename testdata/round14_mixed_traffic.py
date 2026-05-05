#!/usr/bin/env python3
"""
Round 14 RedTeam - Large-scale Mixed Traffic Test
Tests DDoS/CC fusion tag strategy: can WAF distinguish normal from attack traffic?

Scenario 1: 100 normal IPs (10.0.1.x) browsing + small penetration attacks (10.0.10.x)
Scenario 2: Large-scale DDoS/CC (10.0.20.x, 10.0.21.x) + 100 new normal IPs (10.0.2.x)
No IP overlap. Time gap between scenarios.
"""

import requests
import threading
import time
import json
import sys
import os
import random
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict

WAF_URL = "http://127.0.0.1:8081"
ADMIN_URL = "http://127.0.0.1:9090"
SHIELD_LOG = "/opt/shield/logs/shield.log"
RESULTS_FILE = "/tmp/round14_results.json"

# Normal browsing paths
NORMAL_PATHS = ["/", "/", "/", "/index.html", "/favicon.ico", "/style.css", "/robots.txt",
                "/about", "/contact", "/api/status", "/images/logo.png"]

# Normal user agents
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
]


class Round14Test:
    def __init__(self):
        self.results = {
            "scenario1": {
                "normal": {"total": 0, "passed": 0, "challenged": 0, "blocked": 0,
                          "ratelimited": 0, "error": 0, "details": []},
                "attacks": {"sqli": [], "xss": [], "upload": [], "bruteforce": []}
            },
            "scenario2": {
                "normal": {"total": 0, "passed": 0, "challenged": 0, "blocked": 0,
                          "ratelimited": 0, "error": 0, "details": []},
                "ddos_cc": {"total": 0, "blocked": 0, "challenged": 0, "passed_through": 0,
                           "ratelimited": 0, "block_reasons": defaultdict(int), "details": []}
            },
            "metrics": {}
        }
        self.lock = threading.Lock()

    def get_metrics(self):
        try:
            r = requests.get(f"{ADMIN_URL}/stats", timeout=5)
            if r.status_code == 200:
                return r.json()
        except:
            pass
        return {}

    def classify(self, resp):
        if resp is None:
            return "error", ""
        s = resp.status_code
        reason = resp.headers.get("X-Block-Reason", "")
        txt = resp.text[:1000] if resp.text else ""
        is_challenge = "Verifying your browser" in txt or "Checking browser environment" in txt
        if s == 403:
            if is_challenge:
                return "challenged", reason
            return "blocked", reason
        if s == 429:
            if is_challenge:
                return "challenged", reason
            return "ratelimited", reason
        if s == 200:
            if is_challenge:
                return "challenged", reason
            return "passed", ""
        if 500 <= s < 600:
            return "error", ""
        return f"other_{s}", reason

    def session(self, ip):
        s = requests.Session()
        s.headers.update({
            "User-Agent": random.choice(USER_AGENTS),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "X-Forwarded-For": ip,
            "X-Real-IP": ip,
        })
        return s

    # ---- Normal user simulation ----
    def normal_user(self, ip, num_reqs=4):
        """Simulate a normal browsing session from an IP."""
        s = self.session(ip)
        results = []
        visited = set()
        for _ in range(num_reqs):
            path = random.choice(NORMAL_PATHS)
            while path in visited and len(visited) < len(NORMAL_PATHS):
                path = random.choice(NORMAL_PATHS)
            visited.add(path)
            try:
                resp = s.get(f"{WAF_URL}{path}", timeout=15, allow_redirects=False)
                cls, reason = self.classify(resp)
                results.append((cls, reason))
            except Exception as e:
                results.append(("error", str(e)))
            time.sleep(random.uniform(0.3, 0.8))  # Human-like delay
        return ip, results

    def run_normal_batch(self, ips, label="scenario1"):
        """Run normal users in parallel threads."""
        data = self.results[label]["normal"]
        data["total"] = len(ips)

        with ThreadPoolExecutor(max_workers=30) as ex:
            futures = {ex.submit(self.normal_user, ip, random.randint(3, 5)): ip for ip in ips}
            for f in as_completed(futures):
                ip, req_results = f.result()
                outcomes = [r[0] for r in req_results]
                if "blocked" in outcomes:
                    final = "blocked"
                elif "ratelimited" in outcomes:
                    final = "ratelimited"
                elif "challenged" in outcomes:
                    final = "challenged"
                elif "error" in outcomes:
                    final = "error"
                else:
                    final = "passed"
                with self.lock:
                    data[final] += 1
                    data["details"].append({
                        "ip": ip, "final": final, "outcomes": outcomes
                    })

    # ---- Attack payloads ----
    def run_sqli(self, ip):
        payloads = [
            "/?id=1'+UNION+SELECT+1,2,3--",
            "/?id=1'+AND+1=1--",
            "/?id=1'+AND+extractvalue(1,concat(0x7e,database()))--",
            "/?q=1'+OR+'1'='1",
            "/?search=admin'--",
            "/?id=1'+AND+(SELECT+*+FROM+(SELECT(SLEEP(3)))a)--",
            "/?id=1/**/UNION/**/SELECT/**/1,2,3--",
            "/?id=1%27%20UNION%20SELECT%20*%20FROM%20users--",
        ]
        results = []
        s = self.session(ip)
        s.headers["User-Agent"] = "sqlmap/1.0"
        for path in payloads:
            try:
                resp = s.get(f"{WAF_URL}{path}", timeout=10, allow_redirects=False)
                cls, reason = self.classify(resp)
                results.append({"ip": ip, "payload": path, "cls": cls, "reason": reason})
            except Exception as e:
                results.append({"ip": ip, "payload": path, "cls": "error", "reason": str(e)})
            time.sleep(0.1)
        return "sqli", results

    def run_xss(self, ip):
        payloads = [
            "/?q=<script>alert(1)</script>",
            "/?name=<img+src=x+onerror=alert(1)>",
            "/?search=<svg/onload=alert(1)>",
            "/?data=javascript:alert(1)",
            "/?x=<body+onload=alert('XSS')>",
            "/?msg=%3Cscript%3Ealert(1)%3C/script%3E",
            "/?html=<iframe+src=javascript:alert(1)>",
        ]
        results = []
        s = self.session(ip)
        s.headers["User-Agent"] = "<script>alert(1)</script>"
        for path in payloads:
            try:
                resp = s.get(f"{WAF_URL}{path}", timeout=10, allow_redirects=False)
                cls, reason = self.classify(resp)
                results.append({"ip": ip, "payload": path, "cls": cls, "reason": reason})
            except Exception as e:
                results.append({"ip": ip, "payload": path, "cls": "error", "reason": str(e)})
            time.sleep(0.1)
        return "xss", results

    def run_upload(self, ip):
        tests = [
            ("/upload.php", b"<?php system($_GET['cmd']); ?>", "shell.php", "application/x-php"),
            ("/upload.php", b"GIF89a<?php system($_GET['cmd']); ?>", "img.php", "image/gif"),
            ("/api/upload", b"<% Runtime.getRuntime().exec(request.getParameter('cmd')); %>",
             "test.jsp", "application/octet-stream"),
            ("/upload", b"<?php eval($_POST['code']); ?>", "backdoor.php5", "application/x-httpd-php"),
            ("/file/upload", b"<?=system($_GET[0])?>", "cmd.php", "text/plain"),
        ]
        results = []
        s = self.session(ip)
        for path, content, fname, mime in tests:
            try:
                resp = s.post(f"{WAF_URL}{path}", files={"file": (fname, content, mime)},
                              timeout=10, allow_redirects=False)
                cls, reason = self.classify(resp)
                results.append({"ip": ip, "payload": fname, "path": path, "cls": cls, "reason": reason})
            except Exception as e:
                results.append({"ip": ip, "payload": fname, "path": path, "cls": "error", "reason": str(e)})
            time.sleep(0.15)
        return "upload", results

    def run_bruteforce(self, ip):
        """Brute force login attempts."""
        pws = ["admin", "123456", "password", "admin123", "root", "test", "qwerty", "letmein"]
        paths = ["/login", "/admin", "/api/login", "/api/auth", "/signin"]
        results = []
        s = self.session(ip)
        for path in paths:
            for pw in pws[:4]:
                try:
                    resp = s.post(f"{WAF_URL}{path}",
                                  data={"username": "admin", "password": pw},
                                  timeout=10, allow_redirects=False)
                    cls, reason = self.classify(resp)
                    results.append({"ip": ip, "payload": f"{path} pw={pw}", "cls": cls, "reason": reason})
                except Exception as e:
                    results.append({"ip": ip, "payload": f"{path} pw={pw}", "cls": "error", "reason": str(e)})
                time.sleep(0.05)
        return "bruteforce", results

    def run_penetration_attacks(self):
        """Run small-scale penetration attacks from unique IPs."""
        attacks = []
        # SQLi: 10.0.10.1 - 10.0.10.7
        for i in range(1, 8):
            attacks.append((f"10.0.10.{i}", self.run_sqli))
        # XSS: 10.0.10.11 - 10.0.10.15
        for i in range(11, 16):
            attacks.append((f"10.0.10.{i}", self.run_xss))
        # Upload: 10.0.10.21 - 10.0.10.25
        for i in range(21, 26):
            attacks.append((f"10.0.10.{i}", self.run_upload))
        # Brute force: 10.0.10.31 - 10.0.10.35
        for i in range(31, 36):
            attacks.append((f"10.0.10.{i}", self.run_bruteforce))

        with ThreadPoolExecutor(max_workers=10) as ex:
            futures = {ex.submit(fn, ip): (ip, fn.__name__) for ip, fn in attacks}
            for f in as_completed(futures):
                atype, results = f.result()
                with self.lock:
                    self.results["scenario1"]["attacks"][atype].extend(results)

    # ---- DDoS/CC workers ----
    def cc_worker(self, ip, duration_sec, rate):
        """HTTP flood from one attack IP."""
        s = self.session(ip)
        s.headers.update({"User-Agent": f"AttackBot-{ip}/1.0",
                          "Accept": "*/*",
                          "Connection": "keep-alive"})
        paths = ["/", "/index.html", "/api/data", "/search?q=test", "/login",
                 "/admin", "/api/v1/users", "/images/logo.png", "/css/main.css",
                 "/js/app.js", "/api/status", "/wp-admin", "/.env", "/config.php"]
        results = []
        end = time.time() + duration_sec
        while time.time() < end:
            path = random.choice(paths)
            try:
                resp = s.get(f"{WAF_URL}{path}", timeout=10, allow_redirects=False)
                cls, reason = self.classify(resp)
                results.append({"ip": ip, "path": path, "cls": cls, "reason": reason})
            except:
                results.append({"ip": ip, "path": path, "cls": "error", "reason": ""})
            time.sleep(1.0 / rate)
        return results

    def run_scenario2_attack(self):
        """Large-scale distributed DDoS/CC from 200 attack IPs."""
        # 200 attack IPs across two /24 subnets
        attack_ips = [f"10.0.20.{i}" for i in range(1, 101)] + \
                     [f"10.0.21.{i}" for i in range(1, 101)]

        all_results = []
        # Split into batches for staggered launch
        batches = [attack_ips[i:i+50] for i in range(0, len(attack_ips), 50)]

        with ThreadPoolExecutor(max_workers=200) as ex:
            futures = []
            # Batch 0: 50 IPs @ 15 rps -> 750 RPS
            for ip in batches[0]:
                futures.append(ex.submit(self.cc_worker, ip, 90, 15))
            time.sleep(2)

            # Batch 1: 50 IPs @ 12 rps -> 600 RPS (total 1350)
            for ip in batches[1]:
                futures.append(ex.submit(self.cc_worker, ip, 90, 12))
            time.sleep(2)

            # Batch 2: 50 IPs @ 10 rps -> 500 RPS (total 1850)
            for ip in batches[2]:
                futures.append(ex.submit(self.cc_worker, ip, 90, 10))
            time.sleep(2)

            # Batch 3: 50 IPs @ 10 rps -> 500 RPS (total ~2350)
            for ip in batches[3]:
                futures.append(ex.submit(self.cc_worker, ip, 90, 10))

            # Collect results
            for f in as_completed(futures):
                try:
                    results = f.result()
                    with self.lock:
                        all_results.extend(results)
                except:
                    pass

        # Aggregate
        ddos_data = self.results["scenario2"]["ddos_cc"]
        for r in all_results:
            ddos_data["total"] += 1
            cls = r["cls"]
            reason = r["reason"]
            ddos_data["details"].append(r)
            if cls == "blocked":
                ddos_data["blocked"] += 1
            elif cls == "challenged":
                ddos_data["challenged"] += 1
            elif cls == "passed":
                ddos_data["passed_through"] += 1
            elif cls == "ratelimited":
                ddos_data["ratelimited"] += 1
            ddos_data["block_reasons"][reason] += 1

    # ---- Analysis ----
    def analyze_logs(self):
        """Extract attack type labeling from Shield logs."""
        try:
            with open(SHIELD_LOG, 'r') as f:
                lines = f.readlines()[-8000:]
            entries = []
            for line in lines:
                line = line.strip()
                if line:
                    try:
                        entries.append(json.loads(line))
                    except:
                        pass

            type_counts = defaultdict(int)
            for e in entries:
                at = e.get("attack_type", e.get("type", ""))
                reason = str(e.get("reason", ""))
                message = str(e.get("message", ""))
                block_reason = str(e.get("block_reason", ""))
                combined = f"{at} {reason} {message} {block_reason}".lower()

                if at:
                    type_counts[at] += 1
                elif "sql" in combined:
                    type_counts["sql_injection_identified"] += 1
                elif "xss" in combined:
                    type_counts["xss_identified"] += 1
                elif "upload" in combined or "webshell" in combined:
                    type_counts["upload_identified"] += 1
                elif "brute" in combined:
                    type_counts["brute_force_identified"] += 1
                elif "ddos" in combined or "cc" in combined:
                    type_counts["ddos_cc_identified"] += 1

            return dict(type_counts)
        except Exception as e:
            return {"error": str(e)}

    def generate_report(self):
        s1n = self.results["scenario1"]["normal"]
        s2n = self.results["scenario2"]["normal"]
        s2a = self.results["scenario2"]["ddos_cc"]
        s1a = self.results["scenario1"]["attacks"]

        def pct(part, total):
            return (part / max(total, 1)) * 100

        # Attack summaries
        sqli = s1a["sqli"]
        xss = s1a["xss"]
        upload = s1a["upload"]
        bf = s1a["bruteforce"]

        sqli_blocked = sum(1 for a in sqli if a["cls"] in ("blocked", "challenged", "ratelimited"))
        xss_blocked = sum(1 for a in xss if a["cls"] in ("blocked", "challenged", "ratelimited"))
        upload_blocked = sum(1 for a in upload if a["cls"] in ("blocked", "challenged", "ratelimited"))
        bf_blocked = sum(1 for a in bf if a["cls"] in ("blocked", "challenged", "ratelimited"))

        # Type recognition
        sqli_recog = sum(1 for a in sqli if a["reason"] and "sql" in a["reason"].lower())
        xss_recog = sum(1 for a in xss if a["reason"] and "xss" in a["reason"].lower())
        upload_recog = sum(1 for a in upload if a["reason"] and ("upload" in a["reason"].lower() or "webshell" in a["reason"].lower()))
        bf_recog = sum(1 for a in bf if a["reason"] and "brute" in a["reason"].lower())

        # Block reasons for DDoS/CC
        reason_lines = "\n".join(
            f"  - `{r}`: {c}" for r, c in
            sorted(s2a["block_reasons"].items(), key=lambda x: -x[1])[:15]
        )

        log_types = self.analyze_logs()
        log_type_lines = "\n".join(f"  - {k}: {v}" for k, v in sorted(log_types.items()))

        s1_success = s1n["passed"] + s1n["challenged"]
        s1_success_rate = pct(s1_success, s1n["total"])
        s1_fp = pct(s1n["blocked"] + s1n["ratelimited"], s1n["total"])

        s2_success = s2n["passed"] + s2n["challenged"]
        s2_success_rate = pct(s2_success, s2n["total"])
        s2_fp = pct(s2n["blocked"], s2n["total"])

        s2_intercept = s2a["blocked"] + s2a["challenged"] + s2a["ratelimited"]
        s2_intercept_rate = pct(s2_intercept, s2a["total"])

        metric_lines = ""
        for k, v in self.results.get("metrics", {}).items():
            metric_lines += f"  - **{k}**: {json.dumps(v)}\n"

        report = f"""
# Round 14 — 大规模混合流量测试报告

## 测试概述
验证Shield WAF的DDoS/CC融合标签策略在高并发场景下能否正确区分正常流量与攻击流量。

---

## 场景一：正常流量 + 小规模渗透攻击

### 1A. 100个正常IP (10.0.1.1 - 10.0.1.100)

| 指标 | 数量 | 占比 |
|------|------|------|
| 总IP数 | {s1n['total']} | 100% |
| 通过（到达后端） | {s1n['passed']} | {pct(s1n['passed'], s1n['total']):.1f}% |
| JS挑战 | {s1n['challenged']} | {pct(s1n['challenged'], s1n['total']):.1f}% |
| 直接拦截(403) | {s1n['blocked']} | {pct(s1n['blocked'], s1n['total']):.1f}% |
| 频率限制(429) | {s1n['ratelimited']} | {pct(s1n['ratelimited'], s1n['total']):.1f}% |
| 错误 | {s1n['error']} | {pct(s1n['error'], s1n['total']):.1f}% |

**成功率 (通过+挑战): {s1_success}/{s1n['total']} = {s1_success_rate:.1f}%** {"✅ 通过 (≥95%)" if s1_success_rate >= 95 else "❌ 未通过 (<95%)"}
**误杀率 (直接拦截): {s1_fp:.1f}%**

### 1B. 渗透攻击 (独立IP: 10.0.10.x)

| 攻击类型 | 测试数 | 拦截/挑战 | 穿透 | 拦截率 | 类型识别正确 |
|----------|--------|-----------|------|--------|--------------|
| SQL注入 | {len(sqli)} | {sqli_blocked} | {len(sqli)-sqli_blocked} | {pct(sqli_blocked, len(sqli)):.1f}% | {sqli_recog}/{len(sqli)} |
| XSS | {len(xss)} | {xss_blocked} | {len(xss)-xss_blocked} | {pct(xss_blocked, len(xss)):.1f}% | {xss_recog}/{len(xss)} |
| 文件上传 | {len(upload)} | {upload_blocked} | {len(upload)-upload_blocked} | {pct(upload_blocked, len(upload)):.1f}% | {upload_recog}/{len(upload)} |
| 爆破 | {len(bf)} | {bf_blocked} | {len(bf)-bf_blocked} | {pct(bf_blocked, len(bf)):.1f}% | {bf_recog}/{len(bf)} |

---

## 场景二：大规模DDoS/CC + 100正常IP（混合流量）

### 2A. 攻击期间正常IP (10.0.2.1 - 10.0.2.100)

| 指标 | 数量 | 占比 |
|------|------|------|
| 总IP数 | {s2n['total']} | 100% |
| 通过（到达后端） | {s2n['passed']} | {pct(s2n['passed'], s2n['total']):.1f}% |
| JS挑战 | {s2n['challenged']} | {pct(s2n['challenged'], s2n['total']):.1f}% |
| 直接拦截(403) | {s2n['blocked']} | {pct(s2n['blocked'], s2n['total']):.1f}% |
| 频率限制(429) | {s2n['ratelimited']} | {pct(s2n['ratelimited'], s2n['total']):.1f}% |
| 错误 | {s2n['error']} | {pct(s2n['error'], s2n['total']):.1f}% |

**成功率 (通过+挑战): {s2_success}/{s2n['total']} = {s2_success_rate:.1f}%** {"✅ 通过 (≥95%)" if s2_success_rate >= 95 else "❌ 未通过 (<95%)"}
**误杀率 (直接拦截): {s2_fp:.1f}%**

### 2B. DDoS/CC攻击流量 (200个攻击IP: 10.0.20.x, 10.0.21.x)

| 指标 | 数值 |
|------|------|
| 总攻击请求 | {s2a['total']} |
| 拦截(403) | {s2a['blocked']} |
| JS挑战(200) | {s2a['challenged']} |
| 频率限制(429) | {s2a['ratelimited']} |
| 穿透 | {s2a['passed_through']} |

**拦截率: {s2_intercept}/{s2a['total']} = {s2_intercept_rate:.1f}%** {"✅ 通过 (≥80%)" if s2_intercept_rate >= 80 else "❌ 未通过 (<80%)"}

#### 拦截原因分布
{reason_lines if reason_lines else '  (无拦截)'}

---

## 日志攻击类型统计 (Shield Logs)
{log_type_lines if log_type_lines else '  (无匹配日志)'}

---

## 综合判定

### 正常流量保护
- **场景一成功率**: {s1_success_rate:.1f}% {"✅" if s1_success_rate >= 95 else "❌"}
- **场景二成功率**: {s2_success_rate:.1f}% {"✅" if s2_success_rate >= 95 else "❌"}

### 攻击流量拦截
- **场景二DDoS/CC拦截率**: {s2_intercept_rate:.1f}% {"✅" if s2_intercept_rate >= 80 else "❌"}
- **场景一攻击拦截率**:
  - SQL注入: {pct(sqli_blocked, len(sqli)):.1f}%
  - XSS: {pct(xss_blocked, len(xss)):.1f}%
  - 文件上传: {pct(upload_blocked, len(upload)):.1f}%
  - 爆破: {pct(bf_blocked, len(bf)):.1f}%

### 攻击类型识别
- SQL注入识别: {sqli_recog}/{len(sqli)} — 拦截响应中 `X-Block-Reason` 是否含 "sql"
- XSS识别: {xss_recog}/{len(xss)} — 拦截响应中 `X-Block-Reason` 是否含 "xss"
- 文件上传识别: {upload_recog}/{len(upload)} — 拦截响应中 `X-Block-Reason` 是否含 "upload"
- 爆破识别: {bf_recog}/{len(bf)} — 拦截响应中 `X-Block-Reason` 是否含 "brute"

### 指标快照
{metric_lines}

---
**测试时间**: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}
**测试Agent**: RedTeam (Round 14)
"""

        return report


def main():
    tester = Round14Test()

    print("=" * 60)
    print("ROUND 14 — MIXED TRAFFIC TEST")
    print("=" * 60)

    # Baseline
    m0 = tester.get_metrics()
    tester.results["metrics"]["baseline"] = m0
    print(f"\nBaseline metrics: {json.dumps(m0)}")

    # ================================================================
    # SCENARIO 1
    # ================================================================
    print("\n\n>>> SCENARIO 1: 100 Normal IPs (10.0.1.x)")
    s1_ips = [f"10.0.1.{i}" for i in range(1, 101)]
    tester.run_normal_batch(s1_ips, "scenario1")

    print(f"  Passed: {tester.results['scenario1']['normal']['passed']}, "
          f"Challenged: {tester.results['scenario1']['normal']['challenged']}, "
          f"Blocked: {tester.results['scenario1']['normal']['blocked']}")

    print("\n>>> SCENARIO 1: Penetration Attacks (10.0.10.x)")
    tester.run_penetration_attacks()
    sqli_n = len(tester.results["scenario1"]["attacks"]["sqli"])
    xss_n = len(tester.results["scenario1"]["attacks"]["xss"])
    upload_n = len(tester.results["scenario1"]["attacks"]["upload"])
    bf_n = len(tester.results["scenario1"]["attacks"]["bruteforce"])
    print(f"  SQLi: {sqli_n}, XSS: {xss_n}, Upload: {upload_n}, BruteForce: {bf_n}")

    m1 = tester.get_metrics()
    tester.results["metrics"]["after_s1"] = m1
    print(f"After Scenario 1 metrics: {json.dumps(m1)}")

    # ================================================================
    # INTERVAL (60s gap)
    # ================================================================
    print("\n\n>>> Waiting 60 seconds between scenarios...")
    for i in range(6, 0, -1):
        print(f"  {i*10}s remaining...")
        time.sleep(10)

    # ================================================================
    # SCENARIO 2
    # ================================================================
    m2a = tester.get_metrics()
    tester.results["metrics"]["before_s2"] = m2a
    print(f"\nBefore Scenario 2 metrics: {json.dumps(m2a)}")

    print("\n\n>>> SCENARIO 2: Launching DDoS/CC Attack (200 IPs: 10.0.20.x, 10.0.21.x)")

    # Start DDoS/CC attack in separate thread
    attack_thread = threading.Thread(target=tester.run_scenario2_attack)
    attack_thread.start()

    # Wait a bit for attack to ramp up
    time.sleep(10)
    print("  Attack launched, now sending normal traffic during attack...")

    # Run normal traffic during the attack (100 new IPs: 10.0.2.x)
    s2_ips = [f"10.0.2.{i}" for i in range(1, 101)]
    tester.run_normal_batch(s2_ips, "scenario2")

    print(f"  Normal during attack: Passed={tester.results['scenario2']['normal']['passed']}, "
          f"Challenged={tester.results['scenario2']['normal']['challenged']}, "
          f"Blocked={tester.results['scenario2']['normal']['blocked']}")

    # Wait for attack to finish
    print("  Waiting for attack to complete...")
    attack_thread.join(timeout=180)

    m2b = tester.get_metrics()
    tester.results["metrics"]["after_s2"] = m2b
    print(f"After Scenario 2 metrics: {json.dumps(m2b)}")

    # ================================================================
    # REPORT
    # ================================================================
    report = tester.generate_report()
    print("\n" + report)

    # Save results
    with open(RESULTS_FILE, 'w') as f:
        clean = json.loads(json.dumps(tester.results, default=str))
        json.dump(clean, f, indent=2)
    print(f"\nResults saved to {RESULTS_FILE}")

    # Print report to stdout for capture
    print("\n===REPORT_START===")
    print(report)
    print("===REPORT_END===")

    return report


if __name__ == "__main__":
    main()
