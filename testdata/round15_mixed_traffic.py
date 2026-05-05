#!/usr/bin/env python3
"""
Round 15 RedTeam - Large-scale Mixed Traffic Test
Tests DDoS/CC fusion tag strategy: can WAF distinguish normal from attack traffic?

Scenario 1: 100 normal IPs (10.0.3.x) browsing + penetration attacks (10.0.11.x - 10.0.14.x)
Scenario 2: Large-scale DDoS/CC (10.0.30.x, 10.0.31.x, 10.0.32.x) + 100 new normal IPs (10.0.4.x)
No IP overlap. Time gap between scenarios. Targets 4H4G consumption level.
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
RESULTS_FILE = "/tmp/round15_results.json"

NORMAL_PATHS = ["/", "/", "/", "/index.html", "/favicon.ico", "/style.css", "/robots.txt",
                "/about", "/contact", "/api/status", "/images/logo.png"]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
]


class Round15Test:
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
            "metrics": {},
            "attack_type_recognition": defaultdict(lambda: {"correct": 0, "wrong": 0, "unknown": 0})
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
        block_type = resp.headers.get("X-Attack-Type", "")
        txt = resp.text[:2000] if resp.text else ""
        is_challenge = "Verifying your browser" in txt or "Checking browser environment" in txt or "cf-challenge" in txt.lower() or "_cf_chl" in txt
        is_captcha = "captcha" in txt.lower() or "recaptcha" in txt.lower()
        if s == 403:
            if is_challenge or is_captcha:
                return "challenged", reason, block_type
            return "blocked", reason, block_type
        if s == 429:
            if is_challenge:
                return "challenged", reason, block_type
            return "ratelimited", reason, block_type
        if s == 503:
            return "blocked", reason, block_type
        if s == 200:
            if is_challenge:
                return "challenged", reason, block_type
            return "passed", "", ""
        if 500 <= s < 600:
            return "error", "", ""
        return f"other_{s}", reason, block_type

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
    def normal_user(self, ip, num_reqs=5):
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
                cls, reason, btype = self.classify(resp)
                results.append((cls, reason, btype))
            except Exception as e:
                results.append(("error", str(e), ""))
            time.sleep(random.uniform(0.3, 0.8))
        return ip, results

    def run_normal_batch(self, ips, label="scenario1"):
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
                cls, reason, btype = self.classify(resp)
                results.append({"ip": ip, "payload": path, "cls": cls, "reason": reason, "attack_type_header": btype})
            except Exception as e:
                results.append({"ip": ip, "payload": path, "cls": "error", "reason": str(e), "attack_type_header": ""})
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
            "/?input=<a+href='javascript:alert(1)'>click</a>",
        ]
        results = []
        s = self.session(ip)
        s.headers["User-Agent"] = "<script>alert(1)</script>"
        for path in payloads:
            try:
                resp = s.get(f"{WAF_URL}{path}", timeout=10, allow_redirects=False)
                cls, reason, btype = self.classify(resp)
                results.append({"ip": ip, "payload": path, "cls": cls, "reason": reason, "attack_type_header": btype})
            except Exception as e:
                results.append({"ip": ip, "payload": path, "cls": "error", "reason": str(e), "attack_type_header": ""})
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
            ("/wp-content/upload", b"<?php @eval($_POST['pass']);?>", "wp-shell.phtml", "image/jpeg"),
        ]
        results = []
        s = self.session(ip)
        for path, content, fname, mime in tests:
            try:
                resp = s.post(f"{WAF_URL}{path}", files={"file": (fname, content, mime)},
                              timeout=10, allow_redirects=False)
                cls, reason, btype = self.classify(resp)
                results.append({"ip": ip, "payload": fname, "path": path, "cls": cls, "reason": reason, "attack_type_header": btype})
            except Exception as e:
                results.append({"ip": ip, "payload": fname, "path": path, "cls": "error", "reason": str(e), "attack_type_header": ""})
            time.sleep(0.15)
        return "upload", results

    def run_bruteforce(self, ip):
        pws = ["admin", "123456", "password", "admin123", "root", "test", "qwerty", "letmein", "passw0rd", "abc123"]
        paths = ["/login", "/admin", "/api/login", "/api/auth", "/signin"]
        results = []
        s = self.session(ip)
        for path in paths:
            for pw in pws[:5]:
                try:
                    resp = s.post(f"{WAF_URL}{path}",
                                  data={"username": "admin", "password": pw},
                                  timeout=10, allow_redirects=False)
                    cls, reason, btype = self.classify(resp)
                    results.append({"ip": ip, "payload": f"{path} pw={pw}", "cls": cls, "reason": reason, "attack_type_header": btype})
                except Exception as e:
                    results.append({"ip": ip, "payload": f"{path} pw={pw}", "cls": "error", "reason": str(e), "attack_type_header": ""})
                time.sleep(0.05)
        return "bruteforce", results

    def run_penetration_attacks(self):
        attacks = []
        # SQLi: 10.0.11.1 - 10.0.11.8
        for i in range(1, 9):
            attacks.append((f"10.0.11.{i}", self.run_sqli))
        # XSS: 10.0.12.1 - 10.0.12.8
        for i in range(1, 9):
            attacks.append((f"10.0.12.{i}", self.run_xss))
        # Upload: 10.0.13.1 - 10.0.13.6
        for i in range(1, 7):
            attacks.append((f"10.0.13.{i}", self.run_upload))
        # Brute force: 10.0.14.1 - 10.0.14.6
        for i in range(1, 7):
            attacks.append((f"10.0.14.{i}", self.run_bruteforce))

        with ThreadPoolExecutor(max_workers=12) as ex:
            futures = {ex.submit(fn, ip): (ip, fn.__name__) for ip, fn in attacks}
            for f in as_completed(futures):
                atype, results = f.result()
                with self.lock:
                    self.results["scenario1"]["attacks"][atype].extend(results)

    # ---- DDoS/CC workers (4H4G level) ----
    def cc_worker(self, ip, duration_sec, rate):
        s = self.session(ip)
        s.headers.update({"User-Agent": f"AttackBot-{ip}/1.0",
                          "Accept": "*/*",
                          "Connection": "keep-alive"})
        paths = ["/", "/index.html", "/api/data", "/search?q=test", "/login",
                 "/admin", "/api/v1/users", "/images/logo.png", "/css/main.css",
                 "/js/app.js", "/api/status", "/wp-admin", "/.env", "/config.php",
                 "/api/v1/products", "/user/profile", "/api/settings", "/backup.zip"]
        results = []
        end = time.time() + duration_sec
        while time.time() < end:
            path = random.choice(paths)
            try:
                resp = s.get(f"{WAF_URL}{path}", timeout=10, allow_redirects=False)
                cls, reason, btype = self.classify(resp)
                results.append({"ip": ip, "path": path, "cls": cls, "reason": reason, "attack_type_header": btype})
            except:
                results.append({"ip": ip, "path": path, "cls": "error", "reason": "", "attack_type_header": ""})
            time.sleep(1.0 / rate)
        return results

    def run_scenario2_attack(self):
        # 300 attack IPs across three /24 subnets for 4H4G level
        attack_ips = [f"10.0.30.{i}" for i in range(1, 101)] + \
                     [f"10.0.31.{i}" for i in range(1, 101)] + \
                     [f"10.0.32.{i}" for i in range(1, 101)]

        all_results = []
        batches = [attack_ips[i:i+50] for i in range(0, len(attack_ips), 50)]

        with ThreadPoolExecutor(max_workers=300) as ex:
            futures = []
            # Batch 0-1: 100 IPs @ 20 rps -> 2000 RPS
            for batch in [batches[0], batches[1]]:
                for ip in batch:
                    futures.append(ex.submit(self.cc_worker, ip, 120, 20))
                time.sleep(2)

            # Batch 2-3: 100 IPs @ 15 rps -> 1500 RPS (total ~3500)
            for batch in [batches[2], batches[3]]:
                for ip in batch:
                    futures.append(ex.submit(self.cc_worker, ip, 120, 15))
                time.sleep(2)

            # Batch 4-5: 100 IPs @ 12 rps -> 1200 RPS (total ~4700)
            for batch in [batches[4], batches[5]]:
                for ip in batch:
                    futures.append(ex.submit(self.cc_worker, ip, 120, 12))

            for f in as_completed(futures):
                try:
                    results = f.result()
                    with self.lock:
                        all_results.extend(results)
                except:
                    pass

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

    # ---- Attack type recognition analysis ----
    def analyze_attack_recognition(self):
        """Analyze if blocked attacks had correct type labeling."""
        recog = defaultdict(lambda: {"correct": 0, "wrong": 0, "unknown": 0, "details": []})

        for atype in ["sqli", "xss", "upload", "bruteforce"]:
            attacks = self.results["scenario1"]["attacks"][atype]
            for a in attacks:
                cls = a["cls"]
                reason = a.get("reason", "").lower()
                header_type = a.get("attack_type_header", "").lower()
                combined = f"{reason} {header_type}"

                type_map = {
                    "sqli": ["sql", "sqli", "sql_injection", "injection"],
                    "xss": ["xss", "cross_site", "cross-site", "script"],
                    "upload": ["upload", "webshell", "file_upload", "malicious_file"],
                    "bruteforce": ["brute", "bruteforce", "login_attempt", "credential"],
                }

                expected = type_map.get(atype, [])
                if cls in ("blocked", "challenged", "ratelimited"):
                    matched = any(kw in combined for kw in expected)
                    if matched:
                        recog[atype]["correct"] += 1
                        recog[atype]["details"].append({"correct": True, "reason": reason, "header": header_type})
                    elif cls == "blocked" and not reason:
                        recog[atype]["unknown"] += 1
                        recog[atype]["details"].append({"correct": False, "reason": "no_reason", "header": header_type})
                    else:
                        recog[atype]["wrong"] += 1
                        recog[atype]["details"].append({"correct": False, "reason": reason, "header": header_type})

        # Also check DDoS/CC recognition from scenario 2 attack traffic
        ddos_cc = self.results["scenario2"]["ddos_cc"]["details"]
        for r in ddos_cc:
            if r["cls"] in ("blocked", "challenged", "ratelimited"):
                reason = r.get("reason", "").lower()
                header_type = r.get("attack_type_header", "").lower()
                combined = f"{reason} {header_type}"
                ddos_kw = ["ddos", "cc", "flood", "rate_limit", "distributed", "dos", "traffic_anomaly"]
                matched = any(kw in combined for kw in ddos_kw)
                if matched:
                    recog["ddos_cc"]["correct"] += 1
                elif not reason and not header_type:
                    recog["ddos_cc"]["unknown"] += 1
                else:
                    recog["ddos_cc"]["wrong"] += 1

        return dict(recog)

    # ---- Shield log analysis ----
    def analyze_logs(self):
        try:
            with open(SHIELD_LOG, 'r') as f:
                lines = f.readlines()[-10000:]
            entries = []
            for line in lines:
                line = line.strip()
                if line:
                    try:
                        entries.append(json.loads(line))
                    except:
                        pass

            type_counts = defaultdict(int)
            block_logs = []
            for e in entries:
                at = e.get("attack_type", e.get("type", ""))
                reason = str(e.get("reason", ""))
                message = str(e.get("message", ""))
                block_reason = str(e.get("block_reason", ""))
                combined = f"{at} {reason} {message} {block_reason}".lower()

                if at:
                    type_counts[at] += 1
                elif "sql" in combined or "sqli" in combined:
                    type_counts["sql_injection_identified"] += 1
                elif "xss" in combined:
                    type_counts["xss_identified"] += 1
                elif "upload" in combined or "webshell" in combined or "file" in combined:
                    type_counts["upload_identified"] += 1
                elif "brute" in combined:
                    type_counts["brute_force_identified"] += 1
                elif "ddos" in combined or "cc" in combined or "flood" in combined or "distributed" in combined:
                    type_counts["ddos_cc_identified"] += 1

                # Collect block entries for detailed analysis
                if at or reason or block_reason:
                    block_logs.append({
                        "attack_type": at,
                        "reason": reason,
                        "block_reason": block_reason,
                        "message": message[:200]
                    })

            return dict(type_counts), block_logs
        except Exception as e:
            return {"error": str(e)}, []

    def generate_report(self):
        s1n = self.results["scenario1"]["normal"]
        s2n = self.results["scenario2"]["normal"]
        s2a = self.results["scenario2"]["ddos_cc"]
        s1a = self.results["scenario1"]["attacks"]

        def pct(part, total):
            return (part / max(total, 1)) * 100

        # Attack type stats
        sqli = s1a["sqli"]
        xss = s1a["xss"]
        upload = s1a["upload"]
        bf = s1a["bruteforce"]

        def count_blocked(attacks):
            return sum(1 for a in attacks if a["cls"] in ("blocked", "challenged", "ratelimited"))

        sqli_blocked = count_blocked(sqli)
        xss_blocked = count_blocked(xss)
        upload_blocked = count_blocked(upload)
        bf_blocked = count_blocked(bf)

        sqli_penetrated = len(sqli) - sqli_blocked
        xss_penetrated = len(xss) - xss_blocked
        upload_penetrated = len(upload) - upload_blocked
        bf_penetrated = len(bf) - bf_blocked

        # Type recognition
        recog = self.analyze_attack_recognition()

        # DDoS/CC reasons
        reason_lines = "\n".join(
            f"  - `{r}`: {c}" for r, c in
            sorted(s2a["block_reasons"].items(), key=lambda x: -x[1])[:15]
        )

        log_types, block_logs = self.analyze_logs()
        log_type_lines = "\n".join(f"  - {k}: {v}" for k, v in sorted(log_types.items()))

        # Normal traffic success rates
        s1_success = s1n["passed"] + s1n["challenged"]
        s1_success_rate = pct(s1_success, s1n["total"])
        s1_blocked = s1n["blocked"] + s1n["ratelimited"]
        s1_fp_rate = pct(s1_blocked, s1n["total"])

        s2_success = s2n["passed"] + s2n["challenged"]
        s2_success_rate = pct(s2_success, s2n["total"])
        s2_blocked = s2n["blocked"] + s2n["ratelimited"]
        s2_fp_rate = pct(s2_blocked, s2n["total"])

        # DDoS/CC intercept rate (all non-passed = blocked + challenged + ratelimited)
        s2_intercept = s2a["blocked"] + s2a["challenged"] + s2a["ratelimited"]
        s2_intercept_rate = pct(s2_intercept, s2a["total"])
        s2_pass_through = s2a["passed_through"]

        # Metric snapshots
        metric_summary = ""
        for stage, vals in self.results.get("metrics", {}).items():
            if isinstance(vals, dict):
                rps = vals.get("requests_per_second", vals.get("rps", "N/A"))
                blocked = vals.get("blocked_requests", vals.get("blocked", "N/A"))
                metric_summary += f"  - **{stage}**: rps={rps}, blocked={blocked}\n"

        report = f"""# Round 15 — 大规模混合流量测试报告

## 测试概述
验证Shield WAF的DDoS/CC融合标签策略在高并发场景下能否正确区分正常流量与攻击流量。
- 场景一：100个正常IP浏览 + 渗透攻击（独立IP）
- 场景二：300个攻击IP大规模DDoS/CC（目标4H4G级）+ 100个全新正常IP
- 两个场景IP完全独立，无重叠
- 两场景间隔60秒

---

## 场景一：正常流量 + 小规模渗透攻击

### 1A. 100个正常IP (10.0.3.1 - 10.0.3.100)

| 指标 | 数量 | 占比 |
|------|------|------|
| 总IP数 | {s1n['total']} | 100% |
| 通过（到达后端） | {s1n['passed']} | {pct(s1n['passed'], s1n['total']):.1f}% |
| JS挑战 | {s1n['challenged']} | {pct(s1n['challenged'], s1n['total']):.1f}% |
| 直接拦截(403) | {s1n['blocked']} | {pct(s1n['blocked'], s1n['total']):.1f}% |
| 频率限制(429) | {s1n['ratelimited']} | {pct(s1n['ratelimited'], s1n['total']):.1f}% |
| 错误 | {s1n['error']} | {pct(s1n['error'], s1n['total']):.1f}% |

**成功率 (通过+挑战): {s1_success}/{s1n['total']} = {s1_success_rate:.1f}%** {"✅ 通过 (≥95%)" if s1_success_rate >= 95 else "❌ 未通过 (<95%)"}
**误杀率 (直接拦截+频率限制): {s1_fp_rate:.1f}%**
**误杀IP数**: {s1n['blocked'] + s1n['ratelimited']}

### 1B. 渗透攻击 (独立IP: 10.0.11.x - 10.0.14.x)

| 攻击类型 | 测试数 | 拦截数 | 穿透数 | 拦截率 | 识别正确 | 识别错误 | 未识别 |
|----------|--------|--------|--------|--------|----------|----------|--------|
| SQL注入 | {len(sqli)} | {sqli_blocked} | {sqli_penetrated} | {pct(sqli_blocked, len(sqli)):.1f}% | {recog.get('sqli', {}).get('correct', 0)} | {recog.get('sqli', {}).get('wrong', 0)} | {recog.get('sqli', {}).get('unknown', 0)} |
| XSS | {len(xss)} | {xss_blocked} | {xss_penetrated} | {pct(xss_blocked, len(xss)):.1f}% | {recog.get('xss', {}).get('correct', 0)} | {recog.get('xss', {}).get('wrong', 0)} | {recog.get('xss', {}).get('unknown', 0)} |
| 文件上传 | {len(upload)} | {upload_blocked} | {upload_penetrated} | {pct(upload_blocked, len(upload)):.1f}% | {recog.get('upload', {}).get('correct', 0)} | {recog.get('upload', {}).get('wrong', 0)} | {recog.get('upload', {}).get('unknown', 0)} |
| 爆破 | {len(bf)} | {bf_blocked} | {bf_penetrated} | {pct(bf_blocked, len(bf)):.1f}% | {recog.get('bruteforce', {}).get('correct', 0)} | {recog.get('bruteforce', {}).get('wrong', 0)} | {recog.get('bruteforce', {}).get('unknown', 0)} |

---

## 场景二：大规模DDoS/CC + 100正常IP（混合流量）

### 2A. 攻击期间正常IP (10.0.4.1 - 10.0.4.100)

| 指标 | 数量 | 占比 |
|------|------|------|
| 总IP数 | {s2n['total']} | 100% |
| 通过（到达后端） | {s2n['passed']} | {pct(s2n['passed'], s2n['total']):.1f}% |
| JS挑战 | {s2n['challenged']} | {pct(s2n['challenged'], s2n['total']):.1f}% |
| 直接拦截(403) | {s2n['blocked']} | {pct(s2n['blocked'], s2n['total']):.1f}% |
| 频率限制(429) | {s2n['ratelimited']} | {pct(s2n['ratelimited'], s2n['total']):.1f}% |
| 错误 | {s2n['error']} | {pct(s2n['error'], s2n['total']):.1f}% |

**成功率 (通过+挑战): {s2_success}/{s2n['total']} = {s2_success_rate:.1f}%** {"✅ 通过 (≥95%)" if s2_success_rate >= 95 else "❌ 未通过 (<95%)"}
**误杀率 (直接拦截+频率限制): {s2_fp_rate:.1f}%**
**误杀IP数**: {s2n['blocked'] + s2n['ratelimited']}

### 2B. DDoS/CC攻击流量 (300个攻击IP: 10.0.30.x, 10.0.31.x, 10.0.32.x)

| 指标 | 数值 | 占比 |
|------|------|------|
| 总攻击请求 | {s2a['total']} | 100% |
| 拦截(403) | {s2a['blocked']} | {pct(s2a['blocked'], s2a['total']):.1f}% |
| JS挑战(200) | {s2a['challenged']} | {pct(s2a['challenged'], s2a['total']):.1f}% |
| 频率限制(429) | {s2a['ratelimited']} | {pct(s2a['ratelimited'], s2a['total']):.1f}% |
| 穿透(到达后端) | {s2_pass_through} | {pct(s2_pass_through, s2a['total']):.1f}% |

**总拦截率 (拦截+挑战+限流): {s2_intercept}/{s2a['total']} = {s2_intercept_rate:.1f}%** {"✅ 通过 (≥80%)" if s2_intercept_rate >= 80 else "❌ 未通过 (<80%)"}

#### DDoS/CC 类型识别
| 指标 | 数值 |
|------|------|
| 识别正确 | {recog.get('ddos_cc', {}).get('correct', 0)} |
| 识别错误 | {recog.get('ddos_cc', {}).get('wrong', 0)} |
| 未识别 | {recog.get('ddos_cc', {}).get('unknown', 0)} |

#### 拦截原因分布 (Top 15)
{reason_lines if reason_lines else '  (无拦截数据)'}

---

## 日志攻击类型统计 (Shield Logs)
{log_type_lines if log_type_lines else '  (无匹配日志)'}

---

## 攻击类型识别错误清单

### 场景一渗透攻击识别详情
"""
        # Add recognition error details for each attack type
        for atype, label in [("sqli", "SQL注入"), ("xss", "XSS"), ("upload", "文件上传"), ("bruteforce", "爆破")]:
            r = recog.get(atype, {})
            details = r.get("details", [])
            report += f"\n#### {label}\n"
            report += f"- 正确: {r.get('correct', 0)}, 错误: {r.get('wrong', 0)}, 未标注: {r.get('unknown', 0)}\n"
            if details:
                wrong_details = [d for d in details if not d.get("correct")]
                if wrong_details:
                    report += "- 识别错误/未标注示例:\n"
                    for d in wrong_details[:5]:
                        report += f"  - reason=`{d.get('reason','')}`, header=`{d.get('header','')}`\n"

        # Summary metrics
        report += f"""
---

## 综合判定

### 正常流量保护
| 场景 | 成功率 | 误杀率 | 判定 |
|------|--------|--------|------|
| 场景一（无攻击） | {s1_success_rate:.1f}% | {s1_fp_rate:.1f}% | {"✅" if s1_success_rate >= 95 else "❌"} |
| 场景二（攻击中） | {s2_success_rate:.1f}% | {s2_fp_rate:.1f}% | {"✅" if s2_success_rate >= 95 else "❌"} |

### 攻击流量拦截
| 攻击类型 | 拦截率 | 判定 |
|----------|--------|------|
| SQL注入 | {pct(sqli_blocked, len(sqli)):.1f}% | {"✅" if len(sqli) > 0 and pct(sqli_blocked, len(sqli)) >= 80 else "⚠️"} |
| XSS | {pct(xss_blocked, len(xss)):.1f}% | {"✅" if len(xss) > 0 and pct(xss_blocked, len(xss)) >= 80 else "⚠️"} |
| 文件上传 | {pct(upload_blocked, len(upload)):.1f}% | {"✅" if len(upload) > 0 and pct(upload_blocked, len(upload)) >= 80 else "⚠️"} |
| 爆破 | {pct(bf_blocked, len(bf)):.1f}% | {"✅" if len(bf) > 0 and pct(bf_blocked, len(bf)) >= 80 else "⚠️"} |
| DDoS/CC | {s2_intercept_rate:.1f}% | {"✅" if s2_intercept_rate >= 80 else "❌"} |

### 攻击类型识别准确率
| 攻击类型 | 正确 | 错误 | 未标注 | 准确率 |
|----------|------|------|--------|--------|
| SQL注入 | {recog.get('sqli', {}).get('correct', 0)} | {recog.get('sqli', {}).get('wrong', 0)} | {recog.get('sqli', {}).get('unknown', 0)} | {pct(recog.get('sqli', {}).get('correct', 0), recog.get('sqli', {}).get('correct', 0) + recog.get('sqli', {}).get('wrong', 0) + recog.get('sqli', {}).get('unknown', 0)):.1f}% |
| XSS | {recog.get('xss', {}).get('correct', 0)} | {recog.get('xss', {}).get('wrong', 0)} | {recog.get('xss', {}).get('unknown', 0)} | {pct(recog.get('xss', {}).get('correct', 0), recog.get('xss', {}).get('correct', 0) + recog.get('xss', {}).get('wrong', 0) + recog.get('xss', {}).get('unknown', 0)):.1f}% |
| 文件上传 | {recog.get('upload', {}).get('correct', 0)} | {recog.get('upload', {}).get('wrong', 0)} | {recog.get('upload', {}).get('unknown', 0)} | {pct(recog.get('upload', {}).get('correct', 0), recog.get('upload', {}).get('correct', 0) + recog.get('upload', {}).get('wrong', 0) + recog.get('upload', {}).get('unknown', 0)):.1f}% |
| 爆破 | {recog.get('bruteforce', {}).get('correct', 0)} | {recog.get('bruteforce', {}).get('wrong', 0)} | {recog.get('bruteforce', {}).get('unknown', 0)} | {pct(recog.get('bruteforce', {}).get('correct', 0), recog.get('bruteforce', {}).get('correct', 0) + recog.get('bruteforce', {}).get('wrong', 0) + recog.get('bruteforce', {}).get('unknown', 0)):.1f}% |
| DDoS/CC | {recog.get('ddos_cc', {}).get('correct', 0)} | {recog.get('ddos_cc', {}).get('wrong', 0)} | {recog.get('ddos_cc', {}).get('unknown', 0)} | {pct(recog.get('ddos_cc', {}).get('correct', 0), recog.get('ddos_cc', {}).get('correct', 0) + recog.get('ddos_cc', {}).get('wrong', 0) + recog.get('ddos_cc', {}).get('unknown', 0)):.1f}% |

### 指标快照
{metric_summary if metric_summary else '  (无指标数据)'}

### 改进建议
- 若类型识别错误较高，建议增强 X-Attack-Type 响应头标注
- 若正常流量误杀率 > 5%，需调整 DDoS/CC 融合策略的阈值
- 若 DDoS/CC 拦截率 < 80%，考虑降低 global_rate_distributed_threshold

---
**测试时间**: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}
**测试Agent**: RedTeam (Round 15)
**IP范围**:
  - 场景一正常: 10.0.3.1-10.0.3.100
  - 场景一攻击: 10.0.11.x-10.0.14.x
  - 场景二正常: 10.0.4.1-10.0.4.100
  - 场景二攻击: 10.0.30.x-10.0.32.x (300 IPs)
"""

        return report


def main():
    tester = Round15Test()

    print("=" * 60)
    print("ROUND 15 — MIXED TRAFFIC TEST")
    print("=" * 60)

    m0 = tester.get_metrics()
    tester.results["metrics"]["baseline"] = m0
    print(f"\nBaseline metrics: {json.dumps(m0)}")

    # ================================================================
    # SCENARIO 1
    # ================================================================
    print("\n\n>>> SCENARIO 1: 100 Normal IPs (10.0.3.x)")
    s1_ips = [f"10.0.3.{i}" for i in range(1, 101)]
    tester.run_normal_batch(s1_ips, "scenario1")

    s1n = tester.results["scenario1"]["normal"]
    print(f"  Passed: {s1n['passed']}, Challenged: {s1n['challenged']}, "
          f"Blocked: {s1n['blocked']}, RL: {s1n['ratelimited']}, Error: {s1n['error']}")

    print("\n>>> SCENARIO 1: Penetration Attacks (10.0.11.x - 10.0.14.x)")
    tester.run_penetration_attacks()
    s1a = tester.results["scenario1"]["attacks"]
    print(f"  SQLi: {len(s1a['sqli'])}, XSS: {len(s1a['xss'])}, "
          f"Upload: {len(s1a['upload'])}, BruteForce: {len(s1a['bruteforce'])}")

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

    print("\n\n>>> SCENARIO 2: Launching DDoS/CC Attack (300 IPs: 10.0.30.x - 10.0.32.x)")

    attack_thread = threading.Thread(target=tester.run_scenario2_attack)
    attack_thread.start()

    time.sleep(15)
    print("  Attack ramping up, now sending normal traffic during attack...")

    s2_ips = [f"10.0.4.{i}" for i in range(1, 101)]
    tester.run_normal_batch(s2_ips, "scenario2")

    s2n = tester.results["scenario2"]["normal"]
    print(f"  Normal during attack: Passed={s2n['passed']}, Challenged={s2n['challenged']}, "
          f"Blocked={s2n['blocked']}, RL={s2n['ratelimited']}, Error={s2n['error']}")

    print("  Waiting for attack to complete...")
    attack_thread.join(timeout=300)

    m2b = tester.get_metrics()
    tester.results["metrics"]["after_s2"] = m2b
    print(f"After Scenario 2 metrics: {json.dumps(m2b)}")

    # ================================================================
    # REPORT
    # ================================================================
    report = tester.generate_report()
    print("\n" + report)

    with open(RESULTS_FILE, 'w') as f:
        clean = json.loads(json.dumps(tester.results, default=str))
        json.dump(clean, f, indent=2)
    print(f"\nResults saved to {RESULTS_FILE}")

    print("\n===REPORT_START===")
    print(report)
    print("===REPORT_END===")

    return report


if __name__ == "__main__":
    main()
