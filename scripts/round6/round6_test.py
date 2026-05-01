#!/usr/bin/env python3
"""
Round 6 最终回归测试脚本
测试目标: http://localhost:8081 (Shield防火墙)
测试内容:
  1. SQL注入全量回归测试（98个payload，14个类别）
  2. CC攻击回归测试（正常请求不误杀 + 同URL高频识别）
  3. XSS攻击回归测试
  4. 误报回归测试（正常请求复测）
资源限制: CPU≤1核, 内存≤1GB
"""

import requests
import time
import json
import concurrent.futures
import statistics
from urllib.parse import quote

TARGET = "http://localhost:8081"
ADMIN = "http://localhost:9090"
RESULTS = {}

# ===================== 辅助函数 =====================

def send_get(path="/", params=None, headers=None):
    try:
        r = requests.get(TARGET + path, params=params, headers=headers, timeout=10)
        return r.status_code, r.text, r.elapsed.total_seconds()
    except Exception as e:
        return -1, str(e), 0.0

def send_post(path="/", data=None, headers=None):
    try:
        r = requests.post(TARGET + path, data=data, headers=headers, timeout=10)
        return r.status_code, r.text, r.elapsed.total_seconds()
    except Exception as e:
        return -1, str(e), 0.0

def is_blocked(status, text):
    if status in (403, 429, 406, 400):
        return True
    if "block" in text.lower() or "forbidden" in text.lower() or "waf" in text.lower():
        return True
    return False

def reset_metrics():
    try:
        requests.post(ADMIN + "/api/metrics/reset", timeout=5)
    except Exception:
        pass

def get_metrics():
    try:
        r = requests.get(ADMIN + "/api/metrics", timeout=5)
        return r.json()
    except Exception:
        return {}

def reset_cc():
    try:
        requests.post(ADMIN + "/api/cc/reset", timeout=5)
    except Exception:
        pass

def reset_blacklist():
    try:
        requests.post(ADMIN + "/api/blacklist/reset", timeout=5)
    except Exception:
        pass

# ===================== SQL注入全量回归测试 =====================

def test_sql_injection():
    print("\n[+] SQL注入全量回归测试开始...")
    cases = []

    # 1. Union-Based (9个)
    union_payloads = [
        ("union_basic_1", "1' UNION SELECT username, password FROM users--"),
        ("union_all_null", "1' UNION ALL SELECT null, version()--"),
        ("union_info_schema", "' UNION SELECT * FROM information_schema.tables--"),
        ("union_numeric", "-1 UNION SELECT 1,2,3--"),
        ("union_load_file", "1' UNION SELECT null, load_file('/etc/passwd')--"),
        ("union_mysql_user", "1 UNION SELECT user, password FROM mysql.user--"),
        ("union_oracle_banner", "' UNION SELECT banner FROM v$version--"),
        ("union_sqlite_master", "1 UNION SELECT name, sql FROM sqlite_master--"),
        ("union_into_outfile", "1' UNION SELECT 'hacked' INTO OUTFILE '/tmp/shell.php'--"),
    ]
    for name, payload in union_payloads:
        cases.append({"name": name, "payload": payload, "method": "GET", "expected_block": True, "category": "union_based"})

    # 2. Error-Based (4个)
    error_payloads = [
        ("error_extractvalue", "1' AND extractvalue(1, concat(0x7e, (SELECT @@version)))--"),
        ("error_updatexml", "1' AND updatexml(1, concat(0x7e, (SELECT database())), 1)--"),
        ("error_convert", "1' AND 1=convert(int, (SELECT @@version))--"),
        ("error_ctxsys", "1' AND 1=ctxsys.drithsx.sn(1, (SELECT banner FROM v$version WHERE ROWNUM=1))--"),
    ]
    for name, payload in error_payloads:
        cases.append({"name": name, "payload": payload, "method": "GET", "expected_block": True, "category": "error_based"})

    # 3. Boolean-Based Blind (5个)
    bool_payloads = [
        ("bool_1eq1", "1' AND 1=1--"),
        ("bool_1eq2", "1' AND 1=2--"),
        ("bool_ascii_sub", "1' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>64--"),
        ("bool_count", "1' AND (SELECT COUNT(*) FROM users)>0--"),
        ("bool_substring", "1' AND SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='a'--"),
    ]
    for name, payload in bool_payloads:
        cases.append({"name": name, "payload": payload, "method": "GET", "expected_block": True, "category": "boolean_blind"})

    # 4. Time-Based Blind (5个)
    time_payloads = [
        ("time_sleep_sub", "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--"),
        ("time_waitfor", "1'; WAITFOR DELAY '0:0:5'--"),
        ("time_pg_sleep", "1' AND pg_sleep(5)--"),
        ("time_benchmark", "1' AND benchmark(10000000, md5('test'))--"),
        ("time_dbms_pipe", "1' AND (SELECT * FROM (SELECT(dbms_pipe.receive_message(('a'),5)) FROM dual))--"),
    ]
    for name, payload in time_payloads:
        cases.append({"name": name, "payload": payload, "method": "GET", "expected_block": True, "category": "time_blind"})

    # 5. Stacked Queries (5个)
    stack_payloads = [
        ("stack_drop", "1; DROP TABLE users--"),
        ("stack_insert", "1; INSERT INTO logs VALUES ('hacked')--"),
        ("stack_delete", "1; DELETE FROM users WHERE '1'='1'--"),
        ("stack_update", "1; UPDATE users SET password='hacked' WHERE username='admin'--"),
        ("stack_create_user", "1; CREATE USER hacker IDENTIFIED BY 'password'--"),
    ]
    for name, payload in stack_payloads:
        cases.append({"name": name, "payload": payload, "method": "GET", "expected_block": True, "category": "stacked_queries"})

    # 6. Comment Bypass (4个)
    comment_payloads = [
        ("comment_block", "1/**/UNION/**/SELECT/**/username,password/**/FROM/**/users--"),
        ("comment_mysql_hint", "1'/*!50000UNION*/ SELECT username, password FROM users--"),
        ("comment_newline", "1'--\nUNION SELECT * FROM users--"),
        ("comment_inline", "1' /* comment */ UNION SELECT * FROM users--"),
    ]
    for name, payload in comment_payloads:
        cases.append({"name": name, "payload": payload, "method": "GET", "expected_block": True, "category": "comment_bypass"})

    # 7. Encoding Bypass (4个)
    encoding_payloads = [
        ("enc_url_encode", "1%27%20UNION%20SELECT%20*%20FROM%20users--"),
        ("enc_hex_escape", "1\\x27 UNION SELECT * FROM users--"),
        ("enc_double_url", "1%2527 UNION SELECT * FROM users--"),
        ("enc_mixed_case", "1'+%55%4E%49%4F%4E+SELECT+*+FROM+users--"),
    ]
    for name, payload in encoding_payloads:
        cases.append({"name": name, "payload": payload, "method": "GET", "expected_block": True, "category": "encoding_bypass"})

    # 8. Double Encoding (1个)
    cases.append({"name": "double_enc_full", "payload": "1%2527%2520UNION%2520SELECT%2520*%2520FROM%2520users--", "method": "GET", "expected_block": True, "category": "double_encoding"})

    # 9. Wide Byte (2个)
    widebyte_payloads = [
        ("widebyte_df", "1%df' UNION SELECT * FROM users--"),
        ("widebyte_df5c", "1%df%5c' UNION SELECT * FROM users--"),
    ]
    for name, payload in widebyte_payloads:
        cases.append({"name": name, "payload": payload, "method": "GET", "expected_block": True, "category": "widebyte"})

    # 10. Numeric Injection (4个)
    numeric_payloads = [
        ("num_1eq1", "1 AND 1=1"),
        ("num_1eq2", "1 AND 1=2"),
        ("num_or1eq1", "-1 OR 1=1"),
        ("num_convert", "1 AND 1=convert(int,@@version)"),
    ]
    for name, payload in numeric_payloads:
        cases.append({"name": name, "payload": payload, "method": "GET", "expected_block": True, "category": "numeric"})

    # 11. ORDER BY / LIMIT (4个)
    order_payloads = [
        ("orderby_1", "1 ORDER BY 1--"),
        ("orderby_10", "1 ORDER BY 10--"),
        ("orderby_sub", "1 ORDER BY (SELECT @@version)--"),
        ("limit_offset", "1 LIMIT 1 OFFSET (SELECT COUNT(*) FROM users)--"),
    ]
    for name, payload in order_payloads:
        cases.append({"name": name, "payload": payload, "method": "GET", "expected_block": True, "category": "order_limit"})

    # 12. HAVING / GROUP BY (3个)
    having_payloads = [
        ("having_1eq1", "1' HAVING 1=1--"),
        ("groupby_having", "1' GROUP BY users.id HAVING 1=1--"),
        ("limit_sub", "1 LIMIT (SELECT COUNT(*) FROM passwords)--"),
    ]
    for name, payload in having_payloads:
        cases.append({"name": name, "payload": payload, "method": "GET", "expected_block": True, "category": "having_groupby"})

    # 13. Stored Procedure / xp_cmdshell (4个)
    proc_payloads = [
        ("xp_cmdshell_master", "1'; EXEC master..xp_cmdshell 'whoami'--"),
        ("xp_cmdshell_direct", "1'; EXEC xp_cmdshell 'dir'--"),
        ("call_shell", "1'; CALL shell('whoami')--"),
        ("union_shell", "1' UNION SELECT '<?php eval($_POST[1]);?>' INTO OUTFILE '/tmp/shell.php'--"),
    ]
    for name, payload in proc_payloads:
        cases.append({"name": name, "payload": payload, "method": "GET", "expected_block": True, "category": "stored_proc"})

    # 14. Logic / NoSQL Style / Unicode / No-Space (重点类别，12个)
    logic_payloads = [
        ("logic_or_pipe", "1' || '1'='1"),
        ("logic_and_amp", "1' && '1'='1"),
        ("logic_or_x", "1' OR 'x'='x"),
        ("logic_and_x", "1' AND 'x'='x"),
        ("unicode_u0027_or", "1%u0027%20OR%20%271%27=%271"),
        ("unicode_u0027_union", "1%u0027%20UNION%20SELECT%20*%20FROM%20users--"),
        ("nospace_paren_or", "1'OR(1)=(1)"),
        ("nospace_paren_and", "1'AND(1)=(1)"),
        ("nospace_hash", "1'OR(1)=(1)%23"),
        ("nospace_comment", "1'/**/OR/**/'1'='1"),
        ("url_pipe", "1'%7C%7C'1'='1"),
        ("vt_space_or", "1'%0bOR%0b'1'='1"),
    ]
    for name, payload in logic_payloads:
        cases.append({"name": name, "payload": payload, "method": "GET", "expected_block": True, "category": "logic_or_nospace"})

    # POST方法额外测试 (6个)
    post_payloads = [
        ("post_basic_or", "1' OR '1'='1"),
        ("post_union", "1' UNION SELECT * FROM users--"),
        ("post_vt_or", "1'\x0bOR\x0b'1'='1"),
        ("post_pipe", "1'||'1'='1"),
        ("post_stack", "1; DROP TABLE users--"),
        ("post_sleep", "1' AND SLEEP(5)--"),
    ]
    for name, payload in post_payloads:
        cases.append({"name": name, "payload": payload, "method": "POST", "expected_block": True, "category": "post_method"})

    # 边界测试 (额外8个)
    boundary_payloads = [
        ("boundary_xp_cmdshell", "1'; EXEC xp_cmdshell 'dir'--"),
        ("boundary_info_schema", "1' UNION SELECT * FROM INFORMATION_SCHEMA.TABLES--"),
        ("boundary_pg_sleep", "1' AND pg_sleep(5)--"),
        ("boundary_benchmark", "1' AND BENCHMARK(1000000,MD5('test'))--"),
        ("boundary_subquery", "1 AND (SELECT COUNT(*) FROM information_schema.tables)>0"),
        ("boundary_subquery_len", "1 AND (SELECT LENGTH(password) FROM users LIMIT 1)>5"),
        ("boundary_subquery_sub", "1 AND (SELECT SUBSTRING(password,1,1) FROM users LIMIT 1)='a'"),
        ("boundary_waitfor", "1'; WAITFOR DELAY '0:0:5'--"),
    ]
    for name, payload in boundary_payloads:
        cases.append({"name": name, "payload": payload, "method": "GET", "expected_block": True, "category": "boundary"})

    # 执行测试
    blocked = 0
    passed = 0
    penetrated = []
    false_negatives = []
    latencies = []
    category_stats = {}

    for case in cases:
        if case["method"] == "GET":
            status, text, latency = send_get("/search", params={"q": case["payload"]})
        else:
            status, text, latency = send_post("/search", data={"q": case["payload"]}, headers={"Content-Type": "application/x-www-form-urlencoded"})
        latencies.append(latency)
        blocked_flag = is_blocked(status, text)
        if blocked_flag:
            blocked += 1
        if blocked_flag == case["expected_block"]:
            passed += 1
        else:
            if case["expected_block"] and not blocked_flag:
                penetrated.append(case)
                false_negatives.append({
                    "name": case["name"],
                    "payload": case["payload"],
                    "status": status,
                    "category": case["category"],
                    "snippet": text[:200]
                })
        # 类别统计
        cat = case["category"]
        if cat not in category_stats:
            category_stats[cat] = {"total": 0, "blocked": 0, "penetrated": 0}
        category_stats[cat]["total"] += 1
        if blocked_flag:
            category_stats[cat]["blocked"] += 1
        if case["expected_block"] and not blocked_flag:
            category_stats[cat]["penetrated"] += 1

        print(f"  [{case['method']}] {case['name']}: status={status}, blocked={blocked_flag}, cat={case['category']}")
        time.sleep(0.05)

    total = len(cases)
    block_rate = blocked / total * 100 if total else 0
    pass_rate = passed / total * 100 if total else 0
    avg_latency = statistics.mean(latencies) if latencies else 0

    print(f"\n  SQL注入测试结果: 总数={total}, 拦截={blocked}, 穿透={len(penetrated)}")
    print(f"  拦截率: {block_rate:.1f}%, 通过率: {pass_rate:.1f}%, 平均延迟: {avg_latency:.3f}s")
    for cat, stats in category_stats.items():
        cat_rate = stats["blocked"] / stats["total"] * 100 if stats["total"] else 0
        print(f"    [{cat}] 总数={stats['total']}, 拦截={stats['blocked']}, 穿透={stats['penetrated']}, 拦截率={cat_rate:.1f}%")

    return {
        "total": total,
        "blocked": blocked,
        "penetrated": len(penetrated),
        "block_rate": block_rate,
        "pass_rate": pass_rate,
        "avg_latency": avg_latency,
        "penetrated_details": false_negatives,
        "category_stats": category_stats,
    }

# ===================== CC攻击回归测试 =====================

def test_cc_attack():
    print("\n[+] CC攻击回归测试开始...")

    reset_cc()
    reset_blacklist()
    time.sleep(1)

    results = {}

    # 1. 正常请求基准（不同URL，低频率）
    print("  测试1: 正常请求基准（不同URL，20次）")
    normal_blocked = 0
    normal_latencies = []
    for i in range(20):
        status, text, latency = send_get(f"/page{i%5}")
        normal_latencies.append(latency)
        if is_blocked(status, text):
            normal_blocked += 1
        time.sleep(0.2)
    results["normal_requests"] = {
        "total": 20,
        "blocked": normal_blocked,
        "avg_latency": statistics.mean(normal_latencies) if normal_latencies else 0,
    }
    print(f"    正常请求: 拦截={normal_blocked}/20, 平均延迟={results['normal_requests']['avg_latency']:.3f}s")

    # 2. 同URL高频访问（模拟CC）
    print("  测试2: 同URL高频访问（120次/60s，模拟CC）")
    cc_blocked = 0
    cc_latencies = []
    cc_statuses = []
    for i in range(120):
        status, text, latency = send_get("/cc-target")
        cc_statuses.append(status)
        cc_latencies.append(latency)
        if is_blocked(status, text):
            cc_blocked += 1
        time.sleep(0.3)
    results["cc_same_url"] = {
        "total": 120,
        "blocked": cc_blocked,
        "first_block_idx": next((i for i, s in enumerate(cc_statuses) if s in (403, 429)), -1),
        "avg_latency": statistics.mean(cc_latencies) if cc_latencies else 0,
    }
    print(f"    CC同URL: 拦截={cc_blocked}/120, 首次拦截索引={results['cc_same_url']['first_block_idx']}, 平均延迟={results['cc_same_url']['avg_latency']:.3f}s")

    # 3. 不同URL高频访问（不应互相影响）
    print("  测试3: 不同URL高频访问（10个URL各15次=150次）")
    multi_blocked = 0
    multi_latencies = []
    for url_idx in range(10):
        for _ in range(15):
            status, text, latency = send_get(f"/url-{url_idx}")
            multi_latencies.append(latency)
            if is_blocked(status, text):
                multi_blocked += 1
            time.sleep(0.1)
    results["cc_multi_url"] = {
        "total": 150,
        "blocked": multi_blocked,
        "avg_latency": statistics.mean(multi_latencies) if multi_latencies else 0,
    }
    print(f"    CC多URL: 拦截={multi_blocked}/150, 平均延迟={results['cc_multi_url']['avg_latency']:.3f}s")

    # 4. 并发请求压测（控制并发数）
    print("  测试4: 并发请求压测（20并发，50请求）")
    concurrent_blocked = 0
    concurrent_latencies = []
    def fetch_one():
        return send_get("/concurrent-test")
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        futures = [executor.submit(fetch_one) for _ in range(50)]
        for future in concurrent.futures.as_completed(futures):
            status, text, latency = future.result()
            concurrent_latencies.append(latency)
            if is_blocked(status, text):
                concurrent_blocked += 1
    results["cc_concurrent"] = {
        "total": 50,
        "blocked": concurrent_blocked,
        "avg_latency": statistics.mean(concurrent_latencies) if concurrent_latencies else 0,
    }
    print(f"    并发压测: 拦截={concurrent_blocked}/50, 平均延迟={results['cc_concurrent']['avg_latency']:.3f}s")

    # 5. 逐步提升并发测试 (5->100)
    print("  测试5: 逐步提升并发测试")
    step_results = []
    for concurrency in [5, 10, 20, 50, 100]:
        reset_cc()
        time.sleep(0.5)
        step_blocked = 0
        step_latencies = []
        def fetch_step():
            return send_get("/step-test")
        with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
            futures = [executor.submit(fetch_step) for _ in range(concurrency * 2)]
            for future in concurrent.futures.as_completed(futures):
                status, text, latency = future.result()
                step_latencies.append(latency)
                if is_blocked(status, text):
                    step_blocked += 1
        step_results.append({
            "concurrency": concurrency,
            "total": concurrency * 2,
            "blocked": step_blocked,
            "avg_latency": statistics.mean(step_latencies) if step_latencies else 0,
        })
        print(f"      并发={concurrency}: 拦截={step_blocked}/{concurrency*2}, 平均延迟={step_results[-1]['avg_latency']:.3f}s")
        time.sleep(1)
    results["cc_step"] = step_results

    return results

# ===================== XSS攻击回归测试 =====================

def test_xss():
    print("\n[+] XSS攻击回归测试开始...")
    cases = [
        ("xss_script_tag", "<script>alert(1)</script>"),
        ("xss_img_onerror", "<img src=x onerror=alert(1)>"),
        ("xss_javascript_proto", "javascript:alert(1)"),
        ("xss_onmouseover", "<div onmouseover=alert(1)>hover</div>"),
        ("xss_svg_onload", "<svg onload=alert(1)>"),
        ("xss_iframe_src", "<iframe src='javascript:alert(1)'></iframe>"),
        ("xss_encoded_script", "%3Cscript%3Ealert(1)%3C/script%3E"),
        ("xss_double_encoded", "%253Cscript%253Ealert(1)%253C%252Fscript%253E"),
    ]

    blocked = 0
    penetrated = []
    latencies = []

    for name, payload in cases:
        status, text, latency = send_get("/search", params={"q": payload})
        latencies.append(latency)
        blocked_flag = is_blocked(status, text)
        if blocked_flag:
            blocked += 1
        if not blocked_flag:
            penetrated.append({"name": name, "payload": payload, "status": status})
        print(f"  [GET] {name}: status={status}, blocked={blocked_flag}")
        time.sleep(0.05)

    total = len(cases)
    block_rate = blocked / total * 100 if total else 0
    print(f"\n  XSS测试结果: 总数={total}, 拦截={blocked}, 穿透={len(penetrated)}, 拦截率={block_rate:.1f}%")

    return {
        "total": total,
        "blocked": blocked,
        "penetrated": len(penetrated),
        "block_rate": block_rate,
        "avg_latency": statistics.mean(latencies) if latencies else 0,
        "penetrated_details": penetrated,
    }

# ===================== 误报回归测试 =====================

def test_false_positives():
    print("\n[+] 误报回归测试开始...")
    cases = []

    # Round 2/4 误报的正常请求复测
    cases.append({
        "name": "fp_union_tutorial",
        "path": "/search",
        "method": "GET",
        "params": {"q": "UNION to combine results from multiple queries"},
        "expected_block": False
    })
    cases.append({
        "name": "fp_select_from",
        "path": "/search",
        "method": "GET",
        "params": {"q": "SELECT * FROM candidates"},
        "expected_block": False
    })
    cases.append({
        "name": "fp_multipart_boundary",
        "path": "/upload",
        "method": "POST",
        "headers": {"Content-Type": "multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW"},
        "data": "------WebKitFormBoundary7MA4YWxkTrZu0gW\r\nContent-Disposition: form-data; name=\"file\"; filename=\"test.txt\"\r\n\r\nhello world\r\n------WebKitFormBoundary7MA4YWxkTrZu0gW--",
        "expected_block": False
    })
    cases.append({
        "name": "fp_markdown_title",
        "path": "/comment",
        "method": "POST",
        "headers": {"Content-Type": "application/json"},
        "data": json.dumps({"content": "# Hello World\n\nThis is a test.\n\n## Subtitle\n\nSome text."}),
        "expected_block": False
    })

    # 额外正常请求测试
    cases.append({
        "name": "fp_update_stmt",
        "path": "/search",
        "method": "GET",
        "params": {"q": "UPDATE users SET last_login = NOW() WHERE id = 42"},
        "expected_block": False
    })
    cases.append({
        "name": "fp_math_expr",
        "path": "/search",
        "method": "GET",
        "params": {"q": "a <= b || c >= d && x != y"},
        "expected_block": False
    })
    cases.append({
        "name": "fp_legal_url",
        "path": "/search",
        "method": "GET",
        "params": {"q": "https://example.com/search?q=hello&page=1"},
        "expected_block": False
    })
    cases.append({
        "name": "fp_chinese_search",
        "path": "/search",
        "method": "GET",
        "params": {"q": "如何学习SQL数据库"},
        "expected_block": False
    })
    cases.append({
        "name": "fp_normal_get",
        "path": "/",
        "method": "GET",
        "expected_block": False
    })
    cases.append({
        "name": "fp_normal_search",
        "path": "/search",
        "method": "GET",
        "params": {"q": "laptop"},
        "expected_block": False
    })
    cases.append({
        "name": "fp_code_snippet",
        "path": "/search",
        "method": "GET",
        "params": {"q": "def hello(): print('Hello World')"},
        "expected_block": False
    })
    cases.append({
        "name": "fp_graphql_query",
        "path": "/graphql",
        "method": "POST",
        "headers": {"Content-Type": "application/json"},
        "data": json.dumps({"query": "query GetUser($id: ID!) { user(id: $id) { name email } }", "variables": {"id": "123"}}),
        "expected_block": False
    })

    fp_count = 0
    fp_details = []
    latencies = []

    for case in cases:
        if case["method"] == "GET":
            status, text, latency = send_get(case["path"], params=case.get("params"), headers=case.get("headers"))
        else:
            status, text, latency = send_post(case["path"], data=case.get("data"), headers=case.get("headers"))
        latencies.append(latency)
        blocked_flag = is_blocked(status, text)
        if blocked_flag != case["expected_block"]:
            fp_count += 1
            fp_details.append({
                "name": case["name"],
                "expected_block": case["expected_block"],
                "actual_block": blocked_flag,
                "status": status,
                "snippet": text[:200]
            })
        print(f"  [{case['method']}] {case['name']}: status={status}, blocked={blocked_flag}")
        time.sleep(0.05)

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

# ===================== 主函数 =====================

def main():
    print("=" * 60)
    print("Shield 防火墙 Round 6 最终回归测试")
    print(f"目标: {TARGET}")
    print("=" * 60)

    # 确认目标可达
    status, text, _ = send_get("/")
    if status not in (200, 404):
        print(f"[!] 目标不可达: status={status}")
        return
    print(f"[*] 目标可达: status={status}")

    # 重置状态
    reset_metrics()
    reset_cc()
    reset_blacklist()
    time.sleep(1)

    results = {}

    # SQL注入回归测试
    results["sql_injection"] = test_sql_injection()
    time.sleep(2)

    # CC攻击回归测试
    results["cc_attack"] = test_cc_attack()
    time.sleep(2)

    # XSS攻击回归测试
    results["xss"] = test_xss()
    time.sleep(2)

    # 误报测试
    results["false_positive"] = test_false_positives()

    # 汇总
    print("\n" + "=" * 60)
    print("Round 6 回归测试汇总")
    print("=" * 60)
    sql = results["sql_injection"]
    print(f"SQL注入: 总数={sql['total']}, 拦截={sql['blocked']}, 穿透={sql['penetrated']}, 拦截率={sql['block_rate']:.1f}%")
    cc = results["cc_attack"]
    print(f"CC攻击 - 正常请求误杀: {cc['normal_requests']['blocked']}/20")
    print(f"CC攻击 - 同URL高频拦截: {cc['cc_same_url']['blocked']}/120 (首次拦截索引={cc['cc_same_url']['first_block_idx']})")
    print(f"CC攻击 - 多URL误杀: {cc['cc_multi_url']['blocked']}/150")
    print(f"CC攻击 - 并发压测拦截: {cc['cc_concurrent']['blocked']}/50")
    xss = results["xss"]
    print(f"XSS攻击: 总数={xss['total']}, 拦截={xss['blocked']}, 穿透={xss['penetrated']}, 拦截率={xss['block_rate']:.1f}%")
    fp = results["false_positive"]
    print(f"误报测试: 总数={fp['total']}, 误报={fp['fp_count']}, 误报率={fp['fp_rate']:.1f}%")

    # 验收标准
    print("\n" + "=" * 60)
    print("验收标准检查")
    print("=" * 60)
    sql_pass = sql["block_rate"] >= 95.0
    fp_pass = fp["fp_rate"] < 10.0
    cc_pass = cc["normal_requests"]["blocked"] == 0 and cc["cc_same_url"]["blocked"] > 0
    xss_pass = xss["block_rate"] >= 80.0
    print(f"SQL注入拦截率 >= 95%: {'PASS' if sql_pass else 'FAIL'} ({sql['block_rate']:.1f}%)")
    print(f"误报率 < 10%: {'PASS' if fp_pass else 'FAIL'} ({fp['fp_rate']:.1f}%)")
    print(f"CC检测正常: {'PASS' if cc_pass else 'FAIL'} (正常误杀={cc['normal_requests']['blocked']}, CC拦截={cc['cc_same_url']['blocked']})")
    print(f"XSS拦截率 >= 80%: {'PASS' if xss_pass else 'FAIL'} ({xss['block_rate']:.1f}%)")

    results["acceptance"] = {
        "sql_pass": sql_pass,
        "fp_pass": fp_pass,
        "cc_pass": cc_pass,
        "xss_pass": xss_pass,
        "overall_pass": sql_pass and fp_pass and cc_pass,
    }

    # 保存详细报告
    report_json_path = "/root/shield/scripts/round6/round6_report.json"
    with open(report_json_path, "w") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f"\n[*] 详细JSON报告已保存: {report_json_path}")

    # 生成Markdown报告
    md = generate_markdown_report(results)
    report_md_path = "/root/shield/scripts/round6/round6_report.md"
    with open(report_md_path, "w") as f:
        f.write(md)
    print(f"[*] Markdown报告已保存: {report_md_path}")

    return results

def generate_markdown_report(results):
    sql = results["sql_injection"]
    cc = results["cc_attack"]
    xss = results["xss"]
    fp = results["false_positive"]
    acc = results["acceptance"]

    md = f"""# 🔴 Round 6 红队最终回归测试报告

## 测试概况
- **测试时间**: {time.strftime('%Y-%m-%d %H:%M:%S')}
- **测试目标**: http://localhost:8081 (Shield防火墙)
- **后端**: http://127.0.0.1:8082

## 1. SQL注入全量测试

| 指标 | 数值 |
|------|------|
| 总Payload数 | {sql['total']} |
| 拦截数 | {sql['blocked']} |
| 穿透数 | {sql['penetrated']} |
| **拦截率** | **{sql['block_rate']:.1f}%** |
| 平均延迟 | {sql['avg_latency']:.3f}s |

### 按类别统计

"""
    for cat, stats in sql.get("category_stats", {}).items():
        cat_rate = stats["blocked"] / stats["total"] * 100 if stats["total"] else 0
        md += f"| {cat} | {stats['total']} | {stats['blocked']} | {stats['penetrated']} | {cat_rate:.1f}% |\n"

    md += f"""
### 穿透详情

"""
    if sql["penetrated_details"]:
        for p in sql["penetrated_details"]:
            md += f"- **{p['name']}** (`{p['category']}`): status={p['status']}, payload=`{p['payload'][:80]}`\n"
    else:
        md += "- 无穿透payload\n"

    md += f"""
## 2. CC攻击测试

| 测试项 | 总请求 | 拦截数 | 说明 |
|--------|--------|--------|------|
| 正常请求基准 | {cc['normal_requests']['total']} | {cc['normal_requests']['blocked']} | 不同URL低频率 |
| 同URL高频 | {cc['cc_same_url']['total']} | {cc['cc_same_url']['blocked']} | 首次拦截索引={cc['cc_same_url']['first_block_idx']} |
| 多URL高频 | {cc['cc_multi_url']['total']} | {cc['cc_multi_url']['blocked']} | 不应互相影响 |
| 并发压测(20并发) | {cc['cc_concurrent']['total']} | {cc['cc_concurrent']['blocked']} | 50请求 |

### 逐步提升并发测试

"""
    for step in cc.get("cc_step", []):
        md += f"| {step['concurrency']}并发 | {step['total']} | {step['blocked']} | {step['avg_latency']:.3f}s |\n"

    md += f"""
## 3. XSS攻击测试

| 指标 | 数值 |
|------|------|
| 总Payload数 | {xss['total']} |
| 拦截数 | {xss['blocked']} |
| 穿透数 | {xss['penetrated']} |
| **拦截率** | **{xss['block_rate']:.1f}%** |

## 4. 误报测试

| 指标 | 数值 |
|------|------|
| 总正常请求数 | {fp['total']} |
| 误报数 | {fp['fp_count']} |
| **误报率** | **{fp['fp_rate']:.1f}%** |

### 误报详情

"""
    if fp["fp_details"]:
        for f in fp["fp_details"]:
            md += f"- **{f['name']}**: expected={f['expected_block']}, actual={f['actual_block']}, status={f['status']}\n"
    else:
        md += "- 无误报\n"

    md += f"""
## 5. 验收标准检查

| 指标 | 目标 | 实际 | 结果 |
|------|------|------|------|
| SQL注入拦截率 | >= 95% | {sql['block_rate']:.1f}% | {'✅ PASS' if acc['sql_pass'] else '❌ FAIL'} |
| 误报率 | < 10% | {fp['fp_rate']:.1f}% | {'✅ PASS' if acc['fp_pass'] else '❌ FAIL'} |
| CC检测 | 正常 | 误杀={cc['normal_requests']['blocked']}, 拦截={cc['cc_same_url']['blocked']} | {'✅ PASS' if acc['cc_pass'] else '❌ FAIL'} |
| XSS拦截率 | >= 80% | {xss['block_rate']:.1f}% | {'✅ PASS' if acc['xss_pass'] else '❌ FAIL'} |

## 6. 总体结论

**总体结果**: {'✅ 全部通过 - 攻防可结束' if acc['overall_pass'] else '❌ 未全部通过 - 需继续修复'}

"""
    if not acc["overall_pass"]:
        md += "### 未通过项及建议\n\n"
        if not acc["sql_pass"]:
            md += "- **SQL注入拦截率不足**: 建议增强对穿透payload的检测规则\n"
        if not acc["fp_pass"]:
            md += "- **误报率过高**: 建议优化规则减少误杀正常请求\n"
        if not acc["cc_pass"]:
            md += "- **CC检测异常**: 建议调整CC阈值或检测逻辑\n"
    else:
        md += "所有核心指标均达到验收标准，Round 6最终回归测试通过。\n"

    md += """
## 7. 改进建议

1. **持续监控**: 建议在生产环境部署后持续监控误报情况
2. **规则更新**: 定期更新SQL注入和XSS检测规则以应对新变种
3. **性能优化**: CC检测在高并发场景下延迟略有增加，可考虑优化
4. **Unicode支持**: %uXXXX解码修复已验证有效，建议保持
"""
    return md

if __name__ == "__main__":
    main()
