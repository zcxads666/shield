#!/usr/bin/env python3
"""
Round 4 最终回归测试脚本
测试目标: http://localhost:8081 (Shield防火墙)
测试内容:
  1. SQL注入回归测试（Round 1全部payload + Round 2穿透payload复测）
  2. CC攻击回归测试（正常请求不误杀 + 同URL高频识别）
  3. 误报回归测试（Round 2误报的正常请求复测）
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

# ===================== SQL注入回归测试 =====================

def test_sql_injection():
    print("\n[+] SQL注入回归测试开始...")
    cases = []

    # ===== Round 2 穿透payload复测 =====
    # 1. Unicode编码 %u0027（2个payload）
    cases.append({
        "name": "R2复测-Unicode-%u0027-OR",
        "payload": "1%u0027%20OR%20%271%27=%271",
        "method": "GET",
        "expected_block": True,
        "category": "unicode"
    })
    cases.append({
        "name": "R2复测-Unicode-%u0027-UNION",
        "payload": "1%u0027%20UNION%20SELECT%20*%20FROM%20users--",
        "method": "GET",
        "expected_block": True,
        "category": "unicode"
    })

    # 2. 无空格括号绕过（3个payload）
    cases.append({
        "name": "R2复测-无空格-括号绕过",
        "payload": "1'OR(1)=(1)",
        "method": "GET",
        "expected_block": True,
        "category": "no_space"
    })
    cases.append({
        "name": "R2复测-无空格-括号绕过#",
        "payload": "1'OR(1)=(1)%23",
        "method": "GET",
        "expected_block": True,
        "category": "no_space"
    })
    cases.append({
        "name": "R2复测-无空格-AND括号",
        "payload": "1'AND(1)=(1)",
        "method": "GET",
        "expected_block": True,
        "category": "no_space"
    })

    # ===== Round 1 全部payload复测（确保无回归） =====
    # 基础SQL注入
    cases.append({
        "name": "R1-基础-单引号OR",
        "payload": "1' OR '1'='1",
        "method": "GET",
        "expected_block": True,
        "category": "basic"
    })
    cases.append({
        "name": "R1-基础-UNION SELECT",
        "payload": "1' UNION SELECT * FROM users--",
        "method": "GET",
        "expected_block": True,
        "category": "basic"
    })
    cases.append({
        "name": "R1-基础-堆叠查询",
        "payload": "1; DROP TABLE users--",
        "method": "GET",
        "expected_block": True,
        "category": "basic"
    })
    cases.append({
        "name": "R1-基础-时间盲注",
        "payload": "1' AND SLEEP(5)--",
        "method": "GET",
        "expected_block": True,
        "category": "basic"
    })
    cases.append({
        "name": "R1-基础-注释绕过",
        "payload": "1'/**/OR/**/'1'='1",
        "method": "GET",
        "expected_block": True,
        "category": "basic"
    })

    # 编码绕过
    cases.append({
        "name": "R1-编码-双重URL编码",
        "payload": "1%2527%2520OR%2520%25271%2527%3D%25271",
        "method": "GET",
        "expected_block": True,
        "category": "encoding"
    })
    cases.append({
        "name": "R1-编码-HTML实体",
        "payload": "1&#39; OR &#39;1&#39;=&#39;1",
        "method": "GET",
        "expected_block": True,
        "category": "encoding"
    })
    cases.append({
        "name": "R1-编码-宽字节",
        "payload": "1%df%5c' UNION SELECT * FROM users--",
        "method": "GET",
        "expected_block": True,
        "category": "encoding"
    })

    # 逻辑运算符绕过
    cases.append({
        "name": "R1-逻辑-||",
        "payload": "1'||'1'='1",
        "method": "GET",
        "expected_block": True,
        "category": "logic"
    })
    cases.append({
        "name": "R1-逻辑-&&",
        "payload": "1'&&'1'='1",
        "method": "GET",
        "expected_block": True,
        "category": "logic"
    })

    # 无空格绕过
    cases.append({
        "name": "R1-无空格-VT替代",
        "payload": "1'%0bOR%0b'1'='1",
        "method": "GET",
        "expected_block": True,
        "category": "no_space"
    })
    cases.append({
        "name": "R1-无空格-ORDER BY",
        "payload": "1 ORDER BY 1--",
        "method": "GET",
        "expected_block": True,
        "category": "no_space"
    })
    cases.append({
        "name": "R1-无空格-HAVING",
        "payload": "1' HAVING 1=1--",
        "method": "GET",
        "expected_block": True,
        "category": "no_space"
    })

    # POST方法测试
    cases.append({
        "name": "R1-POST-基础",
        "payload": "1' OR '1'='1",
        "method": "POST",
        "expected_block": True,
        "category": "post"
    })
    cases.append({
        "name": "R1-POST-UNION",
        "payload": "1' UNION SELECT * FROM users--",
        "method": "POST",
        "expected_block": True,
        "category": "post"
    })

    # 额外边界测试
    cases.append({
        "name": "边界-xp_cmdshell",
        "payload": "1'; EXEC xp_cmdshell 'dir'--",
        "method": "GET",
        "expected_block": True,
        "category": "boundary"
    })
    cases.append({
        "name": "边界-INFORMATION_SCHEMA",
        "payload": "1' UNION SELECT * FROM INFORMATION_SCHEMA.TABLES--",
        "method": "GET",
        "expected_block": True,
        "category": "boundary"
    })
    cases.append({
        "name": "边界-pg_sleep",
        "payload": "1' AND pg_sleep(5)--",
        "method": "GET",
        "expected_block": True,
        "category": "boundary"
    })
    cases.append({
        "name": "边界-BENCHMARK",
        "payload": "1' AND BENCHMARK(1000000,MD5('test'))--",
        "method": "GET",
        "expected_block": True,
        "category": "boundary"
    })

    blocked = 0
    passed = 0
    penetrated = []
    false_negatives = []
    latencies = []

    for case in cases:
        if case["method"] == "GET":
            status, text, latency = send_get("/search", params={"q": case["payload"]})
        else:
            status, text, latency = send_post("/search", data={"q": case["payload"]})
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
                    "snippet": text[:200]
                })
        print(f"  [{case['method']}] {case['name']}: status={status}, blocked={blocked_flag}")
        time.sleep(0.1)

    total = len(cases)
    block_rate = blocked / total * 100 if total else 0
    pass_rate = passed / total * 100 if total else 0
    avg_latency = statistics.mean(latencies) if latencies else 0

    print(f"\n  SQL注入测试结果: 总数={total}, 拦截={blocked}, 穿透={len(penetrated)}")
    print(f"  拦截率: {block_rate:.1f}%, 通过率: {pass_rate:.1f}%, 平均延迟: {avg_latency:.3f}s")

    return {
        "total": total,
        "blocked": blocked,
        "penetrated": len(penetrated),
        "block_rate": block_rate,
        "pass_rate": pass_rate,
        "avg_latency": avg_latency,
        "penetrated_details": false_negatives,
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
        time.sleep(0.3)  # ~3.3 req/s, 120次约36秒
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

    return results

# ===================== 误报回归测试 =====================

def test_false_positives():
    print("\n[+] 误报回归测试开始...")
    cases = []

    # Round 2 误报的正常请求复测
    cases.append({
        "name": "R2复测-UNION教程内容",
        "path": "/search",
        "method": "GET",
        "params": {"q": "UNION to combine results from multiple queries"},
        "expected_block": False
    })
    cases.append({
        "name": "R2复测-SELECT FROM",
        "path": "/search",
        "method": "GET",
        "params": {"q": "SELECT * FROM candidates"},
        "expected_block": False
    })
    cases.append({
        "name": "R2复测-multipart boundary",
        "path": "/upload",
        "method": "POST",
        "headers": {"Content-Type": "multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW"},
        "data": "------WebKitFormBoundary7MA4YWxkTrZu0gW\r\nContent-Disposition: form-data; name=\"file\"; filename=\"test.txt\"\r\n\r\nhello world\r\n------WebKitFormBoundary7MA4YWxkTrZu0gW--",
        "expected_block": False
    })
    cases.append({
        "name": "R2复测-Markdown标题",
        "path": "/comment",
        "method": "POST",
        "headers": {"Content-Type": "application/json"},
        "data": json.dumps({"content": "# Hello World\n\nThis is a test.\n\n## Subtitle\n\nSome text."}),
        "expected_block": False
    })

    # 额外正常请求测试
    cases.append({
        "name": "正常-UPDATE语句",
        "path": "/search",
        "method": "GET",
        "params": {"q": "UPDATE users SET last_login = NOW() WHERE id = 42"},
        "expected_block": False
    })
    cases.append({
        "name": "正常-数学表达式",
        "path": "/search",
        "method": "GET",
        "params": {"q": "a <= b || c >= d && x != y"},
        "expected_block": False
    })
    cases.append({
        "name": "正常-合法URL",
        "path": "/search",
        "method": "GET",
        "params": {"q": "https://example.com/search?q=hello&page=1"},
        "expected_block": False
    })
    cases.append({
        "name": "正常-中文搜索",
        "path": "/search",
        "method": "GET",
        "params": {"q": "如何学习SQL数据库"},
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

# ===================== 主函数 =====================

def main():
    print("=" * 60)
    print("Shield 防火墙 Round 4 最终回归测试")
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

    # 误报测试
    results["false_positive"] = test_false_positives()

    # 汇总
    print("\n" + "=" * 60)
    print("Round 4 回归测试汇总")
    print("=" * 60)
    sql = results["sql_injection"]
    print(f"SQL注入: 总数={sql['total']}, 拦截={sql['blocked']}, 穿透={sql['penetrated']}, 拦截率={sql['block_rate']:.1f}%")
    cc = results["cc_attack"]
    print(f"CC攻击 - 正常请求误杀: {cc['normal_requests']['blocked']}/20")
    print(f"CC攻击 - 同URL高频拦截: {cc['cc_same_url']['blocked']}/120 (首次拦截索引={cc['cc_same_url']['first_block_idx']})")
    print(f"CC攻击 - 多URL误杀: {cc['cc_multi_url']['blocked']}/150")
    print(f"CC攻击 - 并发压测拦截: {cc['cc_concurrent']['blocked']}/50")
    fp = results["false_positive"]
    print(f"误报测试: 总数={fp['total']}, 误报={fp['fp_count']}, 误报率={fp['fp_rate']:.1f}%")

    # 验收标准
    print("\n" + "=" * 60)
    print("验收标准检查")
    print("=" * 60)
    sql_pass = sql["block_rate"] >= 95.0
    fp_pass = fp["fp_rate"] < 10.0
    cc_pass = cc["normal_requests"]["blocked"] == 0 and cc["cc_same_url"]["blocked"] > 0
    print(f"SQL注入拦截率 >= 95%: {'PASS' if sql_pass else 'FAIL'} ({sql['block_rate']:.1f}%)")
    print(f"误报率 < 10%: {'PASS' if fp_pass else 'FAIL'} ({fp['fp_rate']:.1f}%)")
    print(f"CC检测正常: {'PASS' if cc_pass else 'FAIL'} (正常误杀={cc['normal_requests']['blocked']}, CC拦截={cc['cc_same_url']['blocked']})")

    results["acceptance"] = {
        "sql_pass": sql_pass,
        "fp_pass": fp_pass,
        "cc_pass": cc_pass,
        "overall_pass": sql_pass and fp_pass and cc_pass
    }

    # 保存详细报告
    report_path = "/root/shield/scripts/round4/round4_report.json"
    with open(report_path, "w") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f"\n[*] 详细报告已保存: {report_path}")

    return results

if __name__ == "__main__":
    main()
