#!/usr/bin/env python3
"""
Round 2 最终回归测试脚本
"""
import requests
import time
import json
import concurrent.futures
import statistics

TARGET = "http://localhost:8081"
ADMIN = "http://localhost:9090"

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
    if status in (403, 429, 406):
        return True
    if "block" in text.lower() or "forbidden" in text.lower() or "waf" in text.lower():
        return True
    return False

def test_sql_injection():
    print("\n[+] SQL注入回归测试")
    cases = [
        # Round 1 穿透的5类payload
        {"name": "VT替代空格-OR", "payload": "1'%0bOR%0b'1'='1", "expected": True},
        {"name": "VT替代空格-UNION", "payload": "1'%0bUNION%0bSELECT%0b*%0bFROM%0busers--", "expected": True},
        {"name": "双重URL编码-OR", "payload": "1%2527%2520OR%2520%25271%2527%3D%25271", "expected": True},
        {"name": "双重URL编码-UNION", "payload": "1%2527%2520UNION%2520SELECT%2520*%2520FROM%2520users--", "expected": True},
        {"name": "Unicode-%u0027-OR", "payload": "1%u0027%20OR%20%271%27=%271", "expected": True},
        {"name": "Unicode-%u0027-UNION", "payload": "1%u0027%20UNION%20SELECT%20*%20FROM%20users--", "expected": True},
        {"name": "逻辑OR-||-简单", "payload": "1'||'1'='1", "expected": True},
        {"name": "逻辑OR-||-数字", "payload": "1'||'1'='1'--", "expected": True},
        {"name": "逻辑OR-||-字母", "payload": "ab'||'cd'='cd", "expected": True},
        {"name": "无空格-注释绕过", "payload": "1'/**/OR/**/'1'='1", "expected": True},
        {"name": "无空格-括号绕过", "payload": "1'OR(1)=(1)", "expected": True},
        {"name": "无空格-括号绕过#", "payload": "1'OR(1)=(1)%23", "expected": True},
        {"name": "无空格-AND括号", "payload": "1'AND(1)=(1)", "expected": True},
        # 额外测试
        {"name": "宽字节注入", "payload": "1%df%5c' UNION SELECT * FROM users--", "expected": True},
        {"name": "ORDER BY注入", "payload": "1 ORDER BY 1--", "expected": True},
        {"name": "HAVING注入", "payload": "1' HAVING 1=1--", "expected": True},
        {"name": "时间盲注-SLEEP", "payload": "1' AND SLEEP(5)--", "expected": True},
        {"name": "堆叠查询-DROP", "payload": "1; DROP TABLE users--", "expected": True},
        {"name": "URL编码||", "payload": "1'%7C%7C'1'='1", "expected": True},
        {"name": "POST-VT替代空格", "payload": "1'\x0bOR\x0b'1'='1", "method": "POST", "expected": True},
        {"name": "POST-||逻辑OR", "payload": "1'||'1'='1", "method": "POST", "expected": True},
    ]

    blocked = 0
    penetrated = []
    latencies = []

    for case in cases:
        method = case.get("method", "GET")
        if method == "GET":
            status, text, latency = send_get("/", params={"q": case["payload"]})
        else:
            status, text, latency = send_post("/", data={"q": case["payload"]}, headers={"Content-Type": "application/x-www-form-urlencoded"})
        latencies.append(latency)
        blocked_flag = is_blocked(status, text)
        if blocked_flag:
            blocked += 1
        if blocked_flag != case["expected"]:
            penetrated.append({"name": case["name"], "payload": case["payload"], "status": status, "method": method})
        print(f"  [{method}] {case['name']}: status={status}, blocked={blocked_flag}")
        time.sleep(0.05)

    total = len(cases)
    block_rate = blocked / total * 100 if total else 0
    return {
        "total": total, "blocked": blocked, "penetrated": len(penetrated),
        "block_rate": block_rate, "penetrated_details": penetrated,
        "avg_latency": statistics.mean(latencies) if latencies else 0,
    }

def test_cc_attack():
    print("\n[+] CC攻击回归测试")
    results = {}

    # 正常请求基准
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
        "total": 20, "blocked": normal_blocked,
        "avg_latency": statistics.mean(normal_latencies) if normal_latencies else 0,
    }
    print(f"    正常请求: 拦截={normal_blocked}/20")

    # 同URL高频访问
    print("  测试2: 同URL高频访问（110次/60s）")
    cc_blocked = 0
    cc_latencies = []
    cc_statuses = []
    for i in range(110):
        status, text, latency = send_get("/cc-target")
        cc_statuses.append(status)
        cc_latencies.append(latency)
        if is_blocked(status, text):
            cc_blocked += 1
        time.sleep(0.3)
    results["cc_same_url"] = {
        "total": 110, "blocked": cc_blocked,
        "first_block_idx": next((i for i, s in enumerate(cc_statuses) if s in (403, 429)), -1),
        "avg_latency": statistics.mean(cc_latencies) if cc_latencies else 0,
    }
    print(f"    CC同URL: 拦截={cc_blocked}/110, 首次拦截索引={results['cc_same_url']['first_block_idx']}")

    # 不同URL高频访问
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
        "total": 150, "blocked": multi_blocked,
        "avg_latency": statistics.mean(multi_latencies) if multi_latencies else 0,
    }
    print(f"    CC多URL: 拦截={multi_blocked}/150")

    # 并发请求压测
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
        "total": 50, "blocked": concurrent_blocked,
        "avg_latency": statistics.mean(concurrent_latencies) if concurrent_latencies else 0,
    }
    print(f"    并发压测: 拦截={concurrent_blocked}/50")

    return results

def test_false_positives():
    print("\n[+] 误报测试")
    cases = [
        # multipart form boundary (POST 501=backend不支持，但WAF未拦截)
        {"name": "multipart boundary正常", "path": "/", "method": "POST",
         "headers": {"Content-Type": "multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW"},
         "data": "------WebKitFormBoundary7MA4YWxkTrZu0gW\r\nContent-Disposition: form-data; name=\"file\"; filename=\"test.txt\"\r\n\r\nhello\r\n------WebKitFormBoundary7MA4YWxkTrZu0gW--",
         "expected": False},
        # Markdown内容
        {"name": "Markdown # 标题", "path": "/", "method": "GET",
         "params": {"q": "# Hello World\n\nThis is a test."}, "expected": False},
        {"name": "Markdown 多级标题", "path": "/", "method": "GET",
         "params": {"q": "### Title\n#### Subtitle"}, "expected": False},
        # 正常SQL关键字
        {"name": "正常SQL教程-UNION", "path": "/", "method": "GET",
         "params": {"q": "In SQL, you can use UNION to combine results from multiple queries."}, "expected": False},
        {"name": "正常SQL-SELECT FROM", "path": "/", "method": "GET",
         "params": {"q": "SELECT * FROM candidates WHERE name = 'Alice'"}, "expected": False},
        {"name": "正常SQL-UPDATE", "path": "/", "method": "GET",
         "params": {"q": "UPDATE users SET last_login = NOW() WHERE id = 42"}, "expected": False},
        # 数学表达式
        {"name": "数学表达式 && ||", "path": "/", "method": "GET",
         "params": {"q": "a <= b || c >= d && x != y"}, "expected": False},
        # 合法URL
        {"name": "合法URL含参数", "path": "/", "method": "GET",
         "params": {"q": "https://example.com/search?q=hello&page=1"}, "expected": False},
    ]

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
        # POST返回501是后端不支持，视为WAF未拦截（通过）
        if case["method"] == "POST" and status == 501:
            blocked_flag = False
        if blocked_flag != case["expected"]:
            fp_count += 1
            fp_details.append({"name": case["name"], "expected": case["expected"], "actual": blocked_flag, "status": status})
        print(f"  [{case['method']}] {case['name']}: status={status}, blocked={blocked_flag}")
        time.sleep(0.05)

    total = len(cases)
    fp_rate = fp_count / total * 100 if total else 0
    return {
        "total": total, "fp_count": fp_count, "fp_rate": fp_rate,
        "fp_details": fp_details,
        "avg_latency": statistics.mean(latencies) if latencies else 0,
    }

def main():
    print("=" * 60)
    print("Shield 防火墙 Round 2 回归测试")
    print(f"目标: {TARGET}")
    print("=" * 60)

    status, text, _ = send_get("/")
    if status not in (200, 404):
        print(f"[!] 目标不可达: status={status}")
        return
    print(f"[*] 目标可达: status={status}")

    results = {}
    results["sql_injection"] = test_sql_injection()
    time.sleep(2)
    results["cc_attack"] = test_cc_attack()
    time.sleep(2)
    results["false_positive"] = test_false_positives()

    print("\n" + "=" * 60)
    print("回归测试汇总")
    print("=" * 60)
    sql = results["sql_injection"]
    print(f"SQL注入: 总数={sql['total']}, 拦截={sql['blocked']}, 穿透={sql['penetrated']}, 拦截率={sql['block_rate']:.1f}%")
    cc = results["cc_attack"]
    print(f"CC攻击 - 正常请求误杀: {cc['normal_requests']['blocked']}/20")
    print(f"CC攻击 - 同URL高频拦截: {cc['cc_same_url']['blocked']}/110 (首次拦截索引={cc['cc_same_url']['first_block_idx']})")
    print(f"CC攻击 - 多URL误杀: {cc['cc_multi_url']['blocked']}/150")
    print(f"CC攻击 - 并发压测拦截: {cc['cc_concurrent']['blocked']}/50")
    fp = results["false_positive"]
    print(f"误报测试: 总数={fp['total']}, 误报={fp['fp_count']}, 误报率={fp['fp_rate']:.1f}%")

    report_path = "/root/shield/scripts/round2/final_report.json"
    with open(report_path, "w") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f"\n[*] 详细报告已保存: {report_path}")

if __name__ == "__main__":
    main()
