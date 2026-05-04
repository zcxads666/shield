#!/usr/bin/env python3
"""Compile final Round 13 attack report from collected data."""
import json
import os

# Load data from both test phases
with open("/tmp/round13_results.json") as f:
    fast = json.load(f)

slow_file = "/tmp/round13_slow_results.json"
slow = None
if os.path.exists(slow_file):
    with open(slow_file) as f:
        slow = json.load(f)

# Read ALL logs for comprehensive type analysis
log_entries = []
try:
    with open("/opt/shield/logs/shield.log") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    log_entries.append(json.loads(line))
                except:
                    pass
except:
    pass

# Filter to our test period (09:33 onwards)
test_logs = [e for e in log_entries if e.get("time", "") >= "2026-05-03T09:33:"]

# ============================================================
# Comprehensive Type Identification Analysis
# ============================================================

# Map log messages to expected attack types
MSG_TYPE_MAP = {
    "request_blocked_sqlinject": "SQL注入",
    "sql_injection_detected": "SQL注入",
    "request_blocked_xss": "XSS",
    "xss_detected": "XSS",
    "request_blocked_webshell": "木马上传",
    "webshell_upload_detected": "木马上传",
    "request_blocked_bruteforce": "爆破攻击",
    "request_blocked_cc": "CC攻击",
    "cc_attack_detected": "CC攻击",
    "request_blocked_ddos": "DDoS",
}

# Count type identification accuracy
type_stats = {
    "SQL注入": {"total_blocks": 0, "correct_type": 0, "wrong_type": 0, "wrong_labeled_as": {}},
    "XSS": {"total_blocks": 0, "correct_type": 0, "wrong_type": 0, "wrong_labeled_as": {}},
    "木马上传": {"total_blocks": 0, "correct_type": 0, "wrong_type": 0, "wrong_labeled_as": {}},
    "CC攻击": {"total_blocks": 0, "correct_type": 0, "wrong_type": 0, "wrong_labeled_as": {}},
    "爆破攻击": {"total_blocks": 0, "correct_type": 0, "wrong_type": 0, "wrong_labeled_as": {}},
    "DDoS": {"total_blocks": 0, "correct_type": 0, "wrong_type": 0, "wrong_labeled_as": {}},
}

for entry in test_logs:
    msg = entry.get("message", "")
    attack_type = entry.get("attack_type", "")

    # Only analyze BLOCK messages
    if "blocked" not in msg:
        continue

    # Determine the ACTUAL attack type from the TYPE of block message
    real_type = None
    for msg_key, type_name in MSG_TYPE_MAP.items():
        if msg_key in msg:
            real_type = type_name
            break

    if real_type is None:
        continue

    if real_type not in type_stats:
        continue

    type_stats[real_type]["total_blocks"] += 1

    # Check if WAF label matches the correct expected type for this attack
    expected_labels = {
        "SQL注入": ["sql_injection"],
        "XSS": ["xss"],
        "木马上传": ["webshell_upload"],
        "CC攻击": ["cc_attack"],
        "爆破攻击": ["brute_force"],
        "DDoS": ["ddos_attack", "ddos_attack:http_flood", "ddos_attack:goldeneye"],
    }

    is_correct = False
    if real_type in expected_labels:
        for expected in expected_labels[real_type]:
            if attack_type == expected:
                is_correct = True
                break

    if is_correct:
        type_stats[real_type]["correct_type"] += 1
    else:
        type_stats[real_type]["wrong_type"] += 1
        label = attack_type if attack_type else "无类型标注"
        type_stats[real_type]["wrong_labeled_as"][label] = type_stats[real_type]["wrong_labeled_as"].get(label, 0) + 1

# Supplement type analysis with METRIC-based data for CC and Brute Force
# These attackers were never identified by their own detectors (all caught as DDoS)
# Metrics confirm: cc_blocks stayed 0, brute_force_blocks stayed 0
# The actual attacks were blocked, but labeled as DDoS

# Count DDoS blocks that are actually misclassified other attacks
# ddos_blocks metric went from 1 to 398 → 397 DDoS blocks
# But only 50 were actual DDoS test requests
# The rest (~347) were SQL/XSS/CC/BF requests wrongly caught by DDoS

# Total attacks of each type that SHOULD have been identified:
METRIC_EXPECTED = {
    "CC攻击": 60,      # All 60 CC tests
    "爆破攻击": 282,    # All 282 brute force tests
}

# From metrics analysis: correct identifications per type
METRIC_CORRECT = {
    "SQL注入": 53,     # sql_injections metric +53
    "XSS": 24,        # xss_attempts metric +24
    "木马上传": 29,     # webshell_uploads metric +29
    "CC攻击": 0,       # cc_blocks metric stayed 0
    "爆破攻击": 0,     # brute_force_blocks metric stayed 0
    "DDoS": 50,       # all 50 DDoS requests correctly identified
}

# Print the report
print("=" * 70)
print("🔴 Round 13 红队防火墙复测 - 完整攻击报告")
print("=" * 70)
print(f"测试时间: 2026-05-03 09:33-09:39 UTC")
print(f"目标: Shield WAF @ 127.0.0.1:8081")
print(f"后端: 127.0.0.1:8082")
print()

# ============================================================
# Section 1: Overall Statistics
# ============================================================
print("=" * 70)
print("一、综合拦截效果统计")
print("=" * 70)

# Combined from both test phases
combined = {
    "SQL注入": {"tested": 67 + 15, "blocked": 67 + 15, "passed": 0 + 0},
    "XSS": {"tested": 61 + 12, "blocked": 61 + 12, "passed": 0 + 0},
    "木马上传": {"tested": 35 + 8, "blocked": 35 + 0, "passed": 0 + 8},
    "CC攻击": {"tested": 60, "blocked": 60, "passed": 0},
    "DDoS": {"tested": 50, "blocked": 50, "passed": 0},
    "爆破攻击": {"tested": 230 + 52, "blocked": 230 + 52, "passed": 0 + 0},
}

total_tested = sum(v["tested"] for v in combined.values())
total_blocked = sum(v["blocked"] for v in combined.values())
total_passed = sum(v["passed"] for v in combined.values())

print()
print(f"{'攻击类型':<15} {'测试数':>6} {'拦截数':>6} {'穿透数':>6} {'拦截率':>8} {'识别正确':>8} {'识别错误':>8}")
print("-" * 70)

overall_correct = 0
overall_wrong = 0

for atype, data in combined.items():
    rate = data["blocked"] / data["tested"] * 100 if data["tested"] > 0 else 0

    # Type identification from METRICS (authoritative):
    # - sql_injections: +53 = 53 SQL injections correctly identified
    # - xss_attempts: +24 = 24 XSS correctly identified
    # - webshell_uploads: +29 = 29 webshell uploads correctly identified
    # - cc_blocks: 0 = 0 CC attacks identified (all labeled as DDoS)
    # - brute_force_blocks: 0 = 0 BF attacks identified (all labeled as DDoS)
    # - ddos_blocks: +397 = 397 DDoS blocks total (includes misclassified ones)
    # Correct DDoS identification: 50 (the actual DDoS test requests)
    # Incorrectly labeled as DDoS: 397 - 50 = 347 (CC/BF/SQL/XSS misattributed)

    if atype in METRIC_CORRECT:
        correct = METRIC_CORRECT[atype]
    else:
        correct = 0

    if atype == "DDoS":
        # DDoS correctly identified: 50 actual DDoS tests
        wrong = 0
    else:
        # Total attacks tested minus correctly identified = wrongly identified
        wrong = data["tested"] - data["passed"] - correct

    overall_correct += correct
    overall_wrong += wrong

    print(f"{atype:<15} {data['tested']:>6} {data['blocked']:>6} {data['passed']:>6} {rate:>7.1f}% {correct:>8} {wrong:>8}")

print("-" * 70)
overall_rate = total_blocked / total_tested * 100 if total_tested > 0 else 0
print(f"{'合计':<15} {total_tested:>6} {total_blocked:>6} {total_passed:>6} {overall_rate:>7.1f}% {overall_correct:>8} {overall_wrong:>8}")

# Type accuracy based on metric-verified counts
total_attacks = sum(v["tested"] for v in combined.values())
total_bypassed = sum(v["passed"] for v in combined.values())
total_correct_typed = sum(METRIC_CORRECT.values())
total_wrong_typed = (total_attacks - total_bypassed) - total_correct_typed
type_acc = total_correct_typed / (total_attacks - total_bypassed) * 100 if (total_attacks - total_bypassed) > 0 else 0

print(f"\n  攻击类型识别准确率 (基于WAF指标): {type_acc:.1f}%")
print(f"  正确识别: {total_correct_typed}, 错误标注: {total_wrong_typed}")
print(f"  错误标注明细:")
for atype in ["CC攻击", "爆破攻击"]:
    data = combined[atype]
    blocked = data["blocked"]
    correct = METRIC_CORRECT.get(atype, 0)
    wrong = blocked - correct
    print(f"    - {atype}: {wrong}/{blocked} 次拦截被错误标注为DDoS (0次正确标注)")

# ============================================================
# Section 2: Type Identification Error Details (metric-based)
# ============================================================
print()
print("=" * 70)
print("二、攻击类型识别错误清单 (基于WAF Metrics)")
print("=" * 70)

type_id_data = [
    ("SQL注入", 82, 0, 53, 82-53, "29次被DDoS拦截标注为ddos_attack"),
    ("XSS", 73, 0, 24, 73-24, "49次被DDoS拦截标注为ddos_attack"),
    ("木马上传", 43, 8, 29, 43-8-29, "6次被DDoS拦截标注为ddos_attack; 8次穿透"),
    ("CC攻击", 60, 0, 0, 60, "60次全部被DDoS拦截标注为ddos_attack"),
    ("爆破攻击", 282, 0, 0, 282, "282次全部被DDoS拦截标注为ddos_attack"),
    ("DDoS", 50, 0, 50, 0, "全部正确识别"),
]

print(f"\n{'攻击类型':<12} {'测试':>5} {'穿透':>5} {'正确':>5} {'错误':>5} {'说明'}")
print("-" * 80)
for name, tested, bypassed, correct, wrong, desc in type_id_data:
    print(f"{name:<12} {tested:>5} {bypassed:>5} {correct:>5} {wrong:>5} {desc}")

# ============================================================
# Section 3: Critical Vulnerabilities
# ============================================================
print()
print("=" * 70)
print("三、关键漏洞与绕过发现")
print("=" * 70)

print("""
🔴 漏洞1: DDoS检测器抢占导致攻击类型识别大面积错误 (严重)
  - 根因: proxy.go:237 DDoS检测器在内容扫描前拦截请求
  - CC检测器(proxy.go:224)有 labelAndBlockContentAttack 调用
  - DDoS检测器(proxy.go:242)缺少相同的内容标签逻辑
  - 影响: 77%的已拦截请求被错误标注为DDoS
  - 按验收标准: 标注类型错误 = 视为穿透

🔴 漏洞2: WebShell上传绕过 (严重)
  - 慢速上传PHP/JSP/ASP木马文件时，DDoS未触发
  - 请求成功到达后端(返回501，但内容未被WAF检测)
  - 8个WebShell测试中，8个全部绕过WAF内容检测
  - 包含: eval(), system(), passthru(), Runtime.exec()等恶意函数

🔴 漏洞3: CC攻击无法独立识别 (严重)
  - CC检测器指标 cc_blocks 始终为0
  - 60个CC攻击请求全部被DDoS拦截，类型标注为DDoS
  - CC检测器的行为指纹、挑战机制未独立生效

🔴 漏洞4: 暴力破解无法独立识别 (严重)
  - Brute Force指标 brute_force_blocks 始终为0
  - 282个爆破请求全部被DDoS拦截
  - 所有请求被标注为DDoS而非爆破攻击
  - protected_paths 列表扩展后仍无法独立工作
""")

# ============================================================
# Section 4: False Positive Analysis
# ============================================================
print("=" * 70)
print("四、误报分析")
print("=" * 70)
print()
print("  正常请求测试: 10个 (GET/POST 常见参数)")
print("  误拦截数: 0")
print("  误报率: 0% ✅ (要求 <2%)")
print()

# ============================================================
# Section 5: Metrics Comparison
# ============================================================
print("=" * 70)
print("五、WAF指标变化")
print("=" * 70)
print()
fm_start = fast["initial_metrics"]
fm_end = fast["final_metrics"]
print(f"  {'指标':<25} {'测试前':>8} {'测试后':>8} {'变化':>8}")
print(f"  {'-'*49}")
for key in fm_start:
    if isinstance(fm_start[key], (int, float)):
        delta = fm_end.get(key, 0) - fm_start.get(key, 0)
        print(f"  {key:<25} {fm_start[key]:>8} {fm_end.get(key, 0):>8} {delta:>+8}")

# ============================================================
# Section 6: Recommendations
# ============================================================
print()
print("=" * 70)
print("六、改进建议")
print("=" * 70)
print("""
1. 【紧急】DDoS检测器添加内容标签
   在 proxy.go:242 DDoS拦截前调用 labelAndBlockContentAttack()
   确保被DDoS拦截的请求也能获得正确的攻击类型标注
   参考: CC检测器在 proxy.go:224 已有此调用

2. 【紧急】修复WebShell上传检测路径问题
   确保文件上传内容检测对所有路径生效，不依赖backend返回状态码
   建议在 proxy.go:170 body读取后立即检查文件上传内容

3. 【高优】调整检测器优先级
   内容检测器(SQL/XSS/WS)应在DDoS检测器之前运行
   或至少确保DDoS拦截时附加正确的内容类型标签

4. 【高优】CC检测器独立验证
   DDoS的rate_limit功能与CC检测器功能重叠
   需要明确分工: DDoS负责连接层，CC负责应用层行为分析

5. 【中优】Brute Force检测器独立验证
   在DDoS调整后，验证brute force是否能独立触发
   考虑添加更多failure状态码(如404、500等)以增加检测覆盖面
""")

# ============================================================
# Section 7: Acceptance Criteria Summary
# ============================================================
print("=" * 70)
print("七、验收标准达成情况")
print("=" * 70)
print(f"""
  ✅ 整体拦截率: {overall_rate:.1f}% (要求 >=95%)
  ❌ 攻击类型识别准确率: {type_acc:.1f}% (要求 100%)
  ✅ 误报率: 0% (要求 <2%)

  综合判定: ❌ 未通过 — 攻击类型识别准确率不达标
  正确标注: {total_correct_typed}/{total_attacks - total_bypassed} 次拦截
  CC攻击 0/60 正确识别 | 爆破攻击 0/282 正确识别
  主要阻塞项: DDoS检测器抢占导致类型识别大面积错误
""")

print("=" * 70)
print("报告完毕")
print("=" * 70)
