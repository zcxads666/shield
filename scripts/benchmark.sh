#!/usr/bin/env bash
#
# Shield WAF 压力测试脚本
# 用法: ./scripts/benchmark.sh [--shield-url <url>] [--duration <sec>] [--concurrency <n>]
#
# 测试场景:
#   1. 正常流量基准 (GET /)
#   2. SQL 注入攻击压测 (POST 批量 payload)
#   3. XSS 攻击压测 (POST 批量 payload)
#   4. DDoS/CC 压测 (高频请求)
#   5. 暴力破解压测 (高频登录失败)
#   6. 混合流量 (正常 + 攻击交错)
#
# 输出: 每个场景的 RPS、延迟 P50/P95/P99、错误率、拦截率

set -uo pipefail

SHIELD_URL="${SHIELD_URL:-http://127.0.0.1:18080}"
ADMIN_URL="${ADMIN_URL:-http://127.0.0.1:19090}"
DURATION="${DURATION:-10}"
CONCURRENCY="${CONCURRENCY:-50}"
DATASET_DIR="${DATASET_DIR:-./scripts/testdata}"
RESULTS_DIR="${RESULTS_DIR:-./scripts/benchmark_results}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

mkdir -p "$RESULTS_DIR"

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_pass() { echo -e "${GREEN}[PASS]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_fail() { echo -e "${RED}[FAIL]${NC} $1"; }

#######################################
# 辅助函数: 并发 HTTP 请求压测
# 参数: $1=并发数 $2=总请求数 $3=URL $4=可选 curl 额外参数
#######################################
run_load() {
    local concurrency=$1
    local total=$2
    local url=$3
    local extra_args="${4:-}"
    local tmpdir=$(mktemp -d)
    local pids=()

    # 使用 GNU parallel 或 bash 后台任务
    for i in $(seq 1 $concurrency); do
        (
            local per_worker=$((total / concurrency))
            local worker_file="$tmpdir/worker_$i.txt"
            for j in $(seq 1 $per_worker); do
                local start_ts end_ts http_code
                start_ts=$(date +%s%N)
                http_code=$(curl -s -o /dev/null -w "%{http_code}" \
                    --max-time 10 \
                    $extra_args \
                    "$url" 2>/dev/null || echo "000")
                end_ts=$(date +%s%N)
                local latency_ms=$(( (end_ts - start_ts) / 1000000 ))
                echo "$http_code $latency_ms" >> "$worker_file"
            done
        ) &
        pids+=($!)
    done

    for pid in "${pids[@]}"; do
        wait "$pid" 2>/dev/null || true
    done

    # 汇总结果
    local all_codes="$tmpdir/all_codes.txt"
    local all_latencies="$tmpdir/all_latencies.txt"
    for f in "$tmpdir"/worker_*.txt; do
        [[ -f "$f" ]] || continue
        awk '{print $1}' "$f" >> "$all_codes"
        awk '{print $2}' "$f" >> "$all_latencies"
    done

    local total_reqs=$(wc -l < "$all_codes" | tr -d ' ')
    local ok_200=$(grep -c "^200$" "$all_codes" 2>/dev/null | tr -d '\n' || echo 0)
    local blocked_403=$(grep -c "^403$" "$all_codes" 2>/dev/null | tr -d '\n' || echo 0)
    local blocked_429=$(grep -c "^429$" "$all_codes" 2>/dev/null | tr -d '\n' || echo 0)
    local errors=$(grep -cvE "^(200|403|429)$" "$all_codes" 2>/dev/null | tr -d '\n' || echo 0)

    # 计算延迟分位数 (需要 sort)
    if [[ -s "$all_latencies" ]]; then
        sort -n "$all_latencies" -o "$all_latencies"
        local count=$(wc -l < "$all_latencies" | tr -d ' ')
        local p50=$(awk -v n="$count" 'NR==int(n*0.50)+1{print $1}' "$all_latencies")
        local p95=$(awk -v n="$count" 'NR==int(n*0.95)+1{print $1}' "$all_latencies")
        local p99=$(awk -v n="$count" 'NR==int(n*0.99)+1{print $1}' "$all_latencies")
    else
        local p50=0 p95=0 p99=0
    fi

    rm -rf "$tmpdir"

    echo "total=$total_reqs ok=$ok_200 blocked_403=$blocked_403 blocked_429=$blocked_429 errors=$errors p50=${p50}ms p95=${p95}ms p99=${p99}ms"
}

#######################################
# 场景 1: 正常流量基准
#######################################
bench_normal() {
    log_info "========== 场景1: 正常流量基准 =========="
    local total=$((CONCURRENCY * 20))
    log_info "并发=$CONCURRENCY, 总请求=$total, URL=$SHIELD_URL/?name=alice&message=hello"

    local result
    result=$(run_load "$CONCURRENCY" "$total" "$SHIELD_URL/?name=alice&message=hello")
    echo "$result"

    local ok=$(echo "$result" | grep -o 'ok=[0-9]*' | cut -d= -f2)
    local total_r=$(echo "$result" | grep -o 'total=[0-9]*' | cut -d= -f2)
    local rate=$(awk "BEGIN {printf \"%.2f\", $ok/$total_r*100}")

    log_info "正常请求通过率: $rate% ($ok/$total_r)"
    echo "normal,$result" > "$RESULTS_DIR/normal.csv"
}

#######################################
# 场景 2: SQL 注入攻击压测
#######################################
bench_sql_inject() {
    log_info "========== 场景2: SQL 注入攻击压测 =========="
    local payload_file="$DATASET_DIR/sql_injection.txt"
    if [[ ! -f "$payload_file" ]]; then
        log_warn "未找到 SQL 注入数据集: $payload_file"
        return
    fi

    # 读取前 20 个 payload 循环使用
    local payloads=()
    while IFS= read -r line && [[ ${#payloads[@]} -lt 20 ]]; do
        [[ -n "$line" ]] && payloads+=("$line")
    done < "$payload_file"

    local total=$((CONCURRENCY * 20))
    log_info "并发=$CONCURRENCY, 总请求=$total, payload 数=${#payloads[@]}"

    local tmpdir=$(mktemp -d)
    local pids=()
    local payload_count=${#payloads[@]}

    for i in $(seq 1 $CONCURRENCY); do
        (
            local per_worker=$((total / CONCURRENCY))
            local worker_file="$tmpdir/worker_$i.txt"
            for j in $(seq 1 $per_worker); do
                local idx=$(( (j + i) % payload_count ))
                local payload="${payloads[$idx]}"
                local start_ts end_ts http_code
                start_ts=$(date +%s%N)
                http_code=$(curl -s -o /dev/null -w "%{http_code}" \
                    --max-time 10 \
                    -X POST \
                    --data-urlencode "content=$payload" \
                    "$SHIELD_URL/" 2>/dev/null || echo "000")
                end_ts=$(date +%s%N)
                local latency_ms=$(( (end_ts - start_ts) / 1000000 ))
                echo "$http_code $latency_ms" >> "$worker_file"
            done
        ) &
        pids+=($!)
    done

    for pid in "${pids[@]}"; do wait "$pid" 2>/dev/null || true; done

    local all_codes="$tmpdir/all_codes.txt"
    local all_latencies="$tmpdir/all_latencies.txt"
    for f in "$tmpdir"/worker_*.txt; do
        [[ -f "$f" ]] || continue
        awk '{print $1}' "$f" >> "$all_codes"
        awk '{print $2}' "$f" >> "$all_latencies"
    done

    local total_r=$(wc -l < "$all_codes" | tr -d ' ')
    local blocked_403=$(grep -c "^403$" "$all_codes" 2>/dev/null | tr -d '\n' || echo 0)
    local blocked_429=$(grep -c "^429$" "$all_codes" 2>/dev/null | tr -d '\n' || echo 0)
    local ok_200=$(grep -c "^200$" "$all_codes" 2>/dev/null | tr -d '\n' || echo 0)
    local errors=$(grep -cvE "^(200|403|429)$" "$all_codes" 2>/dev/null | tr -d '\n' || echo 0)

    sort -n "$all_latencies" -o "$all_latencies" 2>/dev/null
    local count=$(wc -l < "$all_latencies" | tr -d ' ')
    local p50=$(awk -v n="$count" 'NR==int(n*0.50)+1{print $1}' "$all_latencies" 2>/dev/null || echo 0)
    local p95=$(awk -v n="$count" 'NR==int(n*0.95)+1{print $1}' "$all_latencies" 2>/dev/null || echo 0)
    local p99=$(awk -v n="$count" 'NR==int(n*0.99)+1{print $1}' "$all_latencies" 2>/dev/null || echo 0)

    rm -rf "$tmpdir"

    local block_rate=$(awk "BEGIN {printf \"%.2f\", ($blocked_403+$blocked_429)/$total_r*100}")
    log_info "SQL 注入拦截率: $block_rate% (403=$blocked_403, 429=$blocked_429, 200=$ok_200, errors=$errors)"
    log_info "延迟 P50=${p50}ms P95=${p95}ms P99=${p99}ms"
    echo "sqli,total=$total_r,blocked_403=$blocked_403,blocked_429=$blocked_429,ok=$ok_200,errors=$errors,p50=${p50}ms,p95=${p95}ms,p99=${p99}ms" > "$RESULTS_DIR/sqli.csv"
}

#######################################
# 场景 3: XSS 攻击压测
#######################################
bench_xss() {
    log_info "========== 场景3: XSS 攻击压测 =========="
    local payload_file="$DATASET_DIR/xss.txt"
    if [[ ! -f "$payload_file" ]]; then
        log_warn "未找到 XSS 数据集: $payload_file"
        return
    fi

    local payloads=()
    while IFS= read -r line && [[ ${#payloads[@]} -lt 20 ]]; do
        [[ -n "$line" ]] && payloads+=("$line")
    done < "$payload_file"

    local total=$((CONCURRENCY * 20))
    log_info "并发=$CONCURRENCY, 总请求=$total, payload 数=${#payloads[@]}"

    local tmpdir=$(mktemp -d)
    local pids=()
    local payload_count=${#payloads[@]}

    for i in $(seq 1 $CONCURRENCY); do
        (
            local per_worker=$((total / CONCURRENCY))
            local worker_file="$tmpdir/worker_$i.txt"
            for j in $(seq 1 $per_worker); do
                local idx=$(( (j + i) % payload_count ))
                local payload="${payloads[$idx]}"
                local start_ts end_ts http_code
                start_ts=$(date +%s%N)
                http_code=$(curl -s -o /dev/null -w "%{http_code}" \
                    --max-time 10 \
                    -X POST \
                    --data-urlencode "content=$payload" \
                    "$SHIELD_URL/" 2>/dev/null || echo "000")
                end_ts=$(date +%s%N)
                local latency_ms=$(( (end_ts - start_ts) / 1000000 ))
                echo "$http_code $latency_ms" >> "$worker_file"
            done
        ) &
        pids+=($!)
    done

    for pid in "${pids[@]}"; do wait "$pid" 2>/dev/null || true; done

    local all_codes="$tmpdir/all_codes.txt"
    local all_latencies="$tmpdir/all_latencies.txt"
    for f in "$tmpdir"/worker_*.txt; do
        [[ -f "$f" ]] || continue
        awk '{print $1}' "$f" >> "$all_codes"
        awk '{print $2}' "$f" >> "$all_latencies"
    done

    local total_r=$(wc -l < "$all_codes" | tr -d ' ')
    local blocked_403=$(grep -c "^403$" "$all_codes" 2>/dev/null | tr -d '\n' || echo 0)
    local blocked_429=$(grep -c "^429$" "$all_codes" 2>/dev/null | tr -d '\n' || echo 0)
    local ok_200=$(grep -c "^200$" "$all_codes" 2>/dev/null | tr -d '\n' || echo 0)
    local errors=$(grep -cvE "^(200|403|429)$" "$all_codes" 2>/dev/null | tr -d '\n' || echo 0)

    sort -n "$all_latencies" -o "$all_latencies" 2>/dev/null
    local count=$(wc -l < "$all_latencies" | tr -d ' ')
    local p50=$(awk -v n="$count" 'NR==int(n*0.50)+1{print $1}' "$all_latencies" 2>/dev/null || echo 0)
    local p95=$(awk -v n="$count" 'NR==int(n*0.95)+1{print $1}' "$all_latencies" 2>/dev/null || echo 0)
    local p99=$(awk -v n="$count" 'NR==int(n*0.99)+1{print $1}' "$all_latencies" 2>/dev/null || echo 0)

    rm -rf "$tmpdir"

    local block_rate=$(awk "BEGIN {printf \"%.2f\", ($blocked_403+$blocked_429)/$total_r*100}")
    log_info "XSS 拦截率: $block_rate% (403=$blocked_403, 429=$blocked_429, 200=$ok_200, errors=$errors)"
    log_info "延迟 P50=${p50}ms P95=${p95}ms P99=${p99}ms"
    echo "xss,total=$total_r,blocked_403=$blocked_403,blocked_429=$blocked_429,ok=$ok_200,errors=$errors,p50=${p50}ms,p95=${p95}ms,p99=${p99}ms" > "$RESULTS_DIR/xss.csv"
}

#######################################
# 场景 4: DDoS/CC 压测 (高频请求)
#######################################
bench_ddos() {
    log_info "========== 场景4: DDoS/CC 压测 =========="
    local total=500
    local concurrency=100
    log_info "并发=$concurrency, 总请求=$total, 目标=$SHIELD_URL/"

    local tmpdir=$(mktemp -d)
    local pids=()

    for i in $(seq 1 $concurrency); do
        (
            local per_worker=$((total / concurrency))
            local worker_file="$tmpdir/worker_$i.txt"
            for j in $(seq 1 $per_worker); do
                local start_ts end_ts http_code
                start_ts=$(date +%s%N)
                http_code=$(curl -s -o /dev/null -w "%{http_code}" \
                    --max-time 5 \
                    "$SHIELD_URL/" 2>/dev/null || echo "000")
                end_ts=$(date +%s%N)
                local latency_ms=$(( (end_ts - start_ts) / 1000000 ))
                echo "$http_code $latency_ms" >> "$worker_file"
            done
        ) &
        pids+=($!)
    done

    for pid in "${pids[@]}"; do wait "$pid" 2>/dev/null || true; done

    local all_codes="$tmpdir/all_codes.txt"
    local all_latencies="$tmpdir/all_latencies.txt"
    for f in "$tmpdir"/worker_*.txt; do
        [[ -f "$f" ]] || continue
        awk '{print $1}' "$f" >> "$all_codes"
        awk '{print $2}' "$f" >> "$all_latencies"
    done

    local total_r=$(wc -l < "$all_codes" | tr -d ' ')
    local blocked_429=$(grep -c "^429$" "$all_codes" 2>/dev/null | tr -d '\n' || echo 0)
    local blocked_403=$(grep -c "^403$" "$all_codes" 2>/dev/null | tr -d '\n' || echo 0)
    local ok_200=$(grep -c "^200$" "$all_codes" 2>/dev/null | tr -d '\n' || echo 0)
    local errors=$(grep -cvE "^(200|403|429)$" "$all_codes" 2>/dev/null | tr -d '\n' || echo 0)

    sort -n "$all_latencies" -o "$all_latencies" 2>/dev/null
    local count=$(wc -l < "$all_latencies" | tr -d ' ')
    local p50=$(awk -v n="$count" 'NR==int(n*0.50)+1{print $1}' "$all_latencies" 2>/dev/null || echo 0)
    local p95=$(awk -v n="$count" 'NR==int(n*0.95)+1{print $1}' "$all_latencies" 2>/dev/null || echo 0)
    local p99=$(awk -v n="$count" 'NR==int(n*0.99)+1{print $1}' "$all_latencies" 2>/dev/null || echo 0)

    rm -rf "$tmpdir"

    local block_rate=$(awk "BEGIN {printf \"%.2f\", ($blocked_429+$blocked_403)/$total_r*100}")
    log_info "DDoS/CC 触发率: $block_rate% (429=$blocked_429, 403=$blocked_403, 200=$ok_200, errors=$errors)"
    log_info "延迟 P50=${p50}ms P95=${p95}ms P99=${p99}ms"
    echo "ddos,total=$total_r,blocked_429=$blocked_429,blocked_403=$blocked_403,ok=$ok_200,errors=$errors,p50=${p50}ms,p95=${p95}ms,p99=${p99}ms" > "$RESULTS_DIR/ddos.csv"
}

#######################################
# 场景 5: 暴力破解压测
#######################################
bench_bruteforce() {
    log_info "========== 场景5: 暴力破解压测 =========="
    local total=30
    local concurrency=10
    log_info "并发=$concurrency, 总请求=$total, 目标=$SHIELD_URL/login"

    local tmpdir=$(mktemp -d)
    local pids=()

    for i in $(seq 1 $concurrency); do
        (
            local per_worker=$((total / concurrency))
            local worker_file="$tmpdir/worker_$i.txt"
            for j in $(seq 1 $per_worker); do
                local start_ts end_ts http_code
                start_ts=$(date +%s%N)
                http_code=$(curl -s -o /dev/null -w "%{http_code}" \
                    --max-time 5 \
                    -X POST \
                    --data "username=admin&password=wrong$j" \
                    "$SHIELD_URL/login" 2>/dev/null || echo "000")
                end_ts=$(date +%s%N)
                local latency_ms=$(( (end_ts - start_ts) / 1000000 ))
                echo "$http_code $latency_ms" >> "$worker_file"
            done
        ) &
        pids+=($!)
    done

    for pid in "${pids[@]}"; do wait "$pid" 2>/dev/null || true; done

    local all_codes="$tmpdir/all_codes.txt"
    local all_latencies="$tmpdir/all_latencies.txt"
    for f in "$tmpdir"/worker_*.txt; do
        [[ -f "$f" ]] || continue
        awk '{print $1}' "$f" >> "$all_codes"
        awk '{print $2}' "$f" >> "$all_latencies"
    done

    local total_r=$(wc -l < "$all_codes" | tr -d ' ')
    local blocked_429=$(grep -c "^429$" "$all_codes" 2>/dev/null | tr -d '\n' || echo 0)
    local blocked_403=$(grep -c "^403$" "$all_codes" 2>/dev/null | tr -d '\n' || echo 0)
    local ok_200=$(grep -c "^200$" "$all_codes" 2>/dev/null | tr -d '\n' || echo 0)
    local errors=$(grep -cvE "^(200|403|429)$" "$all_codes" 2>/dev/null | tr -d '\n' || echo 0)

    sort -n "$all_latencies" -o "$all_latencies" 2>/dev/null
    local count=$(wc -l < "$all_latencies" | tr -d ' ')
    local p50=$(awk -v n="$count" 'NR==int(n*0.50)+1{print $1}' "$all_latencies" 2>/dev/null || echo 0)
    local p95=$(awk -v n="$count" 'NR==int(n*0.95)+1{print $1}' "$all_latencies" 2>/dev/null || echo 0)
    local p99=$(awk -v n="$count" 'NR==int(n*0.99)+1{print $1}' "$all_latencies" 2>/dev/null || echo 0)

    rm -rf "$tmpdir"

    local block_rate=$(awk "BEGIN {printf \"%.2f\", ($blocked_429+$blocked_403)/$total_r*100}")
    log_info "暴力破解触发率: $block_rate% (429=$blocked_429, 403=$blocked_403, 200=$ok_200, errors=$errors)"
    log_info "延迟 P50=${p50}ms P95=${p95}ms P99=${p99}ms"
    echo "bruteforce,total=$total_r,blocked_429=$blocked_429,blocked_403=$blocked_403,ok=$ok_200,errors=$errors,p50=${p50}ms,p95=${p95}ms,p99=${p99}ms" > "$RESULTS_DIR/bruteforce.csv"
}

#######################################
# 场景 6: 混合流量 (正常 + 攻击交错)
#######################################
bench_mixed() {
    log_info "========== 场景6: 混合流量压测 =========="
    local total=300
    local concurrency=30
    log_info "并发=$concurrency, 总请求=$total (50% 正常 + 25% SQLi + 25% XSS)"

    local sqli_payloads=()
    while IFS= read -r line && [[ ${#sqli_payloads[@]} -lt 10 ]]; do
        [[ -n "$line" ]] && sqli_payloads+=("$line")
    done < "$DATASET_DIR/sql_injection.txt"

    local xss_payloads=()
    while IFS= read -r line && [[ ${#xss_payloads[@]} -lt 10 ]]; do
        [[ -n "$line" ]] && xss_payloads+=("$line")
    done < "$DATASET_DIR/xss.txt"

    local tmpdir=$(mktemp -d)
    local pids=()

    for i in $(seq 1 $concurrency); do
        (
            local per_worker=$((total / concurrency))
            local worker_file="$tmpdir/worker_$i.txt"
            for j in $(seq 1 $per_worker); do
                local mod=$((j % 4))
                local start_ts end_ts http_code
                start_ts=$(date +%s%N)
                if [[ $mod -eq 0 || $mod -eq 1 ]]; then
                    # 50% 正常请求
                    http_code=$(curl -s -o /dev/null -w "%{http_code}" \
                        --max-time 5 \
                        "$SHIELD_URL/?name=alice&message=hello" 2>/dev/null || echo "000")
                elif [[ $mod -eq 2 ]]; then
                    # 25% SQLi
                    local payload="${sqli_payloads[$((j % ${#sqli_payloads[@]}))]}"
                    http_code=$(curl -s -o /dev/null -w "%{http_code}" \
                        --max-time 5 \
                        -X POST --data-urlencode "content=$payload" \
                        "$SHIELD_URL/" 2>/dev/null || echo "000")
                else
                    # 25% XSS
                    local payload="${xss_payloads[$((j % ${#xss_payloads[@]}))]}"
                    http_code=$(curl -s -o /dev/null -w "%{http_code}" \
                        --max-time 5 \
                        -X POST --data-urlencode "content=$payload" \
                        "$SHIELD_URL/" 2>/dev/null || echo "000")
                fi
                end_ts=$(date +%s%N)
                local latency_ms=$(( (end_ts - start_ts) / 1000000 ))
                echo "$http_code $latency_ms" >> "$worker_file"
            done
        ) &
        pids+=($!)
    done

    for pid in "${pids[@]}"; do wait "$pid" 2>/dev/null || true; done

    local all_codes="$tmpdir/all_codes.txt"
    local all_latencies="$tmpdir/all_latencies.txt"
    for f in "$tmpdir"/worker_*.txt; do
        [[ -f "$f" ]] || continue
        awk '{print $1}' "$f" >> "$all_codes"
        awk '{print $2}' "$f" >> "$all_latencies"
    done

    local total_r=$(wc -l < "$all_codes" | tr -d ' ')
    local blocked_429=$(grep -c "^429$" "$all_codes" 2>/dev/null | tr -d '\n' || echo 0)
    local blocked_403=$(grep -c "^403$" "$all_codes" 2>/dev/null | tr -d '\n' || echo 0)
    local ok_200=$(grep -c "^200$" "$all_codes" 2>/dev/null | tr -d '\n' || echo 0)
    local errors=$(grep -cvE "^(200|403|429)$" "$all_codes" 2>/dev/null | tr -d '\n' || echo 0)

    sort -n "$all_latencies" -o "$all_latencies" 2>/dev/null
    local count=$(wc -l < "$all_latencies" | tr -d ' ')
    local p50=$(awk -v n="$count" 'NR==int(n*0.50)+1{print $1}' "$all_latencies" 2>/dev/null || echo 0)
    local p95=$(awk -v n="$count" 'NR==int(n*0.95)+1{print $1}' "$all_latencies" 2>/dev/null || echo 0)
    local p99=$(awk -v n="$count" 'NR==int(n*0.99)+1{print $1}' "$all_latencies" 2>/dev/null || echo 0)

    rm -rf "$tmpdir"

    local pass_rate=$(awk "BEGIN {printf \"%.2f\", $ok_200/$total_r*100}")
    local block_rate=$(awk "BEGIN {printf \"%.2f\", ($blocked_429+$blocked_403)/$total_r*100}")
    log_info "混合流量 — 正常通过率: $pass_rate%, 拦截率: $block_rate%"
    log_info "(200=$ok_200, 403=$blocked_403, 429=$blocked_429, errors=$errors)"
    log_info "延迟 P50=${p50}ms P95=${p95}ms P99=${p99}ms"
    echo "mixed,total=$total_r,blocked_429=$blocked_429,blocked_403=$blocked_403,ok=$ok_200,errors=$errors,p50=${p50}ms,p95=${p95}ms,p99=${p99}ms" > "$RESULTS_DIR/mixed.csv"
}

#######################################
# 主程序
#######################################
main() {
    log_info "Shield WAF 压力测试"
    log_info "Shield URL: $SHIELD_URL"
    log_info "Admin URL:  $ADMIN_URL"
    log_info "并发数:     $CONCURRENCY"
    log_info "结果目录:   $RESULTS_DIR"
    echo ""

    # 预热
    log_info "预热中..."
    for i in $(seq 1 5); do
        curl -s -o /dev/null "$SHIELD_URL/" 2>/dev/null || true
    done

    bench_normal
    bench_sql_inject
    bench_xss
    bench_ddos
    bench_bruteforce
    bench_mixed

    echo ""
    log_info "========== 全部压测完成 =========="
    log_info "结果已保存到: $RESULTS_DIR"
    for f in "$RESULTS_DIR"/*.csv; do
        [[ -f "$f" ]] || continue
        log_info "  $(basename "$f"): $(cat "$f")"
    done
}

main "$@"
