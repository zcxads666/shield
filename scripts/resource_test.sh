#!/usr/bin/env bash
#
# Shield WAF CPU / 内存资源占用测试脚本
# 测试场景：待机（无请求）+ 压力（高并发攻击）
# 输出：CPU%、RSS 内存、VSZ 内存、goroutine 数

set -uo pipefail

SHIELD_PID="${SHIELD_PID:-}"
SHIELD_URL="${SHIELD_URL:-http://127.0.0.1:18080}"
DATASET_DIR="${DATASET_DIR:-./scripts/testdata}"
RESULTS_DIR="${RESULTS_DIR:-./scripts/resource_results}"
DURATION_SEC="${DURATION_SEC:-60}"

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
# 获取 Shield 进程资源占用
#######################################
get_shield_pid() {
    if [[ -n "$SHIELD_PID" ]]; then
        echo "$SHIELD_PID"
        return
    fi
    local pid
    pid=$(pgrep -f "bin/shield" | head -1)
    echo "$pid"
}

collect_metrics() {
    local pid=$1
    local label=$2
    local out_file=$3
    
    if [[ -z "$pid" || ! -d "/proc/$pid" ]]; then
        log_fail "Shield 进程不存在"
        return 1
    fi
    
    # 瞬时 CPU% (top -bn1 采样 1 秒), RSS(KB), VSZ(KB), 线程数
    local cpu rss vsz threads
    cpu=$(top -bn1 -p "$pid" 2>/dev/null | awk -v pid="$pid" 'NR>7 && $1==pid {print $9}')
    if [[ -z "$cpu" ]]; then
        cpu=$(ps -p "$pid" -o %cpu= 2>/dev/null | tr -d ' ')
    fi
    rss=$(ps -p "$pid" -o rss= 2>/dev/null | tr -d ' ')
    vsz=$(ps -p "$pid" -o vsz= 2>/dev/null | tr -d ' ')
    threads=$(ps -p "$pid" -o nlwp= 2>/dev/null | tr -d ' ')
    
    # Go runtime metrics (via /debug/pprof if available, else skip)
    local goroutines=0
    if curl -s "$SHIELD_URL/debug/pprof/goroutine?debug=1" > /dev/null 2>&1; then
        goroutines=$(curl -s "$SHIELD_URL/debug/pprof/goroutine?debug=1" 2>/dev/null | grep -c "^goroutine " || echo 0)
    fi
    
    printf "%s,%s,%s,%s,%s,%s\n" "$label" "$cpu" "$rss" "$vsz" "$threads" "$goroutines" >> "$out_file"
}

#######################################
# 场景1: 待机场景
#######################################
test_idle() {
    log_info "========== 场景1: 待机资源占用 =========="
    local pid
    pid=$(get_shield_pid)
    log_info "Shield PID: $pid"
    
    local out_file="$RESULTS_DIR/idle.csv"
    echo "time,cpu%,rss_kb,vsz_kb,threads,goroutines" > "$out_file"
    
    log_info "采集 $DURATION_SEC 秒，每 5 秒采样一次..."
    for i in $(seq 1 $((DURATION_SEC / 5))); do
        collect_metrics "$pid" "$((i * 5))" "$out_file"
        sleep 5
    done
    
    # 汇总
    local avg_cpu max_rss
    avg_cpu=$(awk -F, 'NR>1 {sum+=$2; count++} END {if(count>0) printf "%.2f", sum/count}' "$out_file")
    max_rss=$(awk -F, 'NR>1 {if($3>max) max=$3} END {print max+0}' "$out_file")
    
    log_info "待机平均 CPU: ${avg_cpu}%"
    log_info "待机最大 RSS: ${max_rss}KB"
    
    # 阈值判断
    local cpu_ok=true rss_ok=true
    if awk "BEGIN {exit !($avg_cpu > 5.0)}"; then
        log_fail "待机 CPU 超过 5% (${avg_cpu}%)"
        cpu_ok=false
    else
        log_pass "待机 CPU 达标 (${avg_cpu}%)"
    fi
    
    if awk "BEGIN {exit !($max_rss > 51200)}"; then
        log_fail "待机 RSS 超过 50MB (${max_rss}KB)"
        rss_ok=false
    else
        log_pass "待机 RSS 达标 (${max_rss}KB)"
    fi
    
    echo "idle,avg_cpu=$avg_cpu,max_rss=$max_rss,cpu_ok=$cpu_ok,rss_ok=$rss_ok" > "$RESULTS_DIR/idle_summary.csv"
}

#######################################
# 场景2: 压力场景（高并发攻击）
#######################################
test_stress() {
    log_info "========== 场景2: 压力资源占用 =========="
    local pid
    pid=$(get_shield_pid)
    log_info "Shield PID: $pid"
    
    local out_file="$RESULTS_DIR/stress.csv"
    echo "time,cpu%,rss_kb,vsz_kb,threads,goroutines" > "$out_file"
    
    # 启动压力生成器（后台）
    local payload_file="$DATASET_DIR/sql_injection.txt"
    local pids=()
    
    log_info "启动压力: 20 并发攻击流量 + 10 并发正常流量，持续 $DURATION_SEC 秒"
    
    # 攻击流量
    for i in $(seq 1 20); do
        (
            local end_time=$(( $(date +%s) + DURATION_SEC ))
            while [[ $(date +%s) -lt $end_time ]]; do
                local payload
                payload=$(shuf -n 1 "$payload_file" 2>/dev/null || echo "' OR 1=1 --")
                curl -s -o /dev/null --max-time 3 -X POST --data-urlencode "content=$payload" "$SHIELD_URL/" 2>/dev/null || true
            done
        ) &
        pids+=($!)
    done
    
    # 正常流量
    for i in $(seq 1 10); do
        (
            local end_time=$(( $(date +%s) + DURATION_SEC ))
            while [[ $(date +%s) -lt $end_time ]]; do
                curl -s -o /dev/null --max-time 3 "$SHIELD_URL/?name=alice&message=hello" 2>/dev/null || true
            done
        ) &
        pids+=($!)
    done
    
    # 采集资源
    local start_ts=$(date +%s)
    local sample_count=0
    while [[ $(date +%s) -lt $((start_ts + DURATION_SEC)) ]]; do
        collect_metrics "$pid" "$(( $(date +%s) - start_ts ))" "$out_file"
        sleep 2
        sample_count=$((sample_count + 1))
    done
    
    # 停止压力
    for p in "${pids[@]}"; do
        kill "$p" 2>/dev/null || true
    done
    wait 2>/dev/null || true
    
    # 汇总
    local avg_cpu max_cpu max_rss max_threads
    avg_cpu=$(awk -F, 'NR>1 {sum+=$2; count++} END {if(count>0) printf "%.2f", sum/count}' "$out_file")
    max_cpu=$(awk -F, 'NR>1 {if($2>max) max=$2} END {print max+0}' "$out_file")
    max_rss=$(awk -F, 'NR>1 {if($3>max) max=$3} END {print max+0}' "$out_file")
    max_threads=$(awk -F, 'NR>1 {if($5>max) max=$5} END {print max+0}' "$out_file")
    
    log_info "压力平均 CPU: ${avg_cpu}%"
    log_info "压力峰值 CPU: ${max_cpu}%"
    log_info "压力最大 RSS: ${max_rss}KB"
    log_info "压力最大线程: ${max_threads}"
    
    # 阈值判断
    local cpu_ok=true rss_ok=true
    if awk "BEGIN {exit !($max_cpu > 80.0)}"; then
        log_fail "压力峰值 CPU 超过 80% (${max_cpu}%)"
        cpu_ok=false
    else
        log_pass "压力峰值 CPU 达标 (${max_cpu}%)"
    fi
    
    if awk "BEGIN {exit !($max_rss > 204800)}"; then
        log_fail "压力 RSS 超过 200MB (${max_rss}KB)"
        rss_ok=false
    else
        log_pass "压力 RSS 达标 (${max_rss}KB)"
    fi
    
    echo "stress,avg_cpu=$avg_cpu,max_cpu=$max_cpu,max_rss=$max_rss,max_threads=$max_threads,cpu_ok=$cpu_ok,rss_ok=$rss_ok" > "$RESULTS_DIR/stress_summary.csv"
}

#######################################
# 场景3: 待机恢复（压力后观察内存是否回落）
#######################################
test_recovery() {
    log_info "========== 场景3: 压力后恢复观察 =========="
    local pid
    pid=$(get_shield_pid)
    
    log_info "等待 30 秒观察内存回落..."
    sleep 30
    
    local cpu rss
    cpu=$(ps -p "$pid" -o %cpu= 2>/dev/null | tr -d ' ')
    rss=$(ps -p "$pid" -o rss= 2>/dev/null | tr -d ' ')
    
    log_info "恢复后 CPU: ${cpu}%"
    log_info "恢复后 RSS: ${rss}KB"
    
    echo "recovery,cpu=$cpu,rss=$rss" > "$RESULTS_DIR/recovery.csv"
}

#######################################
# 主程序
#######################################
main() {
    log_info "Shield WAF 资源占用测试"
    log_info "Shield URL: $SHIELD_URL"
    log_info "测试时长: ${DURATION_SEC}s"
    log_info "结果目录: $RESULTS_DIR"
    echo ""
    
    local pid
    pid=$(get_shield_pid)
    if [[ -z "$pid" ]]; then
        log_fail "未找到 Shield 进程，请设置 SHIELD_PID 或先启动 Shield"
        exit 1
    fi
    log_info "目标进程 PID: $pid"
    echo ""
    
    test_idle
    echo ""
    test_stress
    echo ""
    test_recovery
    
    echo ""
    log_info "========== 全部测试完成 =========="
    log_info "结果已保存到: $RESULTS_DIR"
    for f in "$RESULTS_DIR"/*_summary.csv "$RESULTS_DIR"/recovery.csv; do
        [[ -f "$f" ]] || continue
        log_info "  $(basename "$f"): $(cat "$f")"
    done
}

main "$@"
