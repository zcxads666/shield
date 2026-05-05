#!/usr/bin/env bash
set -uo pipefail

SHIELD_URL="${SHIELD_URL:-http://127.0.0.1:18080}"
DATASET_DIR="${DATASET_DIR:-./scripts/testdata}"
RESULTS_DIR="${RESULTS_DIR:-./scripts/resource_results}"
DURATION_SEC="${DURATION_SEC:-300}"
ATTACK_CONCURRENCY="${ATTACK_CONCURRENCY:-20}"
NORMAL_CONCURRENCY="${NORMAL_CONCURRENCY:-10}"

mkdir -p "$RESULTS_DIR"

get_shield_pid() {
    pgrep -f "bin/shield" | head -1
}

collect_metrics() {
    local pid=$1
    local label=$2
    local out_file=$3
    if [[ -z "$pid" || ! -d "/proc/$pid" ]]; then
        echo "$label,MISSING,0,0,0,0" >> "$out_file"
        return
    fi
    local cpu rss vsz threads
    cpu=$(ps -p "$pid" -o %cpu= 2>/dev/null | tr -d ' ')
    rss=$(ps -p "$pid" -o rss= 2>/dev/null | tr -d ' ')
    vsz=$(ps -p "$pid" -o vsz= 2>/dev/null | tr -d ' ')
    threads=$(ps -p "$pid" -o nlwp= 2>/dev/null | tr -d ' ')
    printf "%s,%s,%s,%s,%s,0\n" "$label" "${cpu:-0}" "${rss:-0}" "${vsz:-0}" "${threads:-0}" >> "$out_file"
}

test_idle() {
    echo "[INFO] ========== 场景1: 待机 ${DURATION_SEC}s =========="
    local out_file="$RESULTS_DIR/idle_${DURATION_SEC}s.csv"
    echo "time,cpu%,rss_kb,vsz_kb,threads,goroutines" > "$out_file"
    local pid
    for i in $(seq 1 $((DURATION_SEC / 5))); do
        pid=$(get_shield_pid)
        collect_metrics "$pid" "$((i * 5))" "$out_file"
        sleep 5
    done
    local avg_cpu max_rss
    avg_cpu=$(awk -F, 'NR>1 && $2!="MISSING" {sum+=$2; count++} END {if(count>0) printf "%.2f", sum/count}' "$out_file")
    max_rss=$(awk -F, 'NR>1 && $3>max {max=$3} END {print max+0}' "$out_file")
    echo "[INFO] 待机平均 CPU: ${avg_cpu}%"
    echo "[INFO] 待机最大 RSS: ${max_rss}KB"
    echo "idle_${DURATION_SEC}s,avg_cpu=${avg_cpu},max_rss=${max_rss}" > "$RESULTS_DIR/idle_${DURATION_SEC}s_summary.csv"
}

test_stress() {
    echo "[INFO] ========== 场景2: 压力 ${DURATION_SEC}s (攻击=${ATTACK_CONCURRENCY}, 正常=${NORMAL_CONCURRENCY}) =========="
    local out_file="$RESULTS_DIR/stress_${ATTACK_CONCURRENCY}a${NORMAL_CONCURRENCY}n_${DURATION_SEC}s.csv"
    echo "time,cpu%,rss_kb,vsz_kb,threads,goroutines" > "$out_file"
    local payload_file="$DATASET_DIR/sql_injection.txt"
    local pids=()
    
    for i in $(seq 1 "$ATTACK_CONCURRENCY"); do
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
    
    for i in $(seq 1 "$NORMAL_CONCURRENCY"); do
        (
            local end_time=$(( $(date +%s) + DURATION_SEC ))
            while [[ $(date +%s) -lt $end_time ]]; do
                curl -s -o /dev/null --max-time 3 "$SHIELD_URL/?name=alice&message=hello" 2>/dev/null || true
            done
        ) &
        pids+=($!)
    done
    
    local start_ts=$(date +%s)
    while [[ $(date +%s) -lt $((start_ts + DURATION_SEC)) ]]; do
        local pid=$(get_shield_pid)
        collect_metrics "$pid" "$(( $(date +%s) - start_ts ))" "$out_file"
        sleep 2
    done
    
    for p in "${pids[@]}"; do
        kill "$p" 2>/dev/null || true
    done
    wait 2>/dev/null || true
    
    local avg_cpu max_cpu max_rss max_threads
    avg_cpu=$(awk -F, 'NR>1 && $2!="MISSING" {sum+=$2; count++} END {if(count>0) printf "%.2f", sum/count}' "$out_file")
    max_cpu=$(awk -F, 'NR>1 && $2!="MISSING" && $2>max {max=$2} END {print max+0}' "$out_file")
    max_rss=$(awk -F, 'NR>1 && $3>max {max=$3} END {print max+0}' "$out_file")
    max_threads=$(awk -F, 'NR>1 && $5>max {max=$5} END {print max+0}' "$out_file")
    echo "[INFO] 压力平均 CPU: ${avg_cpu}%"
    echo "[INFO] 压力峰值 CPU: ${max_cpu}%"
    echo "[INFO] 压力最大 RSS: ${max_rss}KB"
    echo "[INFO] 压力最大线程: ${max_threads}"
    echo "stress_${ATTACK_CONCURRENCY}a${NORMAL_CONCURRENCY}n_${DURATION_SEC}s,avg_cpu=${avg_cpu},max_cpu=${max_cpu},max_rss=${max_rss},max_threads=${max_threads}" > "$RESULTS_DIR/stress_${ATTACK_CONCURRENCY}a${NORMAL_CONCURRENCY}n_${DURATION_SEC}s_summary.csv"
}

test_recovery() {
    echo "[INFO] ========== 场景3: 恢复观察 60s =========="
    local out_file="$RESULTS_DIR/recovery_${DURATION_SEC}s.csv"
    echo "time,cpu%,rss_kb,vsz_kb,threads,goroutines" > "$out_file"
    for i in $(seq 1 12); do
        local pid=$(get_shield_pid)
        collect_metrics "$pid" "$((i * 5))" "$out_file"
        sleep 5
    done
    local avg_cpu max_rss
    avg_cpu=$(awk -F, 'NR>1 && $2!="MISSING" {sum+=$2; count++} END {if(count>0) printf "%.2f", sum/count}' "$out_file")
    max_rss=$(awk -F, 'NR>1 && $3>max {max=$3} END {print max+0}' "$out_file")
    echo "[INFO] 恢复平均 CPU: ${avg_cpu}%"
    echo "[INFO] 恢复最大 RSS: ${max_rss}KB"
    echo "recovery_${DURATION_SEC}s,avg_cpu=${avg_cpu},max_rss=${max_rss}" > "$RESULTS_DIR/recovery_${DURATION_SEC}s_summary.csv"
}

main() {
    echo "[INFO] Shield WAF 资源占用测试 (QA增强版)"
    echo "[INFO] 时长: ${DURATION_SEC}s, 攻击并发: ${ATTACK_CONCURRENCY}, 正常并发: ${NORMAL_CONCURRENCY}"
    test_idle
    test_stress
    test_recovery
    echo "[INFO] 全部完成，结果: $RESULTS_DIR"
}

main "$@"
