#!/usr/bin/env bash
#
# Shield WAF 一键批量测试脚本
# 功能: 自动启动 shield + mock 后端，读取本地数据集进行全量测试
# 用法: ./scripts/shield_test.sh
# 数据集: scripts/testdata/ (sql_injection.txt, xss.txt, benign_normal.txt, benign_edge.txt)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
DATASET_DIR="$SCRIPT_DIR/testdata"
RESULTS_DIR="$SCRIPT_DIR/test_results"

SHIELD_BIN="$PROJECT_DIR/bin/shield"
SHIELD_CONFIG="$PROJECT_DIR/test_config.yaml"
SHIELD_PORT=18080
STATUS_FILE="$PROJECT_DIR/data/status.json"
BACKEND_PORT=18081

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

PASS=0
FAIL=0
WARN=0

log_pass() { echo -e "${GREEN}[PASS]${NC} $1"; ((PASS++)) || true; }
log_fail() { echo -e "${RED}[FAIL]${NC} $1"; ((FAIL++)) || true; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; ((WARN++)) || true; }
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_step() { echo -e "\n${BLUE}========== $1 ==========${NC}"; }

# Cleanup function
cleanup() {
    log_info "Cleaning up..."
    if [[ -n "${SHIELD_PID:-}" ]]; then
        kill "$SHIELD_PID" 2>/dev/null || true
        wait "$SHIELD_PID" 2>/dev/null || true
    fi
    if [[ -n "${BACKEND_PID:-}" ]]; then
        kill "$BACKEND_PID" 2>/dev/null || true
        wait "$BACKEND_PID" 2>/dev/null || true
    fi
    rm -f "$PROJECT_DIR/backend.go"
}
trap cleanup EXIT

# Check prerequisites
check_prereqs() {
    log_step "Prerequisites Check"
    
    if [[ ! -f "$SHIELD_BIN" ]]; then
        log_info "Shield binary not found, building..."
        cd "$PROJECT_DIR" && make build
    fi
    
    if [[ ! -f "$SHIELD_CONFIG" ]]; then
        log_info "Creating test config..."
        cat > "$SHIELD_CONFIG" << 'EOF'
server:
  bind_addr: ":18080"
  read_timeout_ms: 30000
  write_timeout_ms: 30000
  max_header_bytes: 1048576

proxy:
  target_url: "http://127.0.0.1:18081"
  trust_forwarded: false

rate_limit:
  enabled: true
  requests_per_second: 100
  burst_size: 150
  block_duration_sec: 300

ddos:
  enabled: true
  max_connections_per_ip: 1000
  slowloris_timeout_ms: 30000
  challenge_threshold: 500

sql_inject:
  enabled: true
  action: block
  severity_level: high

xss:
  enabled: true
  action: block
  filter_response: false

brute_force:
  enabled: true
  max_failures: 5
  window_sec: 60
  block_duration_sec: 600
  protected_paths:
    - /login
    - /api/auth
    - /admin
  status_codes:
    - 401
    - 403

blacklist:
  enabled: true
  persist_path: "./data/blacklist.json"
  auto_blacklist: true

log:
  level: warn
  format: json
  output_path: "./logs/shield.log"
  max_size_mb: 100
  max_backups: 7
  max_age_days: 30

alert:
  enabled: false
  webhook: ""
  syslog_addr: ""
  threshold: 10

rules:
  rules_path: "./data/rules.yaml"
  hot_reload: true
  reload_interval_sec: 3
EOF
    fi
    
    mkdir -p "$RESULTS_DIR"
    log_pass "Prerequisites OK"
}

# Start mock backend
start_backend() {
    log_step "Starting Mock Backend"
    
    cat > "$PROJECT_DIR/backend.go" << 'EOF'
package main

import (
    "fmt"
    "net/http"
)

func main() {
    http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "text/html")
        fmt.Fprintf(w, "<html><body><h1>Backend OK</h1><p>Path: %s</p></body></html>", r.URL.Path)
    })
    http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusUnauthorized)
        fmt.Fprint(w, "Unauthorized")
    })
    fmt.Println("Backend listening on :18081")
    http.ListenAndServe(":18081", nil)
}
EOF
    
    cd "$PROJECT_DIR" && go run backend.go &
    BACKEND_PID=$!
    sleep 2
    
    # Verify backend is up
    if curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:$BACKEND_PORT/" | grep -q "200"; then
        log_pass "Mock backend started on port $BACKEND_PORT"
    else
        log_fail "Mock backend failed to start"
        exit 1
    fi
}

# Start shield
start_shield() {
    log_step "Starting Shield WAF"
    
    cd "$PROJECT_DIR" && "$SHIELD_BIN" -config "$SHIELD_CONFIG" start &
    SHIELD_PID=$!
    sleep 3
    
    # Verify shield is up
    if curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:$SHIELD_PORT/" | grep -q "200"; then
        log_pass "Shield WAF started on port $SHIELD_PORT"
    else
        log_fail "Shield WAF failed to start"
        exit 1
    fi
}

# Read payloads from file (skip comments and empty lines)
read_payloads() {
    local file="$1"
    while IFS= read -r line || [[ -n "$line" ]]; do
        line=$(echo "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        [[ -z "$line" || "$line" =~ ^# ]] && continue
        echo "$line"
    done < "$file"
}

# Count payloads in file
count_payloads() {
    local file="$1"
    local count=0
    while IFS= read -r line || [[ -n "$line" ]]; do
        line=$(echo "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        [[ -z "$line" || "$line" =~ ^# ]] && continue
        ((count++)) || true
    done < "$file"
    echo "$count"
}

#######################################
# 1. Normal Request Test
#######################################
run_normal_test() {
    log_step "Normal Request Test"
    local http_code
    http_code=$(curl -s -o /dev/null -w "%{http_code}" \
        "http://127.0.0.1:$SHIELD_PORT/?name=alice&message=hello" 2>/dev/null || echo "000")
    
    log_info "Normal request: HTTP $http_code"
    if [[ "$http_code" == "200" ]]; then
        log_pass "Normal request passed through"
    else
        log_fail "Normal request blocked unexpectedly ($http_code)"
    fi
    echo "normal,http_code=$http_code" > "$RESULTS_DIR/normal.csv"
}

#######################################
# 2. SQL Injection Test (Dataset-driven)
#######################################
run_sql_injection_test() {
    log_step "SQL Injection Test (Dataset: $DATASET_DIR/sql_injection.txt)"
    local payload_file="$DATASET_DIR/sql_injection.txt"
    local benign_file="$DATASET_DIR/benign_normal.txt"
    
    if [[ ! -f "$payload_file" ]]; then
        log_fail "SQL injection payload file not found: $payload_file"
        return
    fi
    
    local total=0 blocked=0
    while IFS= read -r line || [[ -n "$line" ]]; do
        line=$(echo "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        [[ -z "$line" || "$line" =~ ^# ]] && continue
        ((total++)) || true
        local http_code
        http_code=$(curl -s -o /dev/null -w "%{http_code}" \
            --data-urlencode "q=$line" \
            "http://127.0.0.1:$SHIELD_PORT/" 2>/dev/null || echo "000")
        if [[ "$http_code" == "403" ]]; then
            ((blocked++)) || true
        fi
    done < "$payload_file"
    
    # Benign false positive test
    local benign_total=0 benign_fp=0
    if [[ -f "$benign_file" ]]; then
        while IFS= read -r line || [[ -n "$line" ]]; do
            line=$(echo "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
            [[ -z "$line" || "$line" =~ ^# ]] && continue
            ((benign_total++)) || true
            local http_code
            http_code=$(curl -s -o /dev/null -w "%{http_code}" \
                --data-urlencode "q=$line" \
                "http://127.0.0.1:$SHIELD_PORT/" 2>/dev/null || echo "000")
            if [[ "$http_code" == "403" ]]; then
                ((benign_fp++)) || true
            fi
        done < "$benign_file"
    fi
    
    local rate=0
    if [[ $total -gt 0 ]]; then
        rate=$(awk "BEGIN {printf \"%.2f\", ($blocked/$total)*100}")
    fi
    local fp_rate=0
    if [[ $benign_total -gt 0 ]]; then
        fp_rate=$(awk "BEGIN {printf \"%.2f\", ($benign_fp/$benign_total)*100}")
    fi
    
    log_info "SQL Injection: total=$total, blocked=$blocked, rate=${rate}%"
    log_info "SQL Injection FP: total=$benign_total, fp=$benign_fp, rate=${fp_rate}%"
    
    if awk "BEGIN {exit !($rate >= 95)}"; then
        log_pass "SQL Injection block rate >= 95% ($rate%)"
    else
        log_fail "SQL Injection block rate < 95% ($rate%)"
    fi
    
    if awk "BEGIN {exit !($fp_rate <= 10)}"; then
        log_pass "SQL Injection FP rate <= 10% ($fp_rate%)"
    else
        log_fail "SQL Injection FP rate > 10% ($fp_rate%)"
    fi
    
    echo "sql_injection,total=$total,blocked=$blocked,rate=$rate,fp_total=$benign_total,fp=$benign_fp,fp_rate=$fp_rate" \
        > "$RESULTS_DIR/sql_injection.csv"
}

#######################################
# 3. XSS Test (Dataset-driven)
#######################################
run_xss_test() {
    log_step "XSS Test (Dataset: $DATASET_DIR/xss.txt)"
    local payload_file="$DATASET_DIR/xss.txt"
    local benign_file="$DATASET_DIR/benign_normal.txt"
    
    if [[ ! -f "$payload_file" ]]; then
        log_fail "XSS payload file not found: $payload_file"
        return
    fi
    
    local total=0 blocked=0
    while IFS= read -r line || [[ -n "$line" ]]; do
        line=$(echo "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        [[ -z "$line" || "$line" =~ ^# ]] && continue
        ((total++)) || true
        local http_code
        http_code=$(curl -s -o /dev/null -w "%{http_code}" \
            --data-urlencode "content=$line" \
            "http://127.0.0.1:$SHIELD_PORT/" 2>/dev/null || echo "000")
        if [[ "$http_code" == "403" ]]; then
            ((blocked++)) || true
        fi
    done < "$payload_file"
    
    local benign_total=0 benign_fp=0
    if [[ -f "$benign_file" ]]; then
        while IFS= read -r line || [[ -n "$line" ]]; do
            line=$(echo "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
            [[ -z "$line" || "$line" =~ ^# ]] && continue
            ((benign_total++)) || true
            local http_code
            http_code=$(curl -s -o /dev/null -w "%{http_code}" \
                --data-urlencode "content=$line" \
                "http://127.0.0.1:$SHIELD_PORT/" 2>/dev/null || echo "000")
            if [[ "$http_code" == "403" ]]; then
                ((benign_fp++)) || true
            fi
        done < "$benign_file"
    fi
    
    local rate=0
    if [[ $total -gt 0 ]]; then
        rate=$(awk "BEGIN {printf \"%.2f\", ($blocked/$total)*100}")
    fi
    local fp_rate=0
    if [[ $benign_total -gt 0 ]]; then
        fp_rate=$(awk "BEGIN {printf \"%.2f\", ($benign_fp/$benign_total)*100}")
    fi
    
    log_info "XSS: total=$total, blocked=$blocked, rate=${rate}%"
    log_info "XSS FP: total=$benign_total, fp=$benign_fp, rate=${fp_rate}%"
    
    if awk "BEGIN {exit !($rate >= 95)}"; then
        log_pass "XSS block rate >= 95% ($rate%)"
    else
        log_fail "XSS block rate < 95% ($rate%)"
    fi
    
    if awk "BEGIN {exit !($fp_rate <= 5)}"; then
        log_pass "XSS FP rate <= 5% ($fp_rate%)"
    else
        log_fail "XSS FP rate > 5% ($fp_rate%)"
    fi
    
    echo "xss,total=$total,blocked=$blocked,rate=$rate,fp_total=$benign_total,fp=$benign_fp,fp_rate=$fp_rate" \
        > "$RESULTS_DIR/xss.csv"
}

#######################################
# 4. DDoS / CC Test
#######################################
run_ddos_test() {
    log_step "DDoS / CC Test"
    local total=100 blocked=0
    
    for i in $(seq 1 $total); do
        local http_code
        http_code=$(curl -s -o /dev/null -w "%{http_code}" \
            "http://127.0.0.1:$SHIELD_PORT/?id=$i" 2>/dev/null || echo "000")
        if [[ "$http_code" == "429" || "$http_code" == "403" ]]; then
            ((blocked++)) || true
        fi
    done
    
    local rate=0
    if [[ $total -gt 0 ]]; then
        rate=$(awk "BEGIN {printf \"%.2f\", ($blocked/$total)*100}")
    fi
    
    log_info "DDoS/CC: total=$total, blocked=$blocked, rate=${rate}%"
    
    if [[ $blocked -gt 0 ]]; then
        log_pass "DDoS/CC protection triggered ($blocked/$total)"
    else
        log_warn "DDoS/CC protection did not trigger (may need higher load)"
    fi
    
    echo "ddos,total=$total,blocked=$blocked,rate=$rate" > "$RESULTS_DIR/ddos.csv"
}

#######################################
# 5. Brute Force Test
#######################################
run_bruteforce_test() {
    log_step "Brute Force Test"
    local total=10 blocked=0
    local path="/login"
    
    for i in $(seq 1 $total); do
        local http_code
        http_code=$(curl -s -o /dev/null -w "%{http_code}" \
            -X POST \
            --data "username=admin&password=wrong$i" \
            "http://127.0.0.1:$SHIELD_PORT$path" 2>/dev/null || echo "000")
        if [[ "$http_code" == "429" || "$http_code" == "403" ]]; then
            ((blocked++)) || true
        fi
    done
    
    log_info "Brute Force: total=$total, blocked=$blocked"
    
    if [[ $blocked -gt 0 ]]; then
        log_pass "Brute Force protection triggered ($blocked/$total)"
    else
        log_warn "Brute Force protection did not trigger (may need more attempts)"
    fi
    
    echo "bruteforce,total=$total,blocked=$blocked" > "$RESULTS_DIR/bruteforce.csv"
}

#######################################
# 6. Blacklist Test
#######################################
run_blacklist_test() {
    log_step "Blacklist Test"
    local http_code
    http_code=$(curl -s -o /dev/null -w "%{http_code}" \
        -H "X-Forwarded-For: 1.2.3.4" \
        "http://127.0.0.1:$SHIELD_PORT/" 2>/dev/null || echo "000")
    
    log_info "Blacklist test: HTTP $http_code"
    if [[ "$http_code" == "403" ]]; then
        log_pass "Blacklist IP blocked"
    else
        log_warn "Blacklist IP not blocked (may need manual blacklist entry)"
    fi
    
    echo "blacklist,http_code=$http_code" > "$RESULTS_DIR/blacklist.csv"
}

#######################################
# 7. Status File Test
#######################################
run_admin_test() {
    log_step "Status File Test"
    
    if [[ -f "$STATUS_FILE" ]]; then
        log_pass "Status file exists: $STATUS_FILE"
        if command -v python3 &>/dev/null; then
            log_info "$(python3 -m json.tool "$STATUS_FILE" 2>/dev/null | head -20)"
        elif command -v jq &>/dev/null; then
            log_info "$(jq '.' "$STATUS_FILE" 2>/dev/null | head -20)"
        else
            log_info "$(head -20 "$STATUS_FILE")"
        fi
    else
        log_fail "Status file not found: $STATUS_FILE (is server running?)"
    fi

    echo "admin,health=n/a,stats=n/a" > "$RESULTS_DIR/admin.csv"
}

#######################################
# Main
#######################################
main() {
    log_info "Shield WAF Batch Test Tool"
    log_info "Project:  $PROJECT_DIR"
    log_info "Dataset:  $DATASET_DIR"
    log_info "Results:  $RESULTS_DIR"
    
    check_prereqs
    start_backend
    start_shield
    
    run_normal_test
    run_sql_injection_test
    run_xss_test
    run_ddos_test
    run_bruteforce_test
    run_blacklist_test
    run_admin_test
    
    log_step "Summary"
    log_info "PASS: $PASS  FAIL: $FAIL  WARN: $WARN"
    
    if [[ $FAIL -gt 0 ]]; then
        log_fail "Some critical tests failed."
        exit 1
    else
        log_pass "All critical tests passed."
        exit 0
    fi
}

main "$@"
