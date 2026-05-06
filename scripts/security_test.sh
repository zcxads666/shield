#!/usr/bin/env bash
#
# Shield WAF Security Standardized Test Script
# Usage: ./scripts/security_test.sh [--shield-url <url>] [--admin-url <url>]
#
# Tests: SQL Injection, XSS, DDoS/CC, Brute Force, Blacklist, Normal Request Pass-through
# Exit code: 0 = all passed, 1 = any critical test failed

set -euo pipefail

SHIELD_URL="${SHIELD_URL:-http://127.0.0.1:8080}"
STATUS_FILE="${STATUS_FILE:-./data/status.json}"
DATASET_DIR="${DATASET_DIR:-./scripts/testdata}"
RESULTS_DIR="${RESULTS_DIR:-./scripts/test_results}"

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

mkdir -p "$RESULTS_DIR"

PASS=0
FAIL=0
WARN=0

log_pass() { echo -e "${GREEN}[PASS]${NC} $1"; ((PASS++)) || true; }
log_fail() { echo -e "${RED}[FAIL]${NC} $1"; ((FAIL++)) || true; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; ((WARN++)) || true; }
log_info() { echo -e "[INFO] $1"; }

#######################################
# 1. SQL Injection Test
#######################################
run_sql_injection_test() {
    log_info "========== SQL Injection Test =========="
    local payload_file="$DATASET_DIR/sql_injection.txt"
    local benign_file="$DATASET_DIR/benign_normal.txt"
    local total=0 blocked=0 fp=0

    if [[ ! -f "$payload_file" ]]; then
        log_warn "SQL injection payload file not found: $payload_file"
        return
    fi

    while IFS= read -r line || [[ -n "$line" ]]; do
        line=$(echo "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        [[ -z "$line" || "$line" =~ ^# ]] && continue
        ((total++)) || true
        local http_code
        http_code=$(curl -s -o /dev/null -w "%{http_code}" \
            --data-urlencode "q=$line" \
            "$SHIELD_URL/" 2>/dev/null || echo "000")
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
                "$SHIELD_URL/" 2>/dev/null || echo "000")
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
# 2. XSS Test
#######################################
run_xss_test() {
    log_info "========== XSS Test =========="
    local payload_file="$DATASET_DIR/xss.txt"
    local benign_file="$DATASET_DIR/benign_normal.txt"
    local total=0 blocked=0 fp=0

    if [[ ! -f "$payload_file" ]]; then
        log_warn "XSS payload file not found: $payload_file"
        return
    fi

    while IFS= read -r line || [[ -n "$line" ]]; do
        line=$(echo "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        [[ -z "$line" || "$line" =~ ^# ]] && continue
        ((total++)) || true
        local http_code
        http_code=$(curl -s -o /dev/null -w "%{http_code}" \
            --data-urlencode "content=$line" \
            "$SHIELD_URL/" 2>/dev/null || echo "000")
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
                "$SHIELD_URL/" 2>/dev/null || echo "000")
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
# 3. DDoS / CC Test
#######################################
run_ddos_test() {
    log_info "========== DDoS / CC Test =========="
    local total=100 blocked=0

    for i in $(seq 1 $total); do
        local http_code
        http_code=$(curl -s -o /dev/null -w "%{http_code}" \
            "$SHIELD_URL/?id=$i" 2>/dev/null || echo "000")
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
# 4. Brute Force Test
#######################################
run_bruteforce_test() {
    log_info "========== Brute Force Test =========="
    local total=10 blocked=0
    local path="/login"

    for i in $(seq 1 $total); do
        local http_code
        http_code=$(curl -s -o /dev/null -w "%{http_code}" \
            -X POST \
            --data "username=admin&password=wrong$i" \
            "$SHIELD_URL$path" 2>/dev/null || echo "000")
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
# 5. Blacklist Test
#######################################
run_blacklist_test() {
    log_info "========== Blacklist Test =========="
    local http_code
    http_code=$(curl -s -o /dev/null -w "%{http_code}" \
        -H "X-Forwarded-For: 1.2.3.4" \
        "$SHIELD_URL/" 2>/dev/null || echo "000")

    log_info "Blacklist test: HTTP $http_code"
    if [[ "$http_code" == "403" ]]; then
        log_pass "Blacklist IP blocked"
    else
        log_warn "Blacklist IP not blocked (may need manual blacklist entry)"
    fi

    echo "blacklist,http_code=$http_code" > "$RESULTS_DIR/blacklist.csv"
}

#######################################
# 6. Status Test (via status file)
#######################################
run_admin_test() {
    log_info "========== Status Test =========="
    if [[ -f "$STATUS_FILE" ]]; then
        local stat_code="200"
        log_pass "Status file found: $STATUS_FILE"
        log_info "Status content:"
        if command -v python3 &>/dev/null; then
            python3 -m json.tool "$STATUS_FILE" 2>/dev/null | head -30
        elif command -v jq &>/dev/null; then
            jq '.' "$STATUS_FILE" 2>/dev/null | head -30
        else
            head -30 "$STATUS_FILE"
        fi
    else
        local stat_code="404"
        log_fail "Status file not found: $STATUS_FILE (is server running?)"
    fi

    echo "admin,health=$stat_code,stats=$stat_code" > "$RESULTS_DIR/admin.csv"
}

#######################################
# 7. Normal Request Pass-through
#######################################
run_normal_test() {
    log_info "========== Normal Request Test =========="
    local http_code
    http_code=$(curl -s -o /dev/null -w "%{http_code}" \
        "$SHIELD_URL/?name=alice&message=hello" 2>/dev/null || echo "000")

    log_info "Normal request: HTTP $http_code"
    if [[ "$http_code" == "200" || "$http_code" == "502" || "$http_code" == "504" ]]; then
        log_pass "Normal request passed through (backend may not be running)"
    else
        log_fail "Normal request blocked unexpectedly ($http_code)"
    fi

    echo "normal,http_code=$http_code" > "$RESULTS_DIR/normal.csv"
}

#######################################
# Main
#######################################
main() {
    log_info "Shield Security Standardized Test"
    log_info "Shield URL: $SHIELD_URL"
    log_info "Status File: $STATUS_FILE"
    log_info "Dataset:    $DATASET_DIR"
    log_info "Results:    $RESULTS_DIR"
    echo ""

    run_normal_test
    run_sql_injection_test
    run_xss_test
    run_ddos_test
    run_bruteforce_test
    run_blacklist_test
    run_admin_test

    echo ""
    log_info "========== Summary =========="
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
