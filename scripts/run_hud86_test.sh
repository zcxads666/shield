#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# HUD-86: QA Comprehensive Verification Test Suite
# ============================================================
# Tests CC, DDoS, Brute Force, SQLi, XSS, WebShell, FP, Mixed
# Uses a dedicated test shield instance with appropriate thresholds.

SHIELD_DIR="/root/shield"
TEST_CONFIG="$SHIELD_DIR/test_config_hud86.yaml"
SHIELD_PORT=18080
ADMIN_PORT=19090
BACKEND_PORT=18081

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASS=0; FAIL=0

pass_msg() { echo -e "${GREEN}[PASS]${NC} $1"; ((PASS++)); }
fail_msg() { echo -e "${RED}[FAIL]${NC} $1"; ((FAIL++)); }
info_msg() { echo -e "${YELLOW}[INFO]${NC} $1"; }

# Cleanup on exit
cleanup() {
    info_msg "Cleaning up..."
    [[ -n "${SHIELD_PID:-}" ]] && kill "$SHIELD_PID" 2>/dev/null || true
    [[ -n "${SHIELD_PID:-}" ]] && wait "$SHIELD_PID" 2>/dev/null || true
    [[ -n "${BACKEND_PID:-}" ]] && kill "$BACKEND_PID" 2>/dev/null || true
    [[ -n "${BACKEND_PID:-}" ]] && wait "$BACKEND_PID" 2>/dev/null || true
    rm -f "$SHIELD_DIR/mock_backend.go"
    rm -f /tmp/test_blacklist.json /tmp/test_rules.yaml
}
trap cleanup EXIT

# Start mock backend
info_msg "Starting mock backend on :$BACKEND_PORT..."
cat > "$SHIELD_DIR/mock_backend.go" << 'GOEOF'
package main
import ("fmt"; "net/http"; "strings")
func main() {
    http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "text/html")
        fmt.Fprintf(w, "<html><body><h1>OK</h1><p>Path: %s</p></body></html>", r.URL.Path)
    })
    http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
        if r.Method == "POST" {
            w.WriteHeader(http.StatusUnauthorized)
            fmt.Fprint(w, `{"error":"invalid credentials"}`)
        } else {
            fmt.Fprint(w, `<html><form method="post"><input name="user"/></form></html>`)
        }
    })
    http.HandleFunc("/upload", func(w http.ResponseWriter, r *http.Request) {
        fmt.Fprint(w, `{"status":"uploaded"}`)
    })
    http.HandleFunc("/search", func(w http.ResponseWriter, r *http.Request) {
        if r.Method == "POST" {
            r.ParseForm()
            q := r.FormValue("q")
            if strings.Contains(q, "'") || strings.Contains(q, "UNION") {
                w.WriteHeader(http.StatusInternalServerError)
                fmt.Fprint(w, `<html><h1>Error</h1><p>SQL error near '${q}'</p></html>`)
            } else {
                fmt.Fprintf(w, `<html><body><h1>Search Results</h1><p>Query: %s</p></body></html>`, q)
            }
        } else {
            fmt.Fprint(w, `<html><form method="post"><input name="q"/></form></html>`)
        }
    })
    http.HandleFunc("/comment", func(w http.ResponseWriter, r *http.Request) {
        fmt.Fprint(w, `{"status":"posted"}`)
    })
    http.HandleFunc("/contact", func(w http.ResponseWriter, r *http.Request) {
        fmt.Fprint(w, `{"status":"received"}`)
    })
    fmt.Println("Mock backend listening on :18081")
    http.ListenAndServe(":18081", nil)
}
GOEOF
cd "$SHIELD_DIR" && go run mock_backend.go &
BACKEND_PID=$!
sleep 2

# Verify backend
if curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:$BACKEND_PORT/" | grep -q "200"; then
    pass_msg "Mock backend started"
else
    fail_msg "Mock backend failed to start"
    exit 1
fi

# Build shield if needed
if [[ ! -f "$SHIELD_DIR/bin/shield" ]]; then
    info_msg "Building shield..."
    cd "$SHIELD_DIR" && go build -o bin/shield ./cmd/shield
fi

# Start shield with test config
info_msg "Starting test shield on :$SHIELD_PORT..."
cd "$SHIELD_DIR" && ./bin/shield -config "$TEST_CONFIG" &
SHIELD_PID=$!
sleep 3

# Verify shield
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:$SHIELD_PORT/" 2>/dev/null || echo "000")
if [[ "$HTTP_CODE" == "200" ]]; then
    pass_msg "Test shield started (HTTP $HTTP_CODE)"
else
    fail_msg "Test shield failed to start (HTTP $HTTP_CODE)"
    exit 1
fi

# ============================================================
# Run the Go verification program against test shield
# ============================================================
info_msg "Building verification program..."
cat > "$SHIELD_DIR/scripts/hud86_runner.go" << 'GOEOF'
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	shieldURL  = "http://127.0.0.1:18080"
	adminURL   = "http://127.0.0.1:19090"
	timeout    = 10 * time.Second
	reportFile = "/root/shield/scripts/test_results/hud86_verification_report.json"
)

const (
	ipCC = "10.0.0.1"; ipDDoS = "10.0.0.2"; ipBF = "10.0.0.3"
	ipSQLi = "10.0.0.4"; ipXSS = "10.0.0.5"; ipWS = "10.0.0.6"
	ipNormal = "10.0.0.7"; ipMixedCC = "10.0.0.8"; ipMixedDD = "10.0.0.9"
	ipMixedBF = "10.0.0.10"; ipMixedSQ = "10.0.0.11"
)

type TestResult struct {
	Name        string      `json:"name"`
	Total       int         `json:"total"`
	Blocked     int         `json:"blocked"`
	Passed      int         `json:"passed"`
	BlockRate   float64     `json:"block_rate"`
	IdentOK     int         `json:"ident_ok"`
	IdentWrong  int         `json:"ident_wrong"`
	IdentRate   float64     `json:"ident_accuracy"`
	WrongItems  []WrongItem `json:"wrong_items,omitempty"`
	PassedCheck bool        `json:"passed_check"`
	Notes       string      `json:"notes,omitempty"`
}

type WrongItem struct {
	Payload      string `json:"payload"`
	ExpectedType string `json:"expected_type"`
	ActualType   string `json:"actual_type,omitempty"`
	HTTPCode     int    `json:"http_code"`
	Issue        string `json:"issue"`
}

type Report struct {
	Timestamp      string                 `json:"timestamp"`
	Issue          string                 `json:"issue"`
	TestConfig     string                 `json:"test_config"`
	Summary        map[string]TestResult  `json:"summary"`
	OverallPass    bool                   `json:"overall_pass"`
	PassRate       float64                `json:"pass_rate"`
	RiskAssessment string                 `json:"risk_assessment"`
}

var client = &http.Client{Timeout: timeout}

func main() {
	fmt.Println("==============================================")
	fmt.Println("  HUD-86 QA Verification - Test Suite")
	fmt.Println("  Target:", shieldURL)
	fmt.Println("==============================================")
	fmt.Println()

	os.MkdirAll("/root/shield/scripts/test_results", 0755)

	report := Report{
		Timestamp:  time.Now().Format(time.RFC3339),
		Issue:      "HUD-86",
		TestConfig: "test_config_hud86.yaml (CC: 15/30/60s, BF: 5/60s, DDoS rate: 100rps/300burst)",
		Summary:    make(map[string]TestResult),
	}

	results := make(map[string]TestResult)

	results["cc_attack"] = testCCAttack()
	fmt.Println()
	results["ddos_attack"] = testDDoSAttack()
	fmt.Println()
	results["brute_force"] = testBruteForce()
	fmt.Println()
	results["sql_injection"] = testSQLInjection()
	fmt.Println()
	results["xss"] = testXSS()
	fmt.Println()
	results["webshell_upload"] = testWebShellUpload()
	fmt.Println()
	results["normal_requests"] = testNormalRequests()
	fmt.Println()
	results["mixed_cc_ddos"] = testMixedCCDDoS()
	fmt.Println()
	results["mixed_bruteforce_sqli"] = testMixedBruteForceSQLi()
	fmt.Println()

	allPassed := true
	passCount := 0
	for _, r := range results {
		if r.PassedCheck {
			passCount++
		} else {
			allPassed = false
		}
	}
	overallPassRate := float64(passCount) / float64(len(results)) * 100

	report.Summary = results
	report.OverallPass = allPassed
	report.PassRate = overallPassRate

	if allPassed {
		report.RiskAssessment = "LOW - All verification items passed"
	} else if overallPassRate >= 80 {
		report.RiskAssessment = "MEDIUM - Most items passed, some need attention"
	} else {
		report.RiskAssessment = "HIGH - Multiple failures, fixes may be incomplete"
	}

	fmt.Println("==============================================")
	fmt.Println("  VERIFICATION SUMMARY")
	fmt.Println("==============================================")
	keys := []string{"cc_attack","ddos_attack","brute_force","sql_injection","xss","webshell_upload","normal_requests","mixed_cc_ddos","mixed_bruteforce_sqli"}
	for _, k := range keys {
		r := results[k]
		status := "PASS"
		if !r.PassedCheck { status = "FAIL" }
		fmt.Printf("  [%s] %-22s: block=%5.1f%%  ident=%5.1f%%  %s\n", status, r.Name, r.BlockRate, r.IdentRate, r.Notes)
	}
	fmt.Printf("\n  Overall: %s  (%.0f%% items pass)\n", map[bool]string{true:"PASS",false:"FAIL"}[allPassed], overallPassRate)
	fmt.Printf("  Risk:    %s\n", report.RiskAssessment)

	data, _ := json.MarshalIndent(report, "", "  ")
	os.WriteFile(reportFile, data, 0644)
	fmt.Printf("\n  Report saved to: %s\n", reportFile)
}

func doReq(ip, method, path string, headers map[string]string, body []byte) (int, string) {
	req, _ := http.NewRequest(method, shieldURL+path, bytes.NewReader(body))
	req.Header.Set("X-Forwarded-For", ip)
	for k, v := range headers { req.Header.Set(k, v) }
	resp, err := client.Do(req)
	if err != nil { return 0, "" }
	defer resp.Body.Close()
	io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header.Get("X-Block-Reason")
}

func getIP(ip, path string) (int, string) { return doReq(ip, "GET", path, nil, nil) }
func postFormIP(ip, path string, data url.Values) (int, string) {
	body := data.Encode()
	return doReq(ip, "POST", path, map[string]string{"Content-Type":"application/x-www-form-urlencoded"}, []byte(body))
}
func doUploadIP(ip, path, filename, content string) (int, string) {
	buf := &bytes.Buffer{}
	w := multipart.NewWriter(buf)
	p, _ := w.CreateFormFile("file", filename)
	p.Write([]byte(content))
	w.Close()
	req, _ := http.NewRequest("POST", shieldURL+path, buf)
	req.Header.Set("X-Forwarded-For", ip)
	req.Header.Set("Content-Type", w.FormDataContentType())
	resp, err := client.Do(req)
	if err != nil { return 0, "" }
	defer resp.Body.Close()
	io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header.Get("X-Block-Reason")
}

func blocked(code int) bool { return code == 403 || code == 429 }

// ============ CC Attack ============
func testCCAttack() TestResult {
	fmt.Println("--- CC Attack (IP:", ipCC, ") ---")
	r := TestResult{Name: "CC Attack", PassedCheck: true}
	count := 60
	var blk, ok, wr int
	var wi []WrongItem

	for i := 0; i < count; i++ {
		code, reason := getIP(ipCC, fmt.Sprintf("/cc-target?id=%d", i))
		if blocked(code) {
			blk++
			if reason == "cc_attack" { ok++ } else {
				wr++; wi = append(wi, WrongItem{Payload: fmt.Sprintf("GET /cc-target?id=%d", i), ExpectedType: "cc_attack", ActualType: reason, HTTPCode: code, Issue: "wrong label"})
			}
		}
		time.Sleep(60 * time.Millisecond)
	}

	r.Total = count; r.Blocked = blk; r.Passed = count - blk
	if count > 0 { r.BlockRate = float64(blk)/float64(count)*100 }
	r.IdentOK = ok; r.IdentWrong = wr
	if blk > 0 { r.IdentRate = float64(ok)/float64(blk)*100 }
	r.WrongItems = wi

	fmt.Printf("  CC: %d req, %d blocked (%.1f%%), ident=%d/%d\n", count, blk, r.BlockRate, ok, blk)
	if !check(&r, "block_rate>=95", r.BlockRate >= 95) {}
	if !check(&r, "ident=100", r.IdentRate >= 99) {}
	return r
}

// ============ DDoS Attack ============
func testDDoSAttack() TestResult {
	fmt.Println("--- DDoS Attack (IP:", ipDDoS, ") ---")
	r := TestResult{Name: "DDoS Attack", PassedCheck: true}
	paths := []string{"/d/a","/d/b","/d/c","/d/d","/d/e","/d/f","/d/g","/d/h","/d/i","/d/j","/d/k","/d/l"}
	var blk, ok, wr int64
	var wg sync.WaitGroup
	var mu sync.Mutex
	var wi []WrongItem

	for w := 0; w < 10; w++ {
		wg.Add(1)
		go func(wid int) {
			defer wg.Done()
			for i := 0; i < 30; i++ {
				path := paths[(wid*30+i)%len(paths)]
				code, reason := getIP(ipDDoS, path+fmt.Sprintf("?p=%d&w=%d", i, wid))
				if blocked(code) {
					atomic.AddInt64(&blk, 1)
					if strings.HasPrefix(reason, "ddos_attack") { atomic.AddInt64(&ok, 1) } else {
						atomic.AddInt64(&wr, 1)
						mu.Lock(); wi = append(wi, WrongItem{Payload: fmt.Sprintf("GET %s", path), ExpectedType: "ddos_attack:*", ActualType: reason, HTTPCode: code, Issue: "wrong label"}); mu.Unlock()
					}
				}
			}
		}(w)
	}
	wg.Wait()

	total := 300
	r.Total = total; r.Blocked = int(blk); r.Passed = total - int(blk)
	if total > 0 { r.BlockRate = float64(blk)/float64(total)*100 }
	r.IdentOK = int(ok); r.IdentWrong = int(wr)
	if blk > 0 { r.IdentRate = float64(ok)/float64(blk)*100 }
	r.WrongItems = wi

	fmt.Printf("  DDoS: %d req, %d blocked (%.1f%%), ident=%d/%d\n", total, blk, r.BlockRate, ok, blk)
	check(&r, "block_rate>=95", r.BlockRate >= 95)
	check(&r, "ident=100", r.IdentRate >= 99)
	if len(wi) > 0 && len(wi) <= 5 {
		for _, w := range wi { fmt.Printf("    Wrong: %s -> %s\n", w.Payload, w.ActualType) }
	}
	return r
}

// ============ Brute Force ============
func testBruteForce() TestResult {
	fmt.Println("--- Brute Force (IP:", ipBF, ") ---")
	r := TestResult{Name: "Brute Force", PassedCheck: true}
	count := 15; var blk, ok, wr int; var firstBlk int = -1
	var wi []WrongItem

	for i := 0; i < count; i++ {
		data := url.Values{"username":{"admin"},"password":{fmt.Sprintf("guess%d",i)}}
		code, reason := postFormIP(ipBF, "/login", data)
		if blocked(code) {
			blk++; if firstBlk == -1 { firstBlk = i+1 }
			if reason == "brute_force" { ok++ } else {
				wr++; wi = append(wi, WrongItem{Payload: fmt.Sprintf("POST /login #%d", i+1), ExpectedType: "brute_force", ActualType: reason, HTTPCode: code, Issue: "wrong label"})
			}
		}
		time.Sleep(30 * time.Millisecond)
	}

	r.Total = count; r.Blocked = blk; r.Passed = count - blk
	if count > 0 { r.BlockRate = float64(blk)/float64(count)*100 }
	r.IdentOK = ok; r.IdentWrong = wr
	if blk > 0 { r.IdentRate = float64(ok)/float64(blk)*100 }
	r.WrongItems = wi
	if firstBlk > 0 { r.Notes = fmt.Sprintf("first_block=#%d", firstBlk) }

	fmt.Printf("  BF: %d req, %d blocked (%.1f%%), ident=%d/%d, first=#%d\n", count, blk, r.BlockRate, ok, blk, firstBlk)
	check(&r, "block_rate>=95", r.BlockRate >= 95)
	check(&r, "ident=100", r.IdentRate >= 99)
	return r
}

// ============ SQL Injection ============
func testSQLInjection() TestResult {
	fmt.Println("--- SQL Injection (IP:", ipSQLi, ") ---")
	r := TestResult{Name: "SQL Injection", PassedCheck: true}
	payloads := []string{
		"1' UNION SELECT username, password FROM users--",
		"' UNION SELECT * FROM information_schema.tables--",
		"1' AND 1=1--",
		"1' AND extractvalue(1, concat(0x7e, (SELECT @@version)))--",
		"1; DROP TABLE users--",
		"1' OR '1'='1",
		"-1 UNION SELECT 1,2,3--",
		"1' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>64--",
		"1%27%20UNION%20SELECT%20*%20FROM%20users--",
		"1/**/UNION/**/SELECT/**/username,password/**/FROM/**/users--",
		"1' AND SLEEP(5)--",
		"1' AND 1=convert(int,@@version)--",
		"' OR 1=1--",
		"admin'--",
		"1 ORDER BY 10--",
		"1' UNION SELECT '<?php eval($_POST[1]);?>' INTO OUTFILE '/tmp/shell.php'--",
		"1'; EXEC master..xp_cmdshell 'whoami'--",
		"1' GROUP BY users.id HAVING 1=1--",
		"1 AND (SELECT COUNT(*) FROM information_schema.tables)>0",
		"1' && '1'='1",
	}
	var blk, ok, wr, pen int
	var wi []WrongItem

	for _, p := range payloads {
		data := url.Values{"q":{p}}
		code, reason := postFormIP(ipSQLi, "/search", data)
		if code == 403 {
			blk++
			if reason == "sql_injection" { ok++ } else {
				wr++; wi = append(wi, WrongItem{Payload: p, ExpectedType: "sql_injection", ActualType: reason, HTTPCode: code, Issue: "wrong label"})
			}
		} else if code < 400 {
			pen++; wi = append(wi, WrongItem{Payload: p, ExpectedType: "sql_injection", HTTPCode: code, Issue: "penetrated"})
		}
		time.Sleep(5 * time.Millisecond)
	}

	r.Total = len(payloads); r.Blocked = blk; r.Passed = r.Total - blk
	if r.Total > 0 { r.BlockRate = float64(blk)/float64(r.Total)*100 }
	r.IdentOK = ok; r.IdentWrong = wr
	if blk > 0 { r.IdentRate = float64(ok)/float64(blk)*100 }
	r.WrongItems = wi

	fmt.Printf("  SQLi: %d payloads, %d blocked (%.1f%%), ident=%d/%d, penetrated=%d\n", r.Total, blk, r.BlockRate, ok, blk, pen)
	check(&r, "block_rate>=95", r.BlockRate >= 95)
	check(&r, "ident=100", r.IdentRate >= 99)
	return r
}

// ============ XSS ============
func testXSS() TestResult {
	fmt.Println("--- XSS (IP:", ipXSS, ") ---")
	r := TestResult{Name: "XSS", PassedCheck: true}
	payloads := []string{
		"<script>alert('xss')</script>",
		"<script>alert(document.cookie)</script>",
		"<img src=x onerror=alert(1)>",
		"<body onload=alert('xss')>",
		`<a href="javascript:alert(1)">click</a>`,
		"<svg onload=alert(1)>",
		"<iframe onload=alert(1)>",
		"javascript:alert(1)",
		"<ScRiPt>alert(1)</ScRiPt>",
		"%3Cscript%3Ealert(1)%3C%2Fscript%3E",
		"<img src=1 onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
		"<svg><script>alert&#40;1&#41;</script></svg>",
		"<marquee onstart=alert(1)>",
		"<details open ontoggle=alert(1)>",
		"<button onclick=alert(1)>click</button>",
		"<input onfocus=alert(1) autofocus>",
		"data:text/html,<script>alert(1)</script>",
		`<object data="javascript:alert(1)">`,
		`<embed src="javascript:alert(1)">`,
		"<scr%00ipt>alert(1)</scr%00ipt>",
	}
	var blk, ok, wr, pen int
	var wi []WrongItem

	for _, p := range payloads {
		data := url.Values{"content":{p}}
		code, reason := postFormIP(ipXSS, "/comment", data)
		if code == 403 {
			blk++
			if reason == "xss" { ok++ } else {
				wr++; wi = append(wi, WrongItem{Payload: p, ExpectedType: "xss", ActualType: reason, HTTPCode: code, Issue: "wrong label"})
			}
		} else if code < 400 {
			pen++; wi = append(wi, WrongItem{Payload: p, ExpectedType: "xss", HTTPCode: code, Issue: "penetrated"})
		}
		time.Sleep(5 * time.Millisecond)
	}

	r.Total = len(payloads); r.Blocked = blk; r.Passed = r.Total - blk
	if r.Total > 0 { r.BlockRate = float64(blk)/float64(r.Total)*100 }
	r.IdentOK = ok; r.IdentWrong = wr
	if blk > 0 { r.IdentRate = float64(ok)/float64(blk)*100 }
	r.WrongItems = wi

	fmt.Printf("  XSS: %d payloads, %d blocked (%.1f%%), ident=%d/%d, penetrated=%d\n", r.Total, blk, r.BlockRate, ok, blk, pen)
	check(&r, "block_rate>=95", r.BlockRate >= 95)
	check(&r, "ident=100", r.IdentRate >= 99)
	return r
}

// ============ WebShell ============
func testWebShellUpload() TestResult {
	fmt.Println("--- WebShell (IP:", ipWS, ") ---")
	r := TestResult{Name: "WebShell Upload", PassedCheck: true}
	type p struct { fn, ct string }
	payloads := []p{
		{"shell.php","<?php eval($_POST['cmd']); ?>"},
		{"shell.phtml","<?php system($_GET['c']); ?>"},
		{"shell.php5","<?php @eval($_REQUEST['shell']);?>"},
		{"cmd.jsp","<% Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>"},
		{"shell.asp","<% eval request(\"cmd\") %>"},
		{"shell.aspx","<%@ Page Language=\"C#\" %><% System.Diagnostics.Process.Start(\"cmd.exe\"); %>"},
		{"shell.php.jpg","<?php eval($_POST['cmd']); ?>"},
		{"shell.php;.jpg","<?php system('id'); ?>"},
	}
	var blk, ok, wr, pen int
	var wi []WrongItem

	for _, p := range payloads {
		code, reason := doUploadIP(ipWS, "/upload", p.fn, p.ct)
		if code == 403 {
			blk++
			if reason == "webshell_upload" { ok++ } else {
				wr++; wi = append(wi, WrongItem{Payload: fmt.Sprintf("file=%s",p.fn), ExpectedType: "webshell_upload", ActualType: reason, HTTPCode: code, Issue: "wrong label"})
			}
		} else if code < 400 {
			pen++; wi = append(wi, WrongItem{Payload: fmt.Sprintf("file=%s",p.fn), ExpectedType: "webshell_upload", HTTPCode: code, Issue: "penetrated"})
		}
		time.Sleep(5 * time.Millisecond)
	}

	r.Total = len(payloads); r.Blocked = blk; r.Passed = r.Total - blk
	if r.Total > 0 { r.BlockRate = float64(blk)/float64(r.Total)*100 }
	r.IdentOK = ok; r.IdentWrong = wr
	if blk > 0 { r.IdentRate = float64(ok)/float64(blk)*100 }
	r.WrongItems = wi

	fmt.Printf("  WebShell: %d payloads, %d blocked (%.1f%%), ident=%d/%d, penetrated=%d\n", r.Total, blk, r.BlockRate, ok, blk, pen)
	check(&r, "block_rate>=95", r.BlockRate >= 95)
	check(&r, "ident=100", r.IdentRate >= 99)
	return r
}

// ============ Normal Requests ============
func testNormalRequests() TestResult {
	fmt.Println("--- Normal Requests FP Check (IP:", ipNormal, ") ---")
	r := TestResult{Name: "Normal Requests", PassedCheck: true}

	type req struct { m, p, ct, b string }
	normals := []req{
		{"GET","/","",""},
		{"GET","/index.html","",""},
		{"GET","/about","",""},
		{"GET","/search?q=hello+world","",""},
		{"GET","/api/v1/users?page=1&limit=20","",""},
		{"POST","/login","application/x-www-form-urlencoded","username=alice&password=MySecureP@ss123"},
		{"POST","/contact","application/x-www-form-urlencoded","name=Alice&email=a@b.com&message=Hello"},
		{"POST","/api/v1/comments","application/json",`{"post_id":42,"content":"Great article!"}`},
	}
	var blk int
	var wi []WrongItem

	for _, n := range normals {
		h := map[string]string{}
		if n.ct != "" { h["Content-Type"] = n.ct }
		code, reason := doReq(ipNormal, n.m, n.p, h, []byte(n.b))
		if blocked(code) {
			blk++; wi = append(wi, WrongItem{Payload: fmt.Sprintf("%s %s",n.m,n.p), ExpectedType: "none", ActualType: reason, HTTPCode: code, Issue: "FALSE POSITIVE"})
		}
		time.Sleep(30 * time.Millisecond)
	}

	r.Total = len(normals); r.Blocked = blk; r.Passed = r.Total - blk; r.IdentOK = r.Total - blk; r.IdentRate = 100
	if r.Total > 0 { r.BlockRate = float64(blk)/float64(r.Total)*100 }
	r.WrongItems = wi

	fmt.Printf("  Normal: %d req, %d blocked (FP=%.1f%%)\n", r.Total, blk, r.BlockRate)
	check(&r, "zero_fp", blk == 0)
	return r
}

// ============ Mixed CC + DDoS ============
func testMixedCCDDoS() TestResult {
	fmt.Println("--- Mixed CC+DDoS (IPs:", ipMixedCC, ",", ipMixedDD, ") ---")
	r := TestResult{Name: "Mixed CC+DDoS", PassedCheck: true}
	var wg sync.WaitGroup
	var ccB, ccOK, ddB, ddOK int64

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 30; i++ {
			code, reason := getIP(ipMixedCC, fmt.Sprintf("/mix-cc?id=%d", i))
			if blocked(code) { atomic.AddInt64(&ccB, 1); if reason == "cc_attack" { atomic.AddInt64(&ccOK, 1) } }
			time.Sleep(50 * time.Millisecond)
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		paths := []string{"/mx/a","/mx/b","/mx/c","/mx/d","/mx/e","/mx/f","/mx/g","/mx/h","/mx/i","/mx/j"}
		for i := 0; i < 30; i++ {
			code, reason := getIP(ipMixedDD, paths[i%len(paths)]+fmt.Sprintf("?x=%d", i))
			if blocked(code) { atomic.AddInt64(&ddB, 1); if strings.HasPrefix(reason, "ddos_attack") { atomic.AddInt64(&ddOK, 1) } }
		}
	}()

	wg.Wait()

	total := 60; allB := int(ccB)+int(ddB); allOK := int(ccOK)+int(ddOK)
	r.Total = total; r.Blocked = allB
	if total > 0 { r.BlockRate = float64(allB)/float64(total)*100 }
	r.IdentOK = allOK; r.IdentWrong = allB - allOK
	if allB > 0 { r.IdentRate = float64(allOK)/float64(allB)*100 }
	r.Notes = fmt.Sprintf("cc=%d ddos=%d cc_ok=%d ddos_ok=%d", ccB, ddB, ccOK, ddOK)

	fmt.Printf("  Mixed CC+DDoS: %d req, cc=%d ddos=%d blocked, ident=%d/%d\n", total, ccB, ddB, allOK, allB)
	check(&r, "both_detected", ccB > 0 && ddB > 0)
	check(&r, "correct_ident", r.IdentRate >= 95)
	return r
}

// ============ Mixed BF + SQLi ============
func testMixedBruteForceSQLi() TestResult {
	fmt.Println("--- Mixed BF+SQLi (IPs:", ipMixedBF, ",", ipMixedSQ, ") ---")
	r := TestResult{Name: "Mixed BruteForce+SQLi", PassedCheck: true}
	var wg sync.WaitGroup
	var bfB, bfOK, sqB, sqOK int64

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 12; i++ {
			data := url.Values{"username":{"admin"},"password":{fmt.Sprintf("bf%d",i)}}
			code, reason := postFormIP(ipMixedBF, "/login", data)
			if blocked(code) { atomic.AddInt64(&bfB, 1); if reason == "brute_force" { atomic.AddInt64(&bfOK, 1) } }
			time.Sleep(30 * time.Millisecond)
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		pl := []string{"1' UNION SELECT * FROM users--","' OR '1'='1","1; DROP TABLE users--","1' AND 1=1--","1' OR 1=1--"}
		for i := 0; i < 10; i++ {
			data := url.Values{"q":{pl[i%len(pl)]}}
			code, reason := postFormIP(ipMixedSQ, "/search", data)
			if code == 403 { atomic.AddInt64(&sqB, 1); if reason == "sql_injection" { atomic.AddInt64(&sqOK, 1) } }
			time.Sleep(30 * time.Millisecond)
		}
	}()

	wg.Wait()

	total := 22; allB := int(bfB)+int(sqB); allOK := int(bfOK)+int(sqOK)
	r.Total = total; r.Blocked = allB
	if total > 0 { r.BlockRate = float64(allB)/float64(total)*100 }
	r.IdentOK = allOK; r.IdentWrong = allB - allOK
	if allB > 0 { r.IdentRate = float64(allOK)/float64(allB)*100 }
	r.Notes = fmt.Sprintf("bf=%d sqli=%d bf_ok=%d sqli_ok=%d", bfB, sqB, bfOK, sqOK)

	fmt.Printf("  Mixed BF+SQLi: %d req, bf=%d sqli=%d blocked, ident=%d/%d\n", total, bfB, sqB, allOK, allB)
	check(&r, "both_detected", bfB > 0 && sqB > 0)
	check(&r, "correct_ident", r.IdentRate >= 95)
	return r
}

func check(r *TestResult, name string, pass bool) bool {
	if !pass { r.PassedCheck = false; fmt.Printf("    FAIL: %s\n", name) }
	return pass
}
GOEOF

cd "$SHIELD_DIR" && go run scripts/hud86_runner.go

echo ""
info_msg "Test suite complete. PASS=$PASS FAIL=$FAIL"

# Cleanup happens in trap
