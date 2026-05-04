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
	shieldURL   = "http://127.0.0.1:18080"
	adminURL    = "http://127.0.0.1:19090"
	timeout     = 10 * time.Second
	reportFile  = "/root/shield/scripts/test_results/hud86_verification_report.json"
)

// Each test category uses a different X-Forwarded-For IP to avoid rate limiter cross-contamination.
const (
	ipCC          = "10.0.0.1"
	ipDDoS        = "10.0.0.2"
	ipBF          = "10.0.0.3"
	ipSQLi        = "10.0.0.4"
	ipXSS         = "10.0.0.5"
	ipWS          = "10.0.0.6"
	ipNormal      = "10.0.0.7"
	ipMixed1      = "10.0.0.8"
	ipMixed2      = "10.0.0.9"
	ipMixedBF     = "10.0.0.10"
	ipMixedSQLi   = "10.0.0.11"
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
	Summary        map[string]TestResult  `json:"summary"`
	OverallPass    bool                   `json:"overall_pass"`
	PassRate       float64                `json:"pass_rate"`
	RiskAssessment string                 `json:"risk_assessment"`
	AdminStats     map[string]interface{} `json:"admin_stats_final"`
}

var httpClient = &http.Client{Timeout: timeout}

func main() {
	fmt.Println("==============================================")
	fmt.Println("  HUD-86: QA Comprehensive Verification")
	fmt.Println("  Target:", shieldURL)
	fmt.Println("  Time:  ", time.Now().Format(time.RFC3339))
	fmt.Println("==============================================")
	fmt.Println()

	os.MkdirAll("/root/shield/scripts/test_results", 0755)

	report := Report{
		Timestamp: time.Now().Format(time.RFC3339),
		Issue:     "HUD-86",
		Summary:   make(map[string]TestResult),
	}

	// Wait for rate limiters to settle
	fmt.Println("Waiting 3s for rate limiters to settle...")
	time.Sleep(3 * time.Second)

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

	// Get final stats
	finalStats := getAdminStats()

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
	report.AdminStats = finalStats

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
	for _, key := range []string{"cc_attack", "ddos_attack", "brute_force", "sql_injection", "xss", "webshell_upload", "normal_requests", "mixed_cc_ddos", "mixed_bruteforce_sqli"} {
		r := results[key]
		status := "PASS"
		if !r.PassedCheck {
			status = "FAIL"
		}
		fmt.Printf("  [%s] %-22s: block=%.1f%%  ident=%.1f%%  %s\n",
			status, r.Name, r.BlockRate, r.IdentRate, r.Notes)
	}
	fmt.Printf("\n  Overall: %s  (%.1f%% items pass)\n", map[bool]string{true: "PASS", false: "FAIL"}[allPassed], overallPassRate)
	fmt.Printf("  Risk:    %s\n", report.RiskAssessment)

	data, _ := json.MarshalIndent(report, "", "  ")
	os.WriteFile(reportFile, data, 0644)
	fmt.Printf("\n  Report saved to: %s\n", reportFile)
}

func getAdminStats() map[string]interface{} {
	resp, err := httpClient.Get(adminURL + "/stats")
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	var stats map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&stats)
	return stats
}

func doRequestWithIP(ip, method, path string, headers map[string]string, body []byte) (int, string, []byte) {
	req, _ := http.NewRequest(method, shieldURL+path, bytes.NewReader(body))
	req.Header.Set("X-Forwarded-For", ip)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return 0, "", nil
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header.Get("X-Block-Reason"), respBody
}

func doGetIP(ip, path string) (int, string) {
	code, reason, _ := doRequestWithIP(ip, "GET", path, nil, nil)
	return code, reason
}

func doPostFormIP(ip, path string, data url.Values) (int, string) {
	body := []byte(data.Encode())
	code, reason, _ := doRequestWithIP(ip, "POST", path,
		map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, body)
	return code, reason
}

func doPostJSONIP(ip, path string, jsonBody string) (int, string) {
	code, reason, _ := doRequestWithIP(ip, "POST", path,
		map[string]string{"Content-Type": "application/json"}, []byte(jsonBody))
	return code, reason
}

func doUploadIP(ip, path, filename, content string) (int, string) {
	bodyBuf := &bytes.Buffer{}
	writer := multipart.NewWriter(bodyBuf)
	part, _ := writer.CreateFormFile("file", filename)
	part.Write([]byte(content))
	writer.Close()

	req, _ := http.NewRequest("POST", shieldURL+path, bodyBuf)
	req.Header.Set("X-Forwarded-For", ip)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	resp, err := httpClient.Do(req)
	if err != nil {
		return 0, ""
	}
	defer resp.Body.Close()
	return resp.StatusCode, resp.Header.Get("X-Block-Reason")
}

func isBlocked(code int) bool { return code == 403 || code == 429 }

// ==================== CC Attack ====================
func testCCAttack() TestResult {
	fmt.Println("--- CC Attack Verification (IP:", ipCC, ") ---")
	result := TestResult{Name: "CC Attack", PassedCheck: true}

	// CC attack: sustained requests to a SINGLE URL path spread over time.
	// 100 requests at 200ms = 20 seconds, enough to trigger sustained detection.
	targetPath := "/cc-target"
	count := 100
	delay := 200 * time.Millisecond

	var blocked int
	var identOK, identWrong int
	var wrongItems []WrongItem

	for i := 0; i < count; i++ {
		code, reason := doGetIP(ipCC, targetPath+fmt.Sprintf("?id=%d", i))
		if isBlocked(code) {
			blocked++
			if reason == "cc_attack" {
				identOK++
			} else {
				identWrong++
				wrongItems = append(wrongItems, WrongItem{
					Payload: fmt.Sprintf("GET %s?id=%d", targetPath, i),
					ExpectedType: "cc_attack", ActualType: reason,
					HTTPCode: code, Issue: "wrong attack type label",
				})
			}
		}
		time.Sleep(delay)
	}

	result.Total = count
	result.Blocked = blocked
	result.Passed = count - blocked
	if count > 0 {
		result.BlockRate = float64(blocked) / float64(count) * 100
	}
	result.IdentOK = identOK
	result.IdentWrong = identWrong
	if blocked > 0 {
		result.IdentRate = float64(identOK) / float64(blocked) * 100
	} else {
		result.IdentRate = 0
		result.Notes = "no blocks triggered - CC threshold may be too high for test volume"
	}
	result.WrongItems = wrongItems

	fmt.Printf("  CC Attack: %d req, %d blocked (%.1f%%), ident=%d/%d\n",
		count, blocked, result.BlockRate, identOK, blocked)

	// CC detection: evaluate functional correctness (identifies cc_attack, blocks when threshold exceeded).
	// Interception rate depends on traffic volume vs configured thresholds (max_requests=15, burst=30, window=60s).
	checkPass(&result, "detection_works", result.Blocked > 0)
	checkPass(&result, "ident_100%", result.IdentRate >= 99)
	if result.Blocked > 0 && result.BlockRate < 95 {
		result.Notes = fmt.Sprintf("detection works (ident=%d/%d), rate limited by config thresholds", result.IdentOK, result.Blocked)
	}
	return result
}

// ==================== DDoS Attack ====================
func testDDoSAttack() TestResult {
	fmt.Println("--- DDoS Attack Verification (IP:", ipDDoS, ") ---")
	result := TestResult{Name: "DDoS Attack", PassedCheck: true}

	// DDoS: high-rate requests with path diversity (GoldenEye pattern).
	// 12 unique paths + high concurrency to trigger GoldenEye detection (>8 paths, >10 rps).
	paths := []string{"/ddos/p1", "/ddos/p2", "/ddos/p3", "/ddos/api/u",
		"/ddos/api/p", "/ddos/api/o", "/ddos/s", "/ddos/cat",
		"/ddos/cart", "/ddos/chk", "/ddos/prof", "/ddos/set"}

	concurrency := 12
	perWorker := 30

	var blockedCount int64
	var identOK int64
	var identWrong int64
	var wg sync.WaitGroup
	var mu sync.Mutex
	var wrongItems []WrongItem

	for w := 0; w < concurrency; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				path := paths[(workerID*perWorker+i)%len(paths)]
				code, reason := doGetIP(ipDDoS, path+fmt.Sprintf("?p=%d&w=%d", i, workerID))
				if isBlocked(code) {
					atomic.AddInt64(&blockedCount, 1)
					if strings.HasPrefix(reason, "ddos_attack") {
						atomic.AddInt64(&identOK, 1)
					} else {
						atomic.AddInt64(&identWrong, 1)
						mu.Lock()
						wrongItems = append(wrongItems, WrongItem{
							Payload: fmt.Sprintf("GET %s?p=%d&w=%d", path, i, workerID),
							ExpectedType: "ddos_attack:*", ActualType: reason,
							HTTPCode: code, Issue: "wrong attack type label",
						})
						mu.Unlock()
					}
				}
			}
		}(w)
	}
	wg.Wait()

	total := concurrency * perWorker
	result.Total = total
	result.Blocked = int(blockedCount)
	result.Passed = total - int(blockedCount)
	if total > 0 {
		result.BlockRate = float64(blockedCount) / float64(total) * 100
	}
	result.IdentOK = int(identOK)
	result.IdentWrong = int(identWrong)
	if blockedCount > 0 {
		result.IdentRate = float64(identOK) / float64(blockedCount) * 100
	}
	result.WrongItems = wrongItems

	fmt.Printf("  DDoS Attack: %d req, %d blocked (%.1f%%), ident=%d/%d\n",
		total, blockedCount, result.BlockRate, identOK, blockedCount)

	checkPass(&result, "detection_works", result.Blocked > 0)
	checkPass(&result, "ident_100%", result.IdentRate >= 99)
	if len(result.WrongItems) > 0 {
		b, _ := json.Marshal(result.WrongItems[:min(3, len(result.WrongItems))])
		fmt.Printf("    Wrong items (first 3): %s\n", string(b))
	}
	if result.Blocked > 0 && result.BlockRate < 95 {
		result.Notes = fmt.Sprintf("detection works (ident=%d/%d), increase volume for higher rate", result.IdentOK, result.Blocked)
	}
	return result
}

// ==================== Brute Force ====================
func testBruteForce() TestResult {
	fmt.Println("--- Brute Force Verification (IP:", ipBF, ") ---")
	result := TestResult{Name: "Brute Force", PassedCheck: true}

	count := 15
	delay := 50 * time.Millisecond
	var blocked int
	var identOK, identWrong int
	var blockedAt int = -1
	var wrongItems []WrongItem

	for i := 0; i < count; i++ {
		data := url.Values{
			"username": {"admin"},
			"password": {fmt.Sprintf("guess%d", i)},
		}
		code, reason := doPostFormIP(ipBF, "/login", data)

		if isBlocked(code) {
			blocked++
			if blockedAt == -1 {
				blockedAt = i + 1
			}
			if reason == "brute_force" {
				identOK++
			} else {
				identWrong++
				wrongItems = append(wrongItems, WrongItem{
					Payload: fmt.Sprintf("POST /login guess%d", i),
					ExpectedType: "brute_force", ActualType: reason,
					HTTPCode: code, Issue: "wrong attack type label",
				})
			}
		}
		time.Sleep(delay)
	}

	result.Total = count
	result.Blocked = blocked
	result.Passed = count - blocked
	if count > 0 {
		result.BlockRate = float64(blocked) / float64(count) * 100
	}
	result.IdentOK = identOK
	result.IdentWrong = identWrong
	if blocked > 0 {
		result.IdentRate = float64(identOK) / float64(blocked) * 100
	}
	result.WrongItems = wrongItems
	if blockedAt > 0 {
		result.Notes = fmt.Sprintf("first blocked at req #%d", blockedAt)
	}

	fmt.Printf("  Brute Force: %d req, %d blocked (%.1f%%), ident=%d/%d, first_block=#%d\n",
		count, blocked, result.BlockRate, identOK, blocked, blockedAt)

	checkPass(&result, "detection_works", result.Blocked > 0)
	checkPass(&result, "ident_100%", result.IdentRate >= 99)
	return result
}

// ==================== SQL Injection ====================
func testSQLInjection() TestResult {
	fmt.Println("--- SQL Injection Regression (IP:", ipSQLi, ") ---")
	result := TestResult{Name: "SQL Injection", PassedCheck: true}

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

	var blocked int
	var identOK, identWrong int
	var wrongItems []WrongItem

	for _, payload := range payloads {
		data := url.Values{"q": {payload}}
		code, reason := doPostFormIP(ipSQLi, "/search", data)

		if code == 403 {
			blocked++
			if reason == "sql_injection" {
				identOK++
			} else {
				identWrong++
				wrongItems = append(wrongItems, WrongItem{
					Payload: payload, ExpectedType: "sql_injection",
					ActualType: reason, HTTPCode: code, Issue: "wrong attack type label",
				})
			}
		} else if code < 400 {
			wrongItems = append(wrongItems, WrongItem{
				Payload: payload, ExpectedType: "sql_injection",
				HTTPCode: code, Issue: "penetrated - not blocked",
			})
		}
		time.Sleep(10 * time.Millisecond)
	}

	result.Total = len(payloads)
	result.Blocked = blocked
	result.Passed = result.Total - blocked
	if result.Total > 0 {
		result.BlockRate = float64(blocked) / float64(result.Total) * 100
	}
	result.IdentOK = identOK
	result.IdentWrong = identWrong
	if blocked > 0 {
		result.IdentRate = float64(identOK) / float64(blocked) * 100
	}
	result.WrongItems = wrongItems

	penetrated := result.Total - blocked - identWrong
	fmt.Printf("  SQL Injection: %d payloads, %d blocked (%.1f%%), ident=%d/%d, penetrated=%d\n",
		result.Total, blocked, result.BlockRate, identOK, blocked, penetrated)

	checkPass(&result, "block_rate_95%", result.BlockRate >= 95)
	checkPass(&result, "ident_100%", result.IdentRate >= 99)
	return result
}

// ==================== XSS ====================
func testXSS() TestResult {
	fmt.Println("--- XSS Regression (IP:", ipXSS, ") ---")
	result := TestResult{Name: "XSS", PassedCheck: true}

	payloads := []string{
		"<script>alert('xss')</script>",
		"<script>alert(document.cookie)</script>",
		"<img src=x onerror=alert(1)>",
		"<body onload=alert('xss')>",
		"<a href=\"javascript:alert(1)\">click</a>",
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
		"<object data=\"javascript:alert(1)\">",
		"<embed src=\"javascript:alert(1)\">",
		"<scr%00ipt>alert(1)</scr%00ipt>",
	}

	var blocked int
	var identOK, identWrong int
	var wrongItems []WrongItem

	for _, payload := range payloads {
		data := url.Values{"content": {payload}}
		code, reason := doPostFormIP(ipXSS, "/comment", data)

		if code == 403 {
			blocked++
			if reason == "xss" {
				identOK++
			} else {
				identWrong++
				wrongItems = append(wrongItems, WrongItem{
					Payload: payload, ExpectedType: "xss",
					ActualType: reason, HTTPCode: code, Issue: "wrong attack type label",
				})
			}
		} else if code < 400 {
			wrongItems = append(wrongItems, WrongItem{
				Payload: payload, ExpectedType: "xss",
				HTTPCode: code, Issue: "penetrated - not blocked",
			})
		}
		time.Sleep(10 * time.Millisecond)
	}

	result.Total = len(payloads)
	result.Blocked = blocked
	result.Passed = result.Total - blocked
	if result.Total > 0 {
		result.BlockRate = float64(blocked) / float64(result.Total) * 100
	}
	result.IdentOK = identOK
	result.IdentWrong = identWrong
	if blocked > 0 {
		result.IdentRate = float64(identOK) / float64(blocked) * 100
	}
	result.WrongItems = wrongItems

	penetrated := result.Total - blocked - identWrong
	fmt.Printf("  XSS: %d payloads, %d blocked (%.1f%%), ident=%d/%d, penetrated=%d\n",
		result.Total, blocked, result.BlockRate, identOK, blocked, penetrated)

	checkPass(&result, "block_rate_95%", result.BlockRate >= 95)
	checkPass(&result, "ident_100%", result.IdentRate >= 99)
	return result
}

// ==================== WebShell Upload ====================
func testWebShellUpload() TestResult {
	fmt.Println("--- WebShell Upload Regression (IP:", ipWS, ") ---")
	result := TestResult{Name: "WebShell Upload", PassedCheck: true}

	payloads := []struct{ fn, content string }{
		{"shell.php", "<?php eval($_POST['cmd']); ?>"},
		{"shell.phtml", "<?php system($_GET['c']); ?>"},
		{"shell.php5", "<?php @eval($_REQUEST['shell']);?>"},
		{"cmd.jsp", "<% Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>"},
		{"shell.asp", "<% eval request(\"cmd\") %>"},
		{"shell.aspx", "<%@ Page Language=\"C#\" %><% System.Diagnostics.Process.Start(\"cmd.exe\"); %>"},
		{"shell.php.jpg", "<?php eval($_POST['cmd']); ?>"},
		{"shell.php;.jpg", "<?php system('id'); ?>"},
	}

	var blocked int
	var identOK, identWrong int
	var wrongItems []WrongItem

	for _, p := range payloads {
		code, reason := doUploadIP(ipWS, "/upload", p.fn, p.content)

		if code == 403 {
			blocked++
			if reason == "webshell_upload" {
				identOK++
			} else {
				identWrong++
				wrongItems = append(wrongItems, WrongItem{
					Payload: fmt.Sprintf("file=%s", p.fn), ExpectedType: "webshell_upload",
					ActualType: reason, HTTPCode: code, Issue: "wrong attack type label",
				})
			}
		} else if code < 400 {
			wrongItems = append(wrongItems, WrongItem{
				Payload: fmt.Sprintf("file=%s", p.fn), ExpectedType: "webshell_upload",
				HTTPCode: code, Issue: "penetrated - not blocked",
			})
		}
		time.Sleep(10 * time.Millisecond)
	}

	result.Total = len(payloads)
	result.Blocked = blocked
	result.Passed = result.Total - blocked
	if result.Total > 0 {
		result.BlockRate = float64(blocked) / float64(result.Total) * 100
	}
	result.IdentOK = identOK
	result.IdentWrong = identWrong
	if blocked > 0 {
		result.IdentRate = float64(identOK) / float64(blocked) * 100
	}
	result.WrongItems = wrongItems

	penetrated := result.Total - blocked - identWrong
	fmt.Printf("  WebShell: %d payloads, %d blocked (%.1f%%), ident=%d/%d, penetrated=%d\n",
		result.Total, blocked, result.BlockRate, identOK, blocked, penetrated)

	checkPass(&result, "block_rate_95%", result.BlockRate >= 95)
	checkPass(&result, "ident_100%", result.IdentRate >= 99)
	return result
}

// ==================== Normal Requests ====================
func testNormalRequests() TestResult {
	fmt.Println("--- Normal Requests (FP Check, IP:", ipNormal, ") ---")
	result := TestResult{Name: "Normal Requests", PassedCheck: true}

	type req struct {
		method, path, ct, body string
	}
	normals := []req{
		{"GET", "/", "", ""},
		{"GET", "/index.html", "", ""},
		{"GET", "/about", "", ""},
		{"GET", "/search?q=hello+world", "", ""},
		{"GET", "/api/v1/users?page=1&limit=20", "", ""},
		{"POST", "/login", "application/x-www-form-urlencoded", "username=alice&password=MySecureP@ss123"},
		{"POST", "/contact", "application/x-www-form-urlencoded", "name=Alice&email=alice@example.com&message=Hello"},
		{"POST", "/api/v1/comments", "application/json", `{"post_id": 42, "content": "Great article! Thanks for sharing."}`},
	}

	var blocked int
	var wrongItems []WrongItem

	for _, n := range normals {
		var code int
		var reason string
		headers := map[string]string{}
		if n.ct != "" {
			headers["Content-Type"] = n.ct
		}
		code, reason, _ = doRequestWithIP(ipNormal, n.method, n.path, headers, []byte(n.body))

		if isBlocked(code) {
			blocked++
			wrongItems = append(wrongItems, WrongItem{
				Payload: fmt.Sprintf("%s %s", n.method, n.path), ExpectedType: "none (normal)",
				ActualType: reason, HTTPCode: code, Issue: "FALSE POSITIVE",
			})
		}
		time.Sleep(50 * time.Millisecond)
	}

	result.Total = len(normals)
	result.Blocked = blocked
	result.Passed = result.Total - blocked
	result.IdentOK = result.Total - blocked
	result.IdentRate = 100.0
	if result.Total > 0 {
		result.BlockRate = float64(blocked) / float64(result.Total) * 100
	}
	result.WrongItems = wrongItems

	fmt.Printf("  Normal Reqs: %d sent, %d blocked (FP rate=%.1f%%)\n",
		result.Total, blocked, result.BlockRate)

	checkPass(&result, "zero_false_positive", blocked == 0)
	return result
}

// ==================== Mixed CC + DDoS ====================
func testMixedCCDDoS() TestResult {
	fmt.Println("--- Mixed CC+DDoS (IPs:", ipMixed1, ",", ipMixed2, ") ---")
	result := TestResult{Name: "Mixed CC+DDoS", PassedCheck: true}

	var wg sync.WaitGroup
	var ccB, ccOK, ddB, ddOK int64

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 40; i++ {
			code, reason := doGetIP(ipMixed1, "/mix-cc-target?id="+fmt.Sprintf("%d", i))
			if isBlocked(code) {
				atomic.AddInt64(&ccB, 1)
				if reason == "cc_attack" {
					atomic.AddInt64(&ccOK, 1)
				}
			}
			time.Sleep(80 * time.Millisecond)
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		paths := []string{"/mx/a","/mx/b","/mx/c","/mx/d","/mx/e","/mx/f","/mx/g","/mx/h","/mx/i","/mx/j","/mx/k","/mx/l"}
		for i := 0; i < 200; i++ {
			code, reason := doGetIP(ipMixed2, paths[i%len(paths)]+fmt.Sprintf("?x=%d", i))
			if isBlocked(code) {
				atomic.AddInt64(&ddB, 1)
				if strings.HasPrefix(reason, "ddos_attack") {
					atomic.AddInt64(&ddOK, 1)
				}
			}
		}
	}()

	wg.Wait()

	total := 240
	allB := int(ccB) + int(ddB)
	allOK := int(ccOK) + int(ddOK)

	result.Total = total
	result.Blocked = allB
	if total > 0 {
		result.BlockRate = float64(allB) / float64(total) * 100
	}
	result.IdentOK = allOK
	result.IdentWrong = allB - allOK
	if allB > 0 {
		result.IdentRate = float64(allOK) / float64(allB) * 100
	}
	result.Notes = fmt.Sprintf("cc=%d ddos=%d cc_ok=%d ddos_ok=%d", ccB, ddB, ccOK, ddOK)

	fmt.Printf("  Mixed CC+DDoS: %d req, cc=%d ddos=%d blocked, ident=%d/%d\n",
		total, ccB, ddB, allOK, allB)

	checkPass(&result, "both_detected", ccB > 0 && ddB > 0)
	checkPass(&result, "correct_ident", result.IdentRate >= 95)
	return result
}

// ==================== Mixed BF + SQLi ====================
func testMixedBruteForceSQLi() TestResult {
	fmt.Println("--- Mixed BF+SQLi (IPs:", ipMixedBF, ",", ipMixedSQLi, ") ---")
	result := TestResult{Name: "Mixed BruteForce+SQLi", PassedCheck: true}

	var wg sync.WaitGroup
	var bfB, bfOK, sqB, sqOK int64

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 12; i++ {
			data := url.Values{"username": {"admin"}, "password": {fmt.Sprintf("bf%d", i)}}
			code, reason := doPostFormIP(ipMixedBF, "/login", data)
			if isBlocked(code) {
				atomic.AddInt64(&bfB, 1)
				if reason == "brute_force" {
					atomic.AddInt64(&bfOK, 1)
				}
			}
			time.Sleep(40 * time.Millisecond)
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		payloads := []string{"1' UNION SELECT * FROM users--", "' OR '1'='1", "1; DROP TABLE users--", "1' AND 1=1--", "1' OR 1=1--"}
		for i := 0; i < 10; i++ {
			data := url.Values{"q": {payloads[i%len(payloads)]}}
			code, reason := doPostFormIP(ipMixedSQLi, "/search", data)
			if code == 403 {
				atomic.AddInt64(&sqB, 1)
				if reason == "sql_injection" {
					atomic.AddInt64(&sqOK, 1)
				}
			}
			time.Sleep(40 * time.Millisecond)
		}
	}()

	wg.Wait()

	total := 22
	allB := int(bfB) + int(sqB)
	allOK := int(bfOK) + int(sqOK)

	result.Total = total
	result.Blocked = allB
	if total > 0 {
		result.BlockRate = float64(allB) / float64(total) * 100
	}
	result.IdentOK = allOK
	result.IdentWrong = allB - allOK
	if allB > 0 {
		result.IdentRate = float64(allOK) / float64(allB) * 100
	}
	result.Notes = fmt.Sprintf("bf=%d sqli=%d bf_ok=%d sqli_ok=%d", bfB, sqB, bfOK, sqOK)

	fmt.Printf("  Mixed BF+SQLi: %d req, bf=%d sqli=%d blocked, ident=%d/%d\n",
		total, bfB, sqB, allOK, allB)

	checkPass(&result, "both_detected", bfB > 0 && sqB > 0)
	checkPass(&result, "correct_ident", result.IdentRate >= 95)
	return result
}

func checkPass(result *TestResult, check string, pass bool) {
	if !pass {
		result.PassedCheck = false
		fmt.Printf("    FAIL: %s\n", check)
	}
}

func min(a, b int) int {
	if a < b { return a }
	return b
}
