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
	shieldURL  = "http://127.0.0.1:8081"
	statusFile = "./data/status.json"
	timeout    = 10 * time.Second
	reportFile = "/root/shield/scripts/test_results/round18_regression_report.json"
)

// Different IPs per test type to avoid cross-contamination
const (
	ipDDoSEye     = "10.1.0.1" // GoldenEye
	ipDDoSFlood   = "10.1.0.2" // HTTP Flood
	ipDDoSVol     = "10.1.0.3" // Pure volume
	ipCC          = "10.1.0.4" // CC Attack
	ipCCNormal    = "10.1.0.5" // CC normal traffic
	ipBF          = "10.1.0.6" // Brute Force
	ipSQLi        = "10.1.0.7" // SQL Injection
	ipXSS         = "10.1.0.8" // XSS
	ipWS          = "10.1.0.9" // WebShell upload
	ipNormal      = "10.1.0.10" // Normal requests
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
	Title          string                 `json:"title"`
	Summary        map[string]TestResult  `json:"summary"`
	OverallPass    bool                   `json:"overall_pass"`
	PassRate       float64                `json:"pass_rate"`
	RiskAssessment string                 `json:"risk_assessment"`
	AdminBefore    map[string]interface{} `json:"admin_stats_before"`
	AdminAfter     map[string]interface{} `json:"admin_stats_after"`
}

var httpClient = &http.Client{Timeout: timeout}

func main() {
	fmt.Println("╔══════════════════════════════════════════════════════╗")
	fmt.Println("║  HUD-102 Round 18: DDoS/CC Label Regression Test    ║")
	fmt.Println("║  Target:", shieldURL, "                            ║")
	fmt.Println("║  Time:  ", time.Now().Format(time.RFC3339), "           ║")
	fmt.Println("╚══════════════════════════════════════════════════════╝")
	fmt.Println()

	os.MkdirAll("/root/shield/scripts/test_results", 0755)

	// Snapshot stats before
	beforeStats := getAdminStats()
	fmt.Printf("📊 Stats before: blocked=%v allowed=%v\n\n",
		beforeStats["blocked_requests"], beforeStats["allowed_requests"])

	// Wait for rate limiters to settle
	fmt.Println("Waiting 3s for rate limiters to settle...")
	time.Sleep(3 * time.Second)

	report := Report{
		Timestamp:   time.Now().Format(time.RFC3339),
		Issue:       "HUD-102",
		Title:       "Round 18 Regression - DDoS/CC Label Verification",
		Summary:     make(map[string]TestResult),
		AdminBefore: beforeStats,
	}

	results := make(map[string]TestResult)

	// Core: DDoS tests (GoldenEye, HTTP Flood, Pure Volume)
	fmt.Println("═══════════════ DDoS REGRESSION (CORE) ═══════════════")
	results["ddos_goldeneye"] = testDDoSGoldenEye()
	fmt.Println()
	results["ddos_http_flood"] = testDDoSHTTPFlood()
	fmt.Println()
	results["ddos_pure_volume"] = testDDoSPureVolume()
	fmt.Println()

	// Core: CC tests
	fmt.Println("═══════════════ CC REGRESSION (CORE) ═══════════════")
	results["cc_attack"] = testCCAttack()
	fmt.Println()
	results["cc_normal_mix"] = testCCNormalMix()
	fmt.Println()

	// Regression: other attack types
	fmt.Println("═══════════════ OTHER ATTACK REGRESSION ═══════════════")
	results["sql_injection"] = testSQLInjection()
	fmt.Println()
	results["xss"] = testXSS()
	fmt.Println()
	results["webshell_upload"] = testWebShellUpload()
	fmt.Println()
	results["brute_force"] = testBruteForce()
	fmt.Println()
	results["normal_requests"] = testNormalRequests()
	fmt.Println()

	// Get final stats
	afterStats := getAdminStats()
	report.AdminAfter = afterStats

	// Evaluate
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
		report.RiskAssessment = "LOW - All regression items passed. DDoS/CC labels verified."
	} else if overallPassRate >= 80 {
		report.RiskAssessment = "MEDIUM - Most items passed, some need attention"
	} else {
		report.RiskAssessment = "HIGH - Multiple failures, DDoS/CC label issue may persist"
	}

	// Print summary
	fmt.Println("╔══════════════════════════════════════════════════════╗")
	fmt.Println("║              REGRESSION SUMMARY                      ║")
	fmt.Println("╚══════════════════════════════════════════════════════╝")
	keyOrder := []string{
		"ddos_goldeneye", "ddos_http_flood", "ddos_pure_volume",
		"cc_attack", "cc_normal_mix",
		"sql_injection", "xss", "webshell_upload", "brute_force",
		"normal_requests",
	}
	for _, key := range keyOrder {
		r := results[key]
		status := "✅ PASS"
		if !r.PassedCheck {
			status = "❌ FAIL"
		}
		fmt.Printf("  %s %-25s: block=%.1f%%  ident=%.1f%%  %s\n",
			status, r.Name, r.BlockRate, r.IdentRate, r.Notes)
		if len(r.WrongItems) > 0 {
			for _, wi := range r.WrongItems[:min(3, len(r.WrongItems))] {
				fmt.Printf("       ⚠️ %s → got %s (%s)\n", wi.Payload, wi.ActualType, wi.Issue)
			}
		}
	}
	fmt.Printf("\n  Overall: %s  (%.1f%% items pass)\n", map[bool]string{true: "✅ PASS", false: "❌ FAIL"}[allPassed], overallPassRate)
	fmt.Printf("  Risk:    %s\n", report.RiskAssessment)
	fmt.Printf("\n  Before: blocked=%v allowed=%v\n", beforeStats["blocked_requests"], beforeStats["allowed_requests"])
	fmt.Printf("  After:  blocked=%v allowed=%v\n", afterStats["blocked_requests"], afterStats["allowed_requests"])

	data, _ := json.MarshalIndent(report, "", "  ")
	os.WriteFile(reportFile, data, 0644)
	fmt.Printf("\n  Report saved to: %s\n", reportFile)
}

func getAdminStats() map[string]interface{} {
	data, err := os.ReadFile(statusFile)
	if err != nil {
		fmt.Printf("  Failed to read status file: %v\n", err)
		return map[string]interface{}{}
	}
	var status map[string]interface{}
	json.Unmarshal(data, &status)
	metrics, ok := status["metrics"].(map[string]interface{})
	if !ok {
		return map[string]interface{}{}
	}
	// Remap camelCase keys to snake_case for backward compatibility
	return map[string]interface{}{
		"blocked_requests":   metrics["BlockedRequests"],
		"allowed_requests":   metrics["AllowedRequests"],
		"total_requests":     metrics["TotalRequests"],
		"active_connections": metrics["ActiveConnections"],
		"sql_injections":     metrics["SQLInjections"],
		"ddos_cc_blocks":     metrics["DDoSCCBlocks"],
		"brute_force_blocks": metrics["BruteForceBlocks"],
	}
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

// ==================== DDoS: GoldenEye Pattern ====================
// High path diversity + high rate + concurrent connections
func testDDoSGoldenEye() TestResult {
	fmt.Println("--- DDoS GoldenEye Pattern (IP:", ipDDoSEye, ") ---")
	result := TestResult{Name: "DDoS GoldenEye", PassedCheck: true}

	// 15 unique paths to trigger GoldenEye detection (>8 paths)
	paths := []string{
		"/ddos/a1", "/ddos/a2", "/ddos/a3", "/ddos/a4", "/ddos/a5",
		"/ddos/a6", "/ddos/a7", "/ddos/a8", "/ddos/a9", "/ddos/a10",
		"/ddos/a11", "/ddos/a12", "/ddos/a13", "/ddos/a14", "/ddos/a15",
	}

	concurrency := 15
	perWorker := 30

	var blockedCount int64
	var identOK int64
	var identWrong int64
	var mu sync.Mutex
	var wrongItems []WrongItem
	var wg sync.WaitGroup

	for w := 0; w < concurrency; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				path := paths[(workerID*perWorker+i)%len(paths)]
				code, reason := doGetIP(ipDDoSEye, path+fmt.Sprintf("?id=%d&w=%d", i, workerID))
				if isBlocked(code) {
					atomic.AddInt64(&blockedCount, 1)
					if strings.HasPrefix(reason, "ddos_attack") {
						atomic.AddInt64(&identOK, 1)
					} else {
						atomic.AddInt64(&identWrong, 1)
						mu.Lock()
						wrongItems = append(wrongItems, WrongItem{
							Payload: fmt.Sprintf("GET %s?id=%d&w=%d", path, i, workerID),
							ExpectedType: "ddos_attack:*", ActualType: reason,
							HTTPCode: code, Issue: "WRONG LABEL - expected ddos_attack",
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

	fmt.Printf("  GoldenEye: %d req (%d concurrent), %d blocked (%.1f%%), ident=%d/%d (%.1f%%)\n",
		total, concurrency, blockedCount, result.BlockRate, identOK, blockedCount, result.IdentRate)

	checkPass(&result, "detection_works", result.Blocked > 0)
	checkPass(&result, "ident_ddos_label_100%", result.IdentRate >= 99)
	checkPass(&result, "block_rate_95%", result.BlockRate >= 95)

	if result.IdentWrong > 0 {
		result.Notes = fmt.Sprintf("⚠️ LABEL LEAK: %d blocks mislabeled as non-ddOS", result.IdentWrong)
	} else if result.Blocked > 0 {
		result.Notes = fmt.Sprintf("✅ All %d blocked requests correctly labeled as ddos_attack", result.Blocked)
	}
	return result
}

// ==================== DDoS: HTTP Flood ====================
// Single path, very high rate — pure HTTP Flood pattern
func testDDoSHTTPFlood() TestResult {
	fmt.Println("--- DDoS HTTP Flood (IP:", ipDDoSFlood, ") ---")
	result := TestResult{Name: "DDoS HTTP Flood", PassedCheck: true}

	// Burst of requests to a single path to trigger HTTP Flood detection
	concurrency := 10
	perWorker := 40

	var blockedCount int64
	var identOK int64
	var identWrong int64
	var mu sync.Mutex
	var wrongItems []WrongItem
	var wg sync.WaitGroup

	for w := 0; w < concurrency; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				code, reason := doGetIP(ipDDoSFlood, fmt.Sprintf("/api/data?q=%d&w=%d", i, workerID))
				if isBlocked(code) {
					atomic.AddInt64(&blockedCount, 1)
					if strings.HasPrefix(reason, "ddos_attack") {
						atomic.AddInt64(&identOK, 1)
					} else {
						atomic.AddInt64(&identWrong, 1)
						mu.Lock()
						wrongItems = append(wrongItems, WrongItem{
							Payload: fmt.Sprintf("GET /api/data?q=%d&w=%d", i, workerID),
							ExpectedType: "ddos_attack:*", ActualType: reason,
							HTTPCode: code, Issue: "WRONG LABEL - expected ddos_attack",
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

	fmt.Printf("  HTTP Flood: %d req (%d concurrent), %d blocked (%.1f%%), ident=%d/%d (%.1f%%)\n",
		total, concurrency, blockedCount, result.BlockRate, identOK, blockedCount, result.IdentRate)

	checkPass(&result, "detection_works", result.Blocked > 0)
	checkPass(&result, "ident_ddos_label_100%", result.IdentRate >= 99)
	checkPass(&result, "block_rate_95%", result.BlockRate >= 95)

	if result.IdentWrong > 0 {
		result.Notes = fmt.Sprintf("⚠️ LABEL LEAK: %d blocks mislabeled", result.IdentWrong)
	} else if result.Blocked > 0 {
		result.Notes = fmt.Sprintf("✅ All %d blocked correctly labeled as ddos_attack", result.Blocked)
	}
	return result
}

// ==================== DDoS: Pure Volume Detection ====================
func testDDoSPureVolume() TestResult {
	fmt.Println("--- DDoS Pure Volume (IP:", ipDDoSVol, ") ---")
	result := TestResult{Name: "DDoS Pure Volume", PassedCheck: true}

	// Pure volume: moderate path diversity, high rate
	paths := []string{
		"/vol/p1", "/vol/p2", "/vol/p3", "/vol/p4", "/vol/p5",
		"/vol/p6", "/vol/p7", "/vol/p8",
	}

	concurrency := 10
	perWorker := 35

	var blockedCount int64
	var identOK int64
	var identWrong int64
	var mu sync.Mutex
	var wrongItems []WrongItem
	var wg sync.WaitGroup

	for w := 0; w < concurrency; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				path := paths[(workerID*perWorker+i)%len(paths)]
				code, reason := doGetIP(ipDDoSVol, path+fmt.Sprintf("?v=%d&w=%d", i, workerID))
				if isBlocked(code) {
					atomic.AddInt64(&blockedCount, 1)
					if strings.HasPrefix(reason, "ddos_attack") {
						atomic.AddInt64(&identOK, 1)
					} else {
						atomic.AddInt64(&identWrong, 1)
						mu.Lock()
						wrongItems = append(wrongItems, WrongItem{
							Payload: fmt.Sprintf("GET %s?v=%d&w=%d", path, i, workerID),
							ExpectedType: "ddos_attack:*", ActualType: reason,
							HTTPCode: code, Issue: "WRONG LABEL - expected ddos_attack",
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

	fmt.Printf("  Pure Volume: %d req (%d concurrent), %d blocked (%.1f%%), ident=%d/%d (%.1f%%)\n",
		total, concurrency, blockedCount, result.BlockRate, identOK, blockedCount, result.IdentRate)

	checkPass(&result, "detection_works", result.Blocked > 0)
	checkPass(&result, "ident_ddos_label_100%", result.IdentRate >= 99)
	checkPass(&result, "block_rate_95%", result.BlockRate >= 95)

	if result.IdentWrong > 0 {
		result.Notes = fmt.Sprintf("⚠️ LABEL LEAK: %d blocks mislabeled", result.IdentWrong)
	} else if result.Blocked > 0 {
		result.Notes = fmt.Sprintf("✅ All %d blocked correctly labeled as ddos_attack", result.Blocked)
	}
	return result
}

// ==================== CC Attack ====================
func testCCAttack() TestResult {
	fmt.Println("--- CC Attack (IP:", ipCC, ") ---")
	result := TestResult{Name: "CC Attack", PassedCheck: true}

	targetPath := "/cc-target"
	count := 120
	delay := 150 * time.Millisecond

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
					HTTPCode: code, Issue: "WRONG LABEL - expected cc_attack",
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

	fmt.Printf("  CC Attack: %d req (150ms interval), %d blocked (%.1f%%), ident=%d/%d (%.1f%%)\n",
		count, blocked, result.BlockRate, identOK, blocked, result.IdentRate)

	checkPass(&result, "detection_works", result.Blocked > 0)
	checkPass(&result, "ident_cc_label_100%", result.IdentRate >= 99)
	checkPass(&result, "block_rate_95%", result.BlockRate >= 95)

	if result.IdentWrong > 0 {
		result.Notes = fmt.Sprintf("⚠️ LABEL LEAK: %d CC blocks mislabeled", result.IdentWrong)
	} else if result.Blocked > 0 {
		result.Notes = fmt.Sprintf("✅ All CC blocks correctly labeled")
	}
	return result
}

// ==================== CC + Normal Mixed ====================
// Verify CC doesn't mislabel normal requests
func testCCNormalMix() TestResult {
	fmt.Println("--- CC + Normal Mix (IP:", ipCCNormal, ") ---")
	result := TestResult{Name: "CC Normal Mix Test", PassedCheck: true}

	// First, send normal low-rate requests (baseline)
	var normalBlocked int
	for i := 0; i < 10; i++ {
		code, reason := doGetIP(ipCCNormal, fmt.Sprintf("/normal/item%d", i))
		if code == 403 || code == 429 {
			normalBlocked++
			result.WrongItems = append(result.WrongItems, WrongItem{
				Payload: fmt.Sprintf("GET /normal/item%d", i),
				ExpectedType: "normal (should pass)", ActualType: reason,
				HTTPCode: code, Issue: "FALSE POSITIVE - normal request blocked",
			})
		}
		time.Sleep(500 * time.Millisecond)
	}
	fmt.Printf("  Normal baseline: 10 req, %d blocked (false positives)\n", normalBlocked)

	// Then burst the same URL to trigger CC
	var ccBlocked int
	var ccIdentOK, ccIdentWrong int
	for i := 0; i < 80; i++ {
		code, reason := doGetIP(ipCCNormal, fmt.Sprintf("/normal/item%d", i%5))
		if isBlocked(code) {
			ccBlocked++
			if reason == "cc_attack" {
				ccIdentOK++
			} else if strings.HasPrefix(reason, "ddos_attack") {
				ccIdentWrong++
				result.WrongItems = append(result.WrongItems, WrongItem{
					Payload: fmt.Sprintf("GET /normal/item%d", i%5),
					ExpectedType: "cc_attack", ActualType: reason,
					HTTPCode: code, Issue: "CC mislabeled as DDoS!",
				})
			}
		}
		time.Sleep(100 * time.Millisecond)
	}

	total := 10 + 80
	result.Total = total
	result.Blocked = normalBlocked + ccBlocked
	result.Passed = total - result.Blocked
	if total > 0 {
		result.BlockRate = float64(result.Blocked) / float64(total) * 100
	}
	result.IdentOK = ccIdentOK
	result.IdentWrong = ccIdentWrong + normalBlocked
	if ccBlocked > 0 {
		result.IdentRate = float64(ccIdentOK) / float64(ccBlocked) * 100
	} else if normalBlocked == 0 {
		result.IdentRate = 100
	}

	fmt.Printf("  CC Mixed: %d total, %d blocked (%.1f%%), CC ident=%d/%d, FP=%d\n",
		total, result.Blocked, result.BlockRate, ccIdentOK, ccBlocked, normalBlocked)

	checkPass(&result, "no_false_positives", normalBlocked == 0)
	checkPass(&result, "cc_ident_correct", ccIdentWrong == 0)
	if normalBlocked > 0 {
		result.Notes = fmt.Sprintf("⚠️ %d false positives in normal baseline", normalBlocked)
	} else if ccIdentWrong > 0 {
		result.Notes = fmt.Sprintf("⚠️ %d CC blocks mislabeled as DDoS - LABEL LEAK!", ccIdentWrong)
	} else {
		result.Notes = "✅ No false positives, CC labels correct"
	}
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
				HTTPCode: code, Issue: "PENETRATED - not blocked",
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

	penetrated := result.Total - blocked
	fmt.Printf("  SQLi: %d payloads, %d blocked (%.1f%%), ident=%d/%d, penetrated=%d\n",
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
				HTTPCode: code, Issue: "PENETRATED - not blocked",
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

	penetrated := result.Total - blocked
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

	type uploadCase struct {
		filename string
		content  string
	}
	cases := []uploadCase{
		{"shell.php", "<?php @eval($_POST['cmd']); ?>"},
		{"backdoor.phtml", "<?php system($_GET['c']); ?>"},
		{"cmd.php5", "<?=`$_GET[x]`;?>"},
		{"info.php", "<?php phpinfo(); ?>"},
		{"shell.jsp", "<% Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>"},
		{"image.jpg.php", "<?php @eval($_POST['x']); ?>"},
		{"test.php.jpg", "<?php echo shell_exec($_GET['cmd']); ?>"},
		{"eval.php", "<?=eval($_POST['1'])?>"},
	}

	var blocked int
	var identOK, identWrong int
	var wrongItems []WrongItem

	for _, c := range cases {
		code, reason := doUploadIP(ipWS, "/upload", c.filename, c.content)
		if code == 403 {
			blocked++
			if reason == "webshell_upload" || reason == "file_upload" {
				identOK++
			} else {
				identWrong++
				wrongItems = append(wrongItems, WrongItem{
					Payload: c.filename, ExpectedType: "webshell_upload",
					ActualType: reason, HTTPCode: code, Issue: "wrong attack type label",
				})
			}
		} else if code < 400 {
			wrongItems = append(wrongItems, WrongItem{
				Payload: c.filename, ExpectedType: "webshell_upload",
				HTTPCode: code, Issue: "PENETRATED - not blocked",
			})
		}
		time.Sleep(50 * time.Millisecond)
	}

	result.Total = len(cases)
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

	fmt.Printf("  WebShell: %d uploads, %d blocked (%.1f%%), ident=%d/%d\n",
		result.Total, blocked, result.BlockRate, identOK, blocked)

	checkPass(&result, "block_rate_95%", result.BlockRate >= 95)
	checkPass(&result, "ident_100%", result.IdentRate >= 99)
	return result
}

// ==================== Brute Force ====================
func testBruteForce() TestResult {
	fmt.Println("--- Brute Force Regression (IP:", ipBF, ") ---")
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

// ==================== Normal Requests (False Positive Test) ====================
func testNormalRequests() TestResult {
	fmt.Println("--- Normal Requests (IP:", ipNormal, ") ---")
	result := TestResult{Name: "Normal Requests", PassedCheck: true}

	paths := []string{
		"/", "/style.css", "/script.js", "/favicon.ico",
		"/api/status", "/about", "/contact", "/products",
		"/health", "/ping",
	}
	methods := []string{"GET", "GET", "GET", "GET", "GET", "GET", "GET", "GET", "GET", "GET"}

	var blocked int
	var wrongItems []WrongItem

	for i, path := range paths {
		code, reason := doGetIP(ipNormal, path)
		if code == 403 || code == 429 {
			blocked++
			wrongItems = append(wrongItems, WrongItem{
				Payload: fmt.Sprintf("%s %s", methods[i], path),
				ExpectedType: "normal (should pass)", ActualType: reason,
				HTTPCode: code, Issue: "FALSE POSITIVE - normal request blocked",
			})
		}
		time.Sleep(300 * time.Millisecond)
	}

	result.Total = len(paths)
	result.Blocked = blocked
	result.Passed = result.Total - blocked
	if result.Total > 0 {
		result.BlockRate = float64(blocked) / float64(result.Total) * 100
	}
	result.IdentOK = result.Passed
	result.IdentWrong = blocked
	result.IdentRate = 100
	result.WrongItems = wrongItems

	fmt.Printf("  Normal: %d requests, %d blocked (%.1f%% - false positives)\n",
		result.Total, blocked, result.BlockRate)

	checkPass(&result, "fp_lt_2%", result.BlockRate < 2)
	checkPass(&result, "no_false_positives", blocked == 0)

	if blocked > 0 {
		result.Notes = fmt.Sprintf("⚠️ %d false positives detected", blocked)
	} else {
		result.Notes = "✅ No false positives"
	}
	return result
}

// ==================== Helpers ====================
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func checkPass(result *TestResult, checkName string, condition bool) {
	if !condition {
		result.PassedCheck = false
		fmt.Printf("    ❌ Check '%s' FAILED\n", checkName)
	}
}
