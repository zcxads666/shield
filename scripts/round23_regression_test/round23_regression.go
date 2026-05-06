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
	timeout    = 15 * time.Second
	reportFile = "/root/shield/scripts/test_results/round23_regression_report.json"
)

var httpClient = &http.Client{Timeout: timeout}

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
	Timestamp      string                `json:"timestamp"`
	Issue          string                `json:"issue"`
	Title          string                `json:"title"`
	Summary        map[string]TestResult `json:"summary"`
	OverallPass    bool                  `json:"overall_pass"`
	PassRate       float64               `json:"pass_rate"`
	RiskAssessment string                `json:"risk_assessment"`
}

func main() {
	fmt.Println("╔══════════════════════════════════════════════════════════════╗")
	fmt.Println("║  HUD-123 Round 23: CC Module Regression Test (HUD-121 Fixes) ║")
	fmt.Println("║  Target:", shieldURL, "                                      ║")
	fmt.Println("║  Start:  ", time.Now().Format(time.RFC3339), "                    ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════╝")
	fmt.Println()

	os.MkdirAll("/root/shield/scripts/test_results", 0755)

	results := make(map[string]TestResult)

	fmt.Println("Cooling down firewall state (10s)...")
	time.Sleep(10 * time.Second)

	// =============================================
	// PHASE 1: BASELINE / LOW-RATE TESTS
	// =============================================
	fmt.Println("══════════════ PHASE 1: BASELINE / ATTACK SIGNATURE TESTS ══════════════")
	fmt.Println()

	results["normal_fp"] = testNormalRequests()
	time.Sleep(2 * time.Second)

	results["sql_injection"] = testSQLInjection()
	time.Sleep(2 * time.Second)

	results["xss"] = testXSS()
	time.Sleep(2 * time.Second)

	results["webshell_upload"] = testWebShellUpload()
	time.Sleep(2 * time.Second)

	results["brute_force"] = testBruteForce()

	fmt.Println("\nCooling down (10s)...")
	time.Sleep(10 * time.Second)

	// =============================================
	// PHASE 2: CC REGRESSION TESTS (HUD-121 fixes)
	// =============================================
	fmt.Println("══════════════ PHASE 2: CC REGRESSION (HUD-121 FIXES) ══════════════")
	fmt.Println()

	results["cc_simple_tool"] = testCCSimpleTool()
	time.Sleep(3 * time.Second)

	results["cc_humanlike_tool"] = testCCHumanlikeTool()
	time.Sleep(3 * time.Second)

	results["cc_slow"] = testCCSlow()
	time.Sleep(3 * time.Second)

	results["cc_distributed"] = testCCDistributed()
	time.Sleep(3 * time.Second)

	results["cc_repeat_offender"] = testCCRepeatOffender()
	time.Sleep(3 * time.Second)

	results["cc_normal_same_ip"] = testCCNormalSameIP()

	fmt.Println("\nCooling down (15s)...")
	time.Sleep(15 * time.Second)

	// =============================================
	// PHASE 3: DDoS REGRESSION TESTS
	// =============================================
	fmt.Println("══════════════ PHASE 3: DDoS REGRESSION ══════════════")
	fmt.Println()

	results["ddos_goldeneye"] = testDDoSGoldenEye()
	time.Sleep(5 * time.Second)

	results["ddos_http_flood"] = testDDoSHTTPFlood()

	// =============================================
	// EVALUATION
	// =============================================
	fmt.Println()
	fmt.Println("══════════════ EVALUATION ══════════════")
	fmt.Println()

	allPassed := true
	passCount := 0
	ccPassed := true
	ddosPassed := true

	for key, r := range results {
		if r.PassedCheck {
			passCount++
		} else {
			allPassed = false
			if strings.HasPrefix(key, "cc_") {
				ccPassed = false
			}
			if strings.HasPrefix(key, "ddos_") {
				ddosPassed = false
			}
		}
	}
	overallPassRate := float64(passCount) / float64(len(results)) * 100

	report := Report{
		Timestamp: time.Now().Format(time.RFC3339),
		Issue:     "HUD-123",
		Title:     "Round 23 Regression - CC Module Fix Verification (HUD-121)",
		Summary:   results,
		OverallPass: allPassed,
		PassRate:    overallPassRate,
	}

	if allPassed {
		report.RiskAssessment = "LOW - All tests passed. CC module fixes verified. Mission accomplished."
	} else if ccPassed && ddosPassed {
		report.RiskAssessment = "MEDIUM - CC/DDoS core tests passed, minor issues in other areas"
	} else if !ccPassed && ddosPassed {
		report.RiskAssessment = "HIGH - CC regression failures persist. Further hardening needed."
	} else if ccPassed && !ddosPassed {
		report.RiskAssessment = "MEDIUM - CC fixes verified but DDoS regression detected"
	} else {
		report.RiskAssessment = "CRITICAL - Multiple core modules failing. Deployment may be at risk."
	}

	fmt.Println("╔══════════════════════════════════════════════════════════════╗")
	fmt.Println("║              ROUND 23 REGRESSION SUMMARY                     ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════╝")

	keyOrder := []string{
		"cc_simple_tool", "cc_humanlike_tool", "cc_slow", "cc_distributed",
		"cc_repeat_offender", "cc_normal_same_ip",
		"ddos_goldeneye", "ddos_http_flood",
		"sql_injection", "xss", "webshell_upload", "brute_force",
		"normal_fp",
	}
	for _, key := range keyOrder {
		r, ok := results[key]
		if !ok {
			continue
		}
		status := "PASS"
		if !r.PassedCheck {
			status = "FAIL"
		}
		fmt.Printf("  [%s] %-28s: block=%.1f%%  ident=%.1f%%  %s\n",
			status, r.Name, r.BlockRate, r.IdentRate, r.Notes)
		if len(r.WrongItems) > 0 && len(r.WrongItems) <= 5 {
			for _, wi := range r.WrongItems {
				fmt.Printf("       WARN: %s -> got %s (%s)\n", truncate(wi.Payload, 40), wi.ActualType, wi.Issue)
			}
		} else if len(r.WrongItems) > 5 {
			for _, wi := range r.WrongItems[:3] {
				fmt.Printf("       WARN: %s -> got %s (%s)\n", truncate(wi.Payload, 40), wi.ActualType, wi.Issue)
			}
			fmt.Printf("       ... and %d more errors\n", len(r.WrongItems)-3)
		}
	}
	fmt.Printf("\n  Overall: %s  (%.1f%% items pass)\n",
		map[bool]string{true: "PASS", false: "FAIL"}[allPassed], overallPassRate)
	fmt.Printf("  CC Core: %s  DDoS Core: %s\n",
		map[bool]string{true: "PASS", false: "FAIL"}[ccPassed],
		map[bool]string{true: "PASS", false: "FAIL"}[ddosPassed])
	fmt.Printf("  Risk:    %s\n", report.RiskAssessment)

	data, _ := json.MarshalIndent(report, "", "  ")
	os.WriteFile(reportFile, data, 0644)
	fmt.Printf("\n  Report saved to: %s\n", reportFile)
}

// ==================== CC: Simple Tool (No Cookie, No Referer) ====================
// HUD-121 Fix: burst threshold lowered 30→10
// Expectation: ≥95% block rate, all labeled cc_attack
func testCCSimpleTool() TestResult {
	fmt.Println("--- CC Simple Tool: no Cookie/Referer, 40 req burst to single path (IP: 10.2.0.1) ---")
	r := TestResult{Name: "CC Simple Tool", PassedCheck: true}
	const ip = "10.2.0.1"

	count := 40
	delay := 40 * time.Millisecond
	var blocked int64
	var identOK, identWrong int64
	var mu sync.Mutex
	var wrongItems []WrongItem

	var wg sync.WaitGroup
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func(wid int) {
			defer wg.Done()
			for i := 0; i < count/4; i++ {
				code, reason := doGetIP(ip, fmt.Sprintf("/cc-simple/page?id=%d&w=%d", i, wid))
				if isBlocked(code) {
					atomic.AddInt64(&blocked, 1)
					if reason == "cc_attack" || strings.HasPrefix(reason, "cc_") {
						atomic.AddInt64(&identOK, 1)
					} else {
						atomic.AddInt64(&identWrong, 1)
						mu.Lock()
						wrongItems = append(wrongItems, WrongItem{
							Payload: fmt.Sprintf("GET /cc-simple/page?id=%d", i),
							ExpectedType: "cc_attack", ActualType: reason,
							HTTPCode: code, Issue: "wrong label for simple CC",
						})
						mu.Unlock()
					}
				}
				time.Sleep(delay)
			}
		}(w)
	}
	wg.Wait()

	r.Total = count
	r.Blocked = int(blocked)
	r.Passed = count - int(blocked)
	if count > 0 {
		r.BlockRate = float64(blocked) / float64(count) * 100
	}
	r.IdentOK = int(identOK)
	r.IdentWrong = int(identWrong)
	if blocked > 0 {
		r.IdentRate = float64(identOK) / float64(blocked) * 100
	} else {
		r.IdentRate = 100
	}
	r.WrongItems = wrongItems

	fmt.Printf("  Simple CC: %d req, %d blocked (%.1f%%), ident=%d/%d (%.1f%%)\n",
		count, blocked, r.BlockRate, identOK, blocked, r.IdentRate)

	checkPass(&r, "block_rate>=95%", r.BlockRate >= 95)
	checkPass(&r, "ident_100%_cc_attack", r.IdentRate >= 99)
	if r.IdentWrong > 0 {
		r.Notes = fmt.Sprintf("LABEL LEAK: %d blocks mislabeled", r.IdentWrong)
	} else if r.Blocked > 0 {
		r.Notes = fmt.Sprintf("OK: %d blocks, all correct cc label", r.Blocked)
	} else {
		r.Notes = "FAIL: No blocks - CC burst threshold fix NOT effective"
	}
	return r
}

// ==================== CC: Human-like Tool (UA, Referer, Cookie) ====================
// HUD-121 Fix: global threshold 30→50, syn_flood detection >20rps
// Expectation: ≥95% block rate, all labeled cc_attack (not syn_flood!)
func testCCHumanlikeTool() TestResult {
	fmt.Println("--- CC Human-like Tool: valid UA/Referer/Cookie, 60 req to single path (IP: 10.2.0.2) ---")
	r := TestResult{Name: "CC Human-like Tool", PassedCheck: true}
	const ip = "10.2.0.2"

	count := 60
	delay := 40 * time.Millisecond
	var blocked int64
	var identOK, identWrong int64
	var mu sync.Mutex
	var wrongItems []WrongItem

	var wg sync.WaitGroup
	for w := 0; w < 5; w++ {
		wg.Add(1)
		go func(wid int) {
			defer wg.Done()
			headers := map[string]string{
				"User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0",
				"Referer":         "http://127.0.0.1:8081/",
				"Accept":          "text/html,application/xhtml+xml",
				"Accept-Language": "en-US,en;q=0.9",
				"Accept-Encoding": "gzip, deflate",
				"Cookie":          "sessionid=abc123def456; csrftoken=xyz789",
			}
			for i := 0; i < count/5; i++ {
				code, reason, _ := doRequestWithIP(ip, "GET", fmt.Sprintf("/cc-human/page?id=%d&w=%d", i, wid), headers, nil)
				if isBlocked(code) {
					atomic.AddInt64(&blocked, 1)
					if reason == "cc_attack" || strings.HasPrefix(reason, "cc_") {
						atomic.AddInt64(&identOK, 1)
					} else {
						atomic.AddInt64(&identWrong, 1)
						mu.Lock()
						wrongItems = append(wrongItems, WrongItem{
							Payload: fmt.Sprintf("GET /cc-human/page?id=%d", i),
							ExpectedType: "cc_attack", ActualType: reason,
							HTTPCode: code, Issue: "wrong label for CC with human-like headers",
						})
						mu.Unlock()
					}
				}
				time.Sleep(delay)
			}
		}(w)
	}
	wg.Wait()

	r.Total = count
	r.Blocked = int(blocked)
	r.Passed = count - int(blocked)
	if count > 0 {
		r.BlockRate = float64(blocked) / float64(count) * 100
	}
	r.IdentOK = int(identOK)
	r.IdentWrong = int(identWrong)
	if blocked > 0 {
		r.IdentRate = float64(identOK) / float64(blocked) * 100
	} else {
		r.IdentRate = 100
	}
	r.WrongItems = wrongItems

	fmt.Printf("  Human-like CC: %d req, %d blocked (%.1f%%), ident=%d/%d (%.1f%%), mislabeled=%d\n",
		count, blocked, r.BlockRate, identOK, blocked, r.IdentRate, identWrong)

	checkPass(&r, "block_rate>=95%", r.BlockRate >= 95)
	checkPass(&r, "ident_100%_cc_attack", r.IdentRate >= 99)
	if r.IdentWrong > 0 {
		r.Notes = fmt.Sprintf("LABEL LEAK: %d blocks mislabeled (check syn_flood spillover)", r.IdentWrong)
	} else if r.Blocked > 0 {
		r.Notes = fmt.Sprintf("OK: %d blocks, all correct cc label", r.Blocked)
	} else {
		r.Notes = "FAIL: No blocks - human-like CC NOT detected"
	}
	return r
}

// ==================== CC: Slow Rate Attack ====================
func testCCSlow() TestResult {
	fmt.Println("--- CC Slow: 1 req/2s sustained (IP: 10.2.0.3) ---")
	r := TestResult{Name: "CC Slow Rate", PassedCheck: true}
	const ip = "10.2.0.3"

	count := 60
	delay := 2 * time.Second
	var blocked int64
	var identOK, identWrong int64
	var mu sync.Mutex
	var wrongItems []WrongItem

	var wg sync.WaitGroup
	for w := 0; w < 3; w++ {
		wg.Add(1)
		go func(wid int) {
			defer wg.Done()
			for i := 0; i < count/3; i++ {
				code, reason := doGetIP(ip, fmt.Sprintf("/cc-slow/resource?id=%d&w=%d", i, wid))
				if isBlocked(code) {
					atomic.AddInt64(&blocked, 1)
					if reason == "cc_attack" || strings.HasPrefix(reason, "cc_") {
						atomic.AddInt64(&identOK, 1)
					} else {
						atomic.AddInt64(&identWrong, 1)
						mu.Lock()
						wrongItems = append(wrongItems, WrongItem{
							Payload: fmt.Sprintf("GET /cc-slow/resource?id=%d", i),
							ExpectedType: "cc_attack", ActualType: reason,
							HTTPCode: code, Issue: "wrong label for slow CC",
						})
						mu.Unlock()
					}
				}
				time.Sleep(delay)
			}
		}(w)
	}
	wg.Wait()

	r.Total = count
	r.Blocked = int(blocked)
	r.Passed = count - int(blocked)
	if count > 0 {
		r.BlockRate = float64(blocked) / float64(count) * 100
	}
	r.IdentOK = int(identOK)
	r.IdentWrong = int(identWrong)
	if blocked > 0 {
		r.IdentRate = float64(identOK) / float64(blocked) * 100
	} else {
		r.IdentRate = 100
	}
	r.WrongItems = wrongItems

	fmt.Printf("  Slow CC: %d req (2s interval), %d blocked (%.1f%%), ident=%d/%d (%.1f%%)\n",
		count, blocked, r.BlockRate, identOK, blocked, r.IdentRate)

	checkPass(&r, "slow_cc_detected", r.Blocked > 0)
	checkPass(&r, "ident_100%", r.IdentRate >= 99)
	if r.Blocked > 0 {
		r.Notes = fmt.Sprintf("OK: slow CC detected (%d blocks, %.0f%%)", r.Blocked, r.BlockRate)
	} else {
		r.Notes = "WARN: Slow CC not detected"
	}
	return r
}

// ==================== CC: Distributed Attack ====================
// HUD-121 Fix: path concentration direct block
// Expectation: Proper CC labeling, NOT ddos_attack:http_flood
func testCCDistributed() TestResult {
	fmt.Println("--- CC Distributed: 100+ IPs, 2-3 req each to same path (botnet sim) ---")
	r := TestResult{Name: "CC Distributed", PassedCheck: true}

	numIPs := 120
	reqPerIP := 2
	targetPath := "/cc-distrib/api/data"

	var blocked int64
	var identOK, identWrong int64
	var mu sync.Mutex
	var wrongItems []WrongItem
	var wg sync.WaitGroup

	sem := make(chan struct{}, 30)

	for i := 0; i < numIPs; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			ip := fmt.Sprintf("10.3.%d.%d", idx/256, idx%256)
			for j := 0; j < reqPerIP; j++ {
				code, reason := doGetIP(ip, fmt.Sprintf("%s?id=%d&j=%d", targetPath, idx, j))
				if isBlocked(code) {
					atomic.AddInt64(&blocked, 1)
					if reason == "cc_attack" || strings.HasPrefix(reason, "cc_") {
						atomic.AddInt64(&identOK, 1)
					} else {
						atomic.AddInt64(&identWrong, 1)
						mu.Lock()
						wrongItems = append(wrongItems, WrongItem{
							Payload: fmt.Sprintf("IP %s GET %s", ip, targetPath),
							ExpectedType: "cc_attack", ActualType: reason,
							HTTPCode: code, Issue: fmt.Sprintf("WRONG LABEL: expected cc_attack, got %s", reason),
						})
						mu.Unlock()
					}
				}
				time.Sleep(15 * time.Millisecond)
			}
		}(i)
	}
	wg.Wait()

	total := numIPs * reqPerIP
	r.Total = total
	r.Blocked = int(blocked)
	r.Passed = total - int(blocked)
	if total > 0 {
		r.BlockRate = float64(blocked) / float64(total) * 100
	}
	r.IdentOK = int(identOK)
	r.IdentWrong = int(identWrong)
	if blocked > 0 {
		r.IdentRate = float64(identOK) / float64(blocked) * 100
	} else {
		r.IdentRate = 100
	}
	r.WrongItems = wrongItems

	fmt.Printf("  Distributed CC: %d req (%d IPs), %d blocked (%.1f%%), ident=%d/%d (%.1f%%)\n",
		total, numIPs, blocked, r.BlockRate, identOK, blocked, r.IdentRate)

	checkPass(&r, "block_rate>=95%", r.BlockRate >= 95)
	checkPass(&r, "ident_100%_cc_attack", r.IdentRate >= 99)
	if r.IdentWrong > 0 {
		r.Notes = fmt.Sprintf("LABEL LEAK: %d blocks mislabeled as ddos (path concentration fix not working)", r.IdentWrong)
	} else if r.Blocked > 0 {
		r.Notes = fmt.Sprintf("OK: Distributed CC detected (%d blocks, all cc_attack)", r.Blocked)
	} else {
		r.Notes = "FAIL: No blocks - distributed CC not detected at all"
	}
	return r
}

// ==================== CC: Repeat Offender ====================
// HUD-121 Fix: rateLimit OnBlock call added
// Expectation: Previously blocked IP gets re-blocked immediately
func testCCRepeatOffender() TestResult {
	fmt.Println("--- CC Repeat Offender: burst first, cool down, then re-test (IP: 10.2.0.4) ---")
	r := TestResult{Name: "CC Repeat Offender", PassedCheck: true}
	const ip = "10.2.0.4"

	// Phase 1: Provoke block with burst
	fmt.Println("  Phase 1: Initial burst to get IP blocked...")
	for i := 0; i < 25; i++ {
		doGetIP(ip, fmt.Sprintf("/cc-repeat/trigger?id=%d", i))
		time.Sleep(15 * time.Millisecond)
	}

	// Short cooldown
	time.Sleep(3 * time.Second)

	// Phase 2: Re-test - should be blocked
	fmt.Println("  Phase 2: Re-test (should trigger IP reputation / rate limit)...")
	count := 10
	var blocked int64
	var identOK, identWrong int64
	var mu sync.Mutex
	var wrongItems []WrongItem

	for i := 0; i < count; i++ {
		code, reason := doGetIP(ip, fmt.Sprintf("/cc-repeat/recheck?id=%d", i))
		if isBlocked(code) {
			atomic.AddInt64(&blocked, 1)
			if reason == "cc_attack" || strings.HasPrefix(reason, "cc_") {
				atomic.AddInt64(&identOK, 1)
			} else if strings.Contains(reason, "rate") {
				atomic.AddInt64(&identOK, 1) // rate_limit is also acceptable for repeat
			} else {
				atomic.AddInt64(&identWrong, 1)
				mu.Lock()
				wrongItems = append(wrongItems, WrongItem{
					Payload: fmt.Sprintf("GET /cc-repeat/recheck?id=%d", i),
					ExpectedType: "cc_attack or rate_limit", ActualType: reason,
					HTTPCode: code, Issue: "wrong label for repeat offender",
				})
				mu.Unlock()
			}
		}
		time.Sleep(100 * time.Millisecond)
	}

	r.Total = count
	r.Blocked = int(blocked)
	r.Passed = count - int(blocked)
	if count > 0 {
		r.BlockRate = float64(blocked) / float64(count) * 100
	}
	r.IdentOK = int(identOK)
	r.IdentWrong = int(identWrong)
	if blocked > 0 {
		r.IdentRate = float64(identOK) / float64(blocked) * 100
	} else {
		r.IdentRate = 100
	}
	r.WrongItems = wrongItems

	fmt.Printf("  Repeat Offender: %d req (post-block), %d blocked (%.1f%%), ident=%d/%d (%.1f%%)\n",
		count, blocked, r.BlockRate, identOK, blocked, r.IdentRate)

	checkPass(&r, "repeat_offender_blocked", r.Blocked > 0)
	checkPass(&r, "ident_100%", r.IdentRate >= 99)
	checkPass(&r, "block_rate_95%", r.BlockRate >= 95)
	if r.Blocked >= count {
		r.Notes = fmt.Sprintf("OK: Repeat offender completely blocked (%d/%d)", r.Blocked, count)
	} else if r.Blocked > 0 {
		r.Notes = fmt.Sprintf("Partial: %d/%d blocked. OnBlock working but limited", r.Blocked, count)
	} else {
		r.Notes = "FAIL: Repeat offender not blocked. OnBlock rateLimit NOT working (HUD-121 #4)"
	}
	return r
}

// ==================== CC: Normal Traffic Same IP (FP Check) ====================
func testCCNormalSameIP() TestResult {
	fmt.Println("--- CC Normal same IP: normal browsing after CC, check FP (IP: 10.2.0.5) ---")
	r := TestResult{Name: "CC Normal Same IP", PassedCheck: true}
	const ip = "10.2.0.5"

	// Light traffic burst first
	fmt.Println("  Phase 1: Light traffic...")
	for i := 0; i < 12; i++ {
		doGetIP(ip, fmt.Sprintf("/cc-fp-test/page%d", i%3))
		time.Sleep(80 * time.Millisecond)
	}
	time.Sleep(3 * time.Second)

	// Normal browsing
	fmt.Println("  Phase 2: Normal browsing...")
	paths := []string{"/", "/about", "/products", "/contact", "/api/status", "/health"}
	var blocked int64
	var wrongItems []WrongItem
	var mu sync.Mutex

	for i, path := range paths {
		code, reason := doGetIP(ip, path)
		if isBlocked(code) {
			atomic.AddInt64(&blocked, 1)
			mu.Lock()
			wrongItems = append(wrongItems, WrongItem{
				Payload: fmt.Sprintf("GET %s", path),
				ExpectedType: "normal (should pass)", ActualType: reason,
				HTTPCode: code, Issue: "FALSE POSITIVE: normal request blocked after CC activity",
			})
			mu.Unlock()
		}
		time.Sleep(time.Duration(500+i*150) * time.Millisecond)
	}

	r.Total = len(paths)
	r.Blocked = int(blocked)
	r.Passed = len(paths) - int(blocked)
	if len(paths) > 0 {
		r.BlockRate = float64(blocked) / float64(len(paths)) * 100
	}
	r.IdentOK = r.Passed
	r.IdentWrong = int(blocked)
	r.IdentRate = 100
	r.WrongItems = wrongItems

	fmt.Printf("  Normal after CC: %d req, %d blocked (%.1f%% false positives)\n",
		len(paths), blocked, r.BlockRate)

	checkPass(&r, "no_false_positives", blocked == 0)
	if blocked > 0 {
		r.Notes = fmt.Sprintf("WARN: %d false positives - aggressive blocking lingers", blocked)
	} else {
		r.Notes = "OK: No false positives after CC activity subsides"
	}
	return r
}

// ==================== DDoS: GoldenEye ====================
func testDDoSGoldenEye() TestResult {
	fmt.Println("--- DDoS GoldenEye: high path diversity + high rate (IP: 10.4.0.1) ---")
	r := TestResult{Name: "DDoS GoldenEye", PassedCheck: true}
	const ip = "10.4.0.1"

	paths := []string{
		"/ddos23/ge1", "/ddos23/ge2", "/ddos23/ge3", "/ddos23/ge4",
		"/ddos23/ge5", "/ddos23/ge6", "/ddos23/ge7", "/ddos23/ge8",
		"/ddos23/ge9", "/ddos23/ge10", "/ddos23/ge11", "/ddos23/ge12",
		"/ddos23/ge13", "/ddos23/ge14", "/ddos23/ge15", "/ddos23/ge16",
		"/ddos23/ge17", "/ddos23/ge18", "/ddos23/ge19", "/ddos23/ge20",
	}

	concurrency := 15
	perWorker := 30

	var blocked int64
	var identOK, identWrong int64
	var mu sync.Mutex
	var wrongItems []WrongItem
	var wg sync.WaitGroup

	for w := 0; w < concurrency; w++ {
		wg.Add(1)
		go func(wid int) {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				path := paths[(wid*perWorker+i)%len(paths)]
				code, reason := doGetIP(ip, fmt.Sprintf("%s?id=%d&w=%d", path, i, wid))
				if isBlocked(code) {
					atomic.AddInt64(&blocked, 1)
					if strings.HasPrefix(reason, "ddos_attack") {
						atomic.AddInt64(&identOK, 1)
					} else {
						atomic.AddInt64(&identWrong, 1)
						mu.Lock()
						wrongItems = append(wrongItems, WrongItem{
							Payload: fmt.Sprintf("GET %s?id=%d", path, i),
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
	r.Total = total
	r.Blocked = int(blocked)
	r.Passed = total - int(blocked)
	if total > 0 {
		r.BlockRate = float64(blocked) / float64(total) * 100
	}
	r.IdentOK = int(identOK)
	r.IdentWrong = int(identWrong)
	if blocked > 0 {
		r.IdentRate = float64(identOK) / float64(blocked) * 100
	} else {
		r.IdentRate = 100
	}
	r.WrongItems = wrongItems

	fmt.Printf("  GoldenEye: %d req (%d concurrent), %d blocked (%.1f%%), ident=%d/%d (%.1f%%)\n",
		total, concurrency, blocked, r.BlockRate, identOK, blocked, r.IdentRate)

	checkPass(&r, "detection_works", r.Blocked > 0)
	checkPass(&r, "ident_ddos_label_100%", r.IdentRate >= 99)
	checkPass(&r, "block_rate_95%", r.BlockRate >= 95)

	if r.IdentWrong > 0 {
		r.Notes = fmt.Sprintf("LABEL LEAK: %d DDoS blocks mislabeled", r.IdentWrong)
	} else if r.Blocked > 0 {
		r.Notes = fmt.Sprintf("OK: All %d blocks correctly ddos_attack", r.Blocked)
	} else {
		r.Notes = "WARN: GoldenEye not detected!"
	}
	return r
}

// ==================== DDoS: HTTP Flood ====================
func testDDoSHTTPFlood() TestResult {
	fmt.Println("--- DDoS HTTP Flood: single path extreme rate (IP: 10.4.0.2) ---")
	r := TestResult{Name: "DDoS HTTP Flood", PassedCheck: true}
	const ip = "10.4.0.2"

	concurrency := 10
	perWorker := 40

	var blocked int64
	var identOK, identWrong int64
	var mu sync.Mutex
	var wrongItems []WrongItem
	var wg sync.WaitGroup

	for w := 0; w < concurrency; w++ {
		wg.Add(1)
		go func(wid int) {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				code, reason := doGetIP(ip, fmt.Sprintf("/api/ddos-target?q=%d&w=%d", i, wid))
				if isBlocked(code) {
					atomic.AddInt64(&blocked, 1)
					if strings.HasPrefix(reason, "ddos_attack") {
						atomic.AddInt64(&identOK, 1)
					} else {
						atomic.AddInt64(&identWrong, 1)
						mu.Lock()
						wrongItems = append(wrongItems, WrongItem{
							Payload: fmt.Sprintf("GET /api/ddos-target?q=%d", i),
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
	r.Total = total
	r.Blocked = int(blocked)
	r.Passed = total - int(blocked)
	if total > 0 {
		r.BlockRate = float64(blocked) / float64(total) * 100
	}
	r.IdentOK = int(identOK)
	r.IdentWrong = int(identWrong)
	if blocked > 0 {
		r.IdentRate = float64(identOK) / float64(blocked) * 100
	} else {
		r.IdentRate = 100
	}
	r.WrongItems = wrongItems

	fmt.Printf("  HTTP Flood: %d req (%d concurrent), %d blocked (%.1f%%), ident=%d/%d (%.1f%%)\n",
		total, concurrency, blocked, r.BlockRate, identOK, blocked, r.IdentRate)

	checkPass(&r, "detection_works", r.Blocked > 0)
	checkPass(&r, "ident_ddos_label_100%", r.IdentRate >= 99)
	checkPass(&r, "block_rate_95%", r.BlockRate >= 95)

	if r.IdentWrong > 0 {
		r.Notes = fmt.Sprintf("LABEL LEAK: %d DDoS blocks mislabeled", r.IdentWrong)
	} else if r.Blocked > 0 {
		r.Notes = fmt.Sprintf("OK: All %d blocks correctly ddos_attack", r.Blocked)
	} else {
		r.Notes = "WARN: HTTP Flood not detected!"
	}
	return r
}

// ==================== SQL Injection ====================
func testSQLInjection() TestResult {
	fmt.Println("--- SQL Injection (IP: 10.5.0.1) ---")
	r := TestResult{Name: "SQL Injection", PassedCheck: true}
	const ip = "10.5.0.1"

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
		code, reason := doPostFormIP(ip, "/search", data)

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

	r.Total = len(payloads)
	r.Blocked = blocked
	r.Passed = r.Total - blocked
	if r.Total > 0 {
		r.BlockRate = float64(blocked) / float64(r.Total) * 100
	}
	r.IdentOK = identOK
	r.IdentWrong = identWrong
	if blocked > 0 {
		r.IdentRate = float64(identOK) / float64(blocked) * 100
	} else {
		r.IdentRate = 100
	}
	r.WrongItems = wrongItems

	fmt.Printf("  SQLi: %d payloads, %d blocked (%.1f%%), ident=%d/%d\n",
		r.Total, blocked, r.BlockRate, identOK, blocked)

	checkPass(&r, "block_rate_95%", r.BlockRate >= 95)
	checkPass(&r, "ident_100%", r.IdentRate >= 99)
	if r.Passed > 0 {
		r.Notes = fmt.Sprintf("WARN: %d SQLi payloads penetrated!", r.Passed)
	} else {
		r.Notes = "OK: All SQLi blocked with correct labels"
	}
	return r
}

// ==================== XSS ====================
func testXSS() TestResult {
	fmt.Println("--- XSS (IP: 10.5.0.2) ---")
	r := TestResult{Name: "XSS", PassedCheck: true}
	const ip = "10.5.0.2"

	payloads := []string{
		"<script>alert(1)</script>",
		"<img src=x onerror=alert(1)>",
		"<svg/onload=alert(1)>",
		"<body onload=alert(1)>",
		"<iframe src=\"javascript:alert(1)\">",
		"<a href=\"javascript:alert(1)\">click</a>",
		"<div onclick=\"alert('xss')\">test</div>",
		"<img src=x onerror=\"eval(atob('YWxlcnQoMSk='))\">",
		"<svg><script>alert(1)</script></svg>",
		"';alert(1);//",
		"\" onmouseover=\"alert(1)",
		"javascript:alert(1)",
		"<style>@import'javascript:alert(1)';</style>",
		"<img src=1 onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
		"<marquee onstart=alert(1)>",
		"<details open ontoggle=alert(1)>",
		"<button onclick=alert(1)>click</button>",
		"<input onfocus=alert(1) autofocus>",
		"<object data=\"javascript:alert(1)\">",
		"<embed src=\"javascript:alert(1)\">",
	}

	var blocked int
	var identOK, identWrong int
	var wrongItems []WrongItem

	for _, payload := range payloads {
		data := url.Values{"content": {payload}}
		code, reason := doPostFormIP(ip, "/comment", data)

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

	r.Total = len(payloads)
	r.Blocked = blocked
	r.Passed = r.Total - blocked
	if r.Total > 0 {
		r.BlockRate = float64(blocked) / float64(r.Total) * 100
	}
	r.IdentOK = identOK
	r.IdentWrong = identWrong
	if blocked > 0 {
		r.IdentRate = float64(identOK) / float64(blocked) * 100
	} else {
		r.IdentRate = 100
	}
	r.WrongItems = wrongItems

	fmt.Printf("  XSS: %d payloads, %d blocked (%.1f%%), ident=%d/%d\n",
		r.Total, blocked, r.BlockRate, identOK, blocked)

	checkPass(&r, "block_rate_95%", r.BlockRate >= 95)
	checkPass(&r, "ident_100%", r.IdentRate >= 99)
	if r.Passed > 0 {
		r.Notes = fmt.Sprintf("WARN: %d XSS payloads penetrated!", r.Passed)
	} else {
		r.Notes = "OK: All XSS blocked with correct labels"
	}
	return r
}

// ==================== WebShell Upload ====================
func testWebShellUpload() TestResult {
	fmt.Println("--- WebShell Upload (IP: 10.5.0.3) ---")
	r := TestResult{Name: "WebShell Upload", PassedCheck: true}
	const ip = "10.5.0.3"

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
		{"cmd.war", "<% Runtime.getRuntime().exec(request.getParameter(\"c\")); %>"},
	}

	var blocked int
	var identOK, identWrong int
	var wrongItems []WrongItem

	for _, c := range cases {
		code, reason := doUploadIP(ip, "/upload", c.filename, c.content)
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

	r.Total = len(cases)
	r.Blocked = blocked
	r.Passed = r.Total - blocked
	if r.Total > 0 {
		r.BlockRate = float64(blocked) / float64(r.Total) * 100
	}
	r.IdentOK = identOK
	r.IdentWrong = identWrong
	if blocked > 0 {
		r.IdentRate = float64(identOK) / float64(blocked) * 100
	} else {
		r.IdentRate = 100
	}
	r.WrongItems = wrongItems

	fmt.Printf("  WebShell: %d uploads, %d blocked (%.1f%%), ident=%d/%d\n",
		r.Total, blocked, r.BlockRate, identOK, blocked)

	checkPass(&r, "block_rate_95%", r.BlockRate >= 95)
	checkPass(&r, "ident_100%", r.IdentRate >= 99)
	if r.Passed > 0 {
		r.Notes = fmt.Sprintf("WARN: %d webshells penetrated!", r.Passed)
	} else {
		r.Notes = "OK: All webshells blocked"
	}
	return r
}

// ==================== Brute Force ====================
func testBruteForce() TestResult {
	fmt.Println("--- Brute Force (IP: 10.5.0.4) ---")
	r := TestResult{Name: "Brute Force", PassedCheck: true}
	const ip = "10.5.0.4"

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
		code, reason := doPostFormIP(ip, "/login", data)

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

	r.Total = count
	r.Blocked = blocked
	r.Passed = count - blocked
	if count > 0 {
		r.BlockRate = float64(blocked) / float64(count) * 100
	}
	r.IdentOK = identOK
	r.IdentWrong = identWrong
	if blocked > 0 {
		r.IdentRate = float64(identOK) / float64(blocked) * 100
	} else {
		r.IdentRate = 100
	}
	r.WrongItems = wrongItems
	if blockedAt > 0 {
		r.Notes = fmt.Sprintf("first blocked at req #%d", blockedAt)
	}

	fmt.Printf("  Brute Force: %d req, %d blocked (%.1f%%), ident=%d/%d, first_block=#%d\n",
		count, blocked, r.BlockRate, identOK, blocked, blockedAt)

	checkPass(&r, "detection_works", r.Blocked > 0)
	checkPass(&r, "ident_100%", r.IdentRate >= 99)
	return r
}

// ==================== Normal Requests (False Positive) ====================
func testNormalRequests() TestResult {
	fmt.Println("--- Normal Requests False Positive Test (IP: 10.6.0.1) ---")
	r := TestResult{Name: "Normal Requests FP", PassedCheck: true}
	const ip = "10.6.0.1"

	normalHeaders := map[string]string{
		"User-Agent":      "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
		"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"Accept-Language": "en-US,en;q=0.9",
		"Accept-Encoding": "gzip, deflate",
		"Cache-Control":   "no-cache",
	}

	requests := []struct {
		method string
		path   string
		body   []byte
		ct     string
	}{
		{"GET", "/", nil, ""},
		{"GET", "/style.css", nil, ""},
		{"GET", "/favicon.ico", nil, ""},
		{"GET", "/api/status", nil, ""},
		{"GET", "/about", nil, ""},
		{"GET", "/contact", nil, ""},
		{"GET", "/products", nil, ""},
		{"GET", "/health", nil, ""},
		{"GET", "/ping", nil, ""},
		{"POST", "/search", []byte("q=hello+world"), "application/x-www-form-urlencoded"},
	}

	var blocked int
	var wrongItems []WrongItem

	for _, req := range requests {
		code, reason, _ := doRequestWithIP(ip, req.method, req.path, normalHeaders, req.body)
		if isBlocked(code) {
			blocked++
			wrongItems = append(wrongItems, WrongItem{
				Payload: fmt.Sprintf("%s %s", req.method, req.path),
				ExpectedType: "normal (should pass)", ActualType: reason,
				HTTPCode: code, Issue: "FALSE POSITIVE - normal request blocked",
			})
		}
		time.Sleep(500 * time.Millisecond)
	}

	r.Total = len(requests)
	r.Blocked = blocked
	r.Passed = r.Total - blocked
	if r.Total > 0 {
		r.BlockRate = float64(blocked) / float64(r.Total) * 100
	}
	r.IdentOK = r.Passed
	r.IdentWrong = blocked
	r.IdentRate = 100
	r.WrongItems = wrongItems

	fmt.Printf("  Normal: %d requests, %d blocked (%.1f%% false positives)\n",
		r.Total, blocked, r.BlockRate)

	checkPass(&r, "fp_rate_lt_2%", r.BlockRate < 2)
	checkPass(&r, "no_false_positives", blocked == 0)

	if blocked > 0 {
		r.Notes = fmt.Sprintf("WARN: %d false positives detected", blocked)
	} else {
		r.Notes = "OK: No false positives on normal traffic"
	}
	return r
}

// ==================== HTTP Helpers ====================

func doRequestWithIP(ip, method, path string, headers map[string]string, body []byte) (int, string, []byte) {
	req, _ := http.NewRequest(method, shieldURL+path, bytes.NewReader(body))
	req.Header.Set("X-Forwarded-For", ip)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if len(body) > 0 && headers != nil && headers["Content-Type"] == "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
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

// ==================== Helpers ====================

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

func checkPass(r *TestResult, checkName string, condition bool) {
	if !condition {
		r.PassedCheck = false
		fmt.Printf("    FAIL Check '%s'\n", checkName)
	}
}
