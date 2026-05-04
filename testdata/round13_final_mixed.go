// Round 13 Final Mixed Test — DDoS/CC attack + dual normal traffic simulation
//
// Tests false positive rates during large-scale attacks:
//   A. 100 independent clean IPs making normal requests (should NOT be blocked)
//   B. 100 attack-pool IPs making normal requests (should NOT be blocked if WAF
//      correctly distinguishes attack behavior from normal behavior on same IP)
//
// Usage: go run round13_final_mixed_test.go [ddos|cc]

package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	TargetURL = "http://127.0.0.1:8081"
	AdminURL  = "http://127.0.0.1:9090/stats"

	// DDoS config
	DDoSDuration    = 35 * time.Second
	DDoSWorkers     = 400
	DDoSTotalIPs    = 2000
	DDoSTargetPaths = 10

	// CC config
	CCDuration  = 50 * time.Second
	CCWorkers   = 250
	CCUniqueIPs = 1000
	CCBurstSize = 12

	// Normal user config
	NormalCleanIPs        = 100
	NormalAttackPoolIPs   = 100
	NormalRequestsPerIP   = 8  // how many requests each normal IP makes
	NormalRequestInterval = 1200 * time.Millisecond
	NormalStartDelay      = 5 * time.Second // start normal traffic after attack ramps up
)

// ============================================================
// IP Generation (same as distributed attack)
// ============================================================
func randomIP(rng *rand.Rand) string {
	subnets := [][]int{
		{10, 0, 0, 0}, {172, 16, 0, 0}, {192, 168, 0, 0},
		{100, 64, 0, 0}, {1, 0, 0, 0}, {45, 0, 0, 0},
		{103, 0, 0, 0}, {114, 0, 0, 0}, {116, 0, 0, 0},
		{117, 0, 0, 0}, {118, 0, 0, 0}, {119, 0, 0, 0},
		{121, 0, 0, 0}, {123, 0, 0, 0}, {124, 0, 0, 0},
		{125, 0, 0, 0}, {180, 0, 0, 0}, {182, 0, 0, 0},
		{183, 0, 0, 0}, {202, 0, 0, 0}, {203, 0, 0, 0},
		{210, 0, 0, 0}, {211, 0, 0, 0}, {218, 0, 0, 0},
		{219, 0, 0, 0}, {220, 0, 0, 0}, {221, 0, 0, 0},
		{222, 0, 0, 0}, {223, 0, 0, 0},
	}
	s := subnets[rng.Intn(len(subnets))]
	a := s[0] + rng.Intn(256-s[0])
	if a > 255 { a = s[0] }
	return fmt.Sprintf("%d.%d.%d.%d", a, rng.Intn(256), rng.Intn(256), rng.Intn(254)+1)
}

func randomUA(rng *rand.Rand) string {
	uas := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:120.0) Gecko/20100101 Firefox/120.0",
		"Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Mobile Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
	}
	return uas[rng.Intn(len(uas))]
}

// ============================================================
// Normal user paths (different from attack paths)
// ============================================================
var normalPaths = []string{
	"/",
	"/about",
	"/contact",
	"/products?page=1",
	"/products?page=2",
	"/category/electronics",
	"/category/books",
	"/faq",
	"/terms",
	"/privacy",
	"/blog",
	"/blog/post-1",
	"/help",
	"/sitemap",
}

var normalPostPaths = []struct{ path, body string }{
	{"/contact", "name=John&email=john@example.com&message=Hello"},
	{"/newsletter", "email=subscriber@example.com"},
	{"/survey", "rating=4&comment=Good"},
}

// ============================================================
// Stats tracking
// ============================================================
type NormalStats struct {
	sent     int64
	blocked  int64 // 403
	challenge int64 // 429
	passed   int64 // 200
	errors   int64
}

type AttackStats struct {
	sent       int64
	blocked    int64
	challenged int64
	passed     int64
	errors     int64
}

// ============================================================
// HTTP Client
// ============================================================
func makeClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
			MaxIdleConns:          200,
			MaxIdleConnsPerHost:   100,
			IdleConnTimeout:       90 * time.Second,
			DisableCompression:    false,
			DisableKeepAlives:     false,
			ResponseHeaderTimeout: 10 * time.Second,
		},
		Timeout: 15 * time.Second,
	}
}

func getMetrics() string {
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	resp, err := client.Get(AdminURL)
	if err != nil { return fmt.Sprintf("error: %v", err) }
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return string(body)
}

func doRequest(client *http.Client, path string, ip string, ua string) (int, error) {
	req, _ := http.NewRequest("GET", TargetURL+path, nil)
	req.Header.Set("User-Agent", ua)
	req.Header.Set("X-Forwarded-For", ip)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Connection", "keep-alive")

	resp, err := client.Do(req)
	if err != nil { return 0, err }
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode, nil
}

// ============================================================
// Normal user simulator: makes browsing-like requests
// ============================================================
func runNormalUser(ip string, stats *NormalStats, stopCh chan struct{}, wg *sync.WaitGroup, label string) {
	defer wg.Done()

	rng := rand.New(rand.NewSource(time.Now().UnixNano() + int64(len(ip))))
	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	ua := randomUA(rng)

	for reqNum := 0; reqNum < NormalRequestsPerIP; reqNum++ {
		select {
		case <-stopCh:
			return
		default:
		}

		// Simulate browsing: navigate through different pages
		var path string
		if reqNum == 0 {
			path = "/" // start at homepage
		} else if reqNum%4 == 0 && len(normalPostPaths) > 0 {
			// Occasionally do a POST (like submitting a form)
			pp := normalPostPaths[rng.Intn(len(normalPostPaths))]
			path = pp.path
			// For simplicity, we still use GET for normal requests
			path = normalPaths[rng.Intn(len(normalPaths))]
		} else {
			path = normalPaths[rng.Intn(len(normalPaths))]
		}

		status, err := doRequest(client, path, ip, ua)
		atomic.AddInt64(&stats.sent, 1)

		if err != nil {
			atomic.AddInt64(&stats.errors, 1)
		} else {
			switch {
			case status == 403:
				atomic.AddInt64(&stats.blocked, 1)
			case status == 429:
				atomic.AddInt64(&stats.challenge, 1)
			case status == 200:
				atomic.AddInt64(&stats.passed, 1)
			default:
				atomic.AddInt64(&stats.errors, 1)
			}
		}

		// Realistic delay between page views
		select {
		case <-stopCh:
			return
		case <-time.After(NormalRequestInterval + time.Duration(rng.Intn(800))*time.Millisecond):
		}
	}
}

// ============================================================
// DDoS Attack
// ============================================================
func runDDoS(attackIps []string, stats *AttackStats, stopCh chan struct{}, wg *sync.WaitGroup) {
	client := makeClient()
	duration := DDoSDuration

	for w := 0; w < DDoSWorkers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			localRng := rand.New(rand.NewSource(time.Now().UnixNano() + int64(workerID)))
			for {
				select {
				case <-stopCh: return
				default:
				}
				ip := attackIps[localRng.Intn(len(attackIps))]
				path := fmt.Sprintf("/api/v1/%s", []string{"users","products","search","status","data"}[localRng.Intn(5)])
				if localRng.Intn(3) == 0 {
					path = fmt.Sprintf("/?q=%d", localRng.Intn(10000))
				}
				ua := randomUA(localRng)
				status, err := doRequest(client, path, ip, ua)
				atomic.AddInt64(&stats.sent, 1)
				if err != nil { atomic.AddInt64(&stats.errors, 1); continue }
				switch {
				case status == 403: atomic.AddInt64(&stats.blocked, 1)
				case status == 429: atomic.AddInt64(&stats.challenged, 1)
				case status == 200: atomic.AddInt64(&stats.passed, 1)
				default: atomic.AddInt64(&stats.errors, 1)
				}
			}
		}(w)
	}
	_ = duration
}

// ============================================================
// CC Attack
// ============================================================
func runCC(attackIps []string, stats *AttackStats, stopCh chan struct{}, wg *sync.WaitGroup) {
	client := makeClient()
	ccPaths := []string{"/", "/login", "/api/v1/search?q=popular", "/index.html", "/api/v1/products"}

	for w := 0; w < CCWorkers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			localRng := rand.New(rand.NewSource(time.Now().UnixNano() + int64(workerID)))
			for {
				select {
				case <-stopCh: return
				default:
				}
				ip := attackIps[localRng.Intn(len(attackIps))]
				path := ccPaths[localRng.Intn(len(ccPaths))]
				ua := randomUA(localRng)
				for i := 0; i < CCBurstSize; i++ {
					select {
					case <-stopCh: return
					default:
					}
					status, err := doRequest(client, path, ip, ua)
					atomic.AddInt64(&stats.sent, 1)
					if err != nil { atomic.AddInt64(&stats.errors, 1); continue }
					switch {
					case status == 403: atomic.AddInt64(&stats.blocked, 1)
					case status == 429: atomic.AddInt64(&stats.challenged, 1)
					case status == 200: atomic.AddInt64(&stats.passed, 1)
					default: atomic.AddInt64(&stats.errors, 1)
					}
				}
				time.Sleep(time.Duration(50+localRng.Intn(100)) * time.Millisecond)
			}
		}(w)
	}
}

// ============================================================
// Main test orchestrator
// ============================================================
func runTest(attackType string, attackIps []string, duration time.Duration, runAttack func([]string, *AttackStats, chan struct{}, *sync.WaitGroup)) {
	fmt.Println(strings.Repeat("=", 70))
	fmt.Printf("  FINAL MIXED TEST: %s Attack + Normal Traffic\n", attackType)
	fmt.Printf("  Clean IPs: %d | Attack-Pool IPs: %d | Requests/IP: %d\n",
		NormalCleanIPs, NormalAttackPoolIPs, NormalRequestsPerIP)
	fmt.Println(strings.Repeat("=", 70))

	fmt.Printf("\nBefore Attack:\n%s\n\n", getMetrics())

	rng := rand.New(rand.NewSource(time.Now().UnixNano()))

	// Generate CLEAN IP pool (NOT in attack pool)
	attackIPSet := make(map[string]bool)
	for _, ip := range attackIps {
		attackIPSet[ip] = true
	}
	cleanIps := make([]string, NormalCleanIPs)
	for i := 0; i < NormalCleanIPs; i++ {
		for {
			ip := randomIP(rng)
			if !attackIPSet[ip] {
				cleanIps[i] = ip
				attackIPSet[ip] = true // mark as used so we don't duplicate
				break
			}
			// Unlikely infinite loop with 2000+ attack IPs and diverse subnets
		}
	}

	// Select 100 IPs from the attack pool for normal-request-from-attack-IP test
	attackPoolNormIps := make([]string, NormalAttackPoolIPs)
	perm := rng.Perm(len(attackIps))
	for i := 0; i < NormalAttackPoolIPs && i < len(perm); i++ {
		attackPoolNormIps[i] = attackIps[perm[i]]
	}

	// Stats
	attackStats := &AttackStats{}
	cleanStats := &NormalStats{}
	attackPoolStats := &NormalStats{}

	var attackWg sync.WaitGroup
	var normalWg sync.WaitGroup
	stopCh := make(chan struct{})

	// Phase 1: Launch attack
	fmt.Printf("[Phase 1] Starting %s attack...\n", attackType)
	runAttack(attackIps, attackStats, stopCh, &attackWg)

	// Phase 2: Wait for attack to ramp up, then start normal traffic
	fmt.Printf("[Phase 2] Waiting %v for attack ramp-up...\n", NormalStartDelay)
	time.Sleep(NormalStartDelay)

	// Launch CLEAN normal users
	fmt.Printf("[Phase 3] Launching %d clean-IP normal users...\n", NormalCleanIPs)
	for i := 0; i < NormalCleanIPs; i++ {
		normalWg.Add(1)
		go runNormalUser(cleanIps[i], cleanStats, stopCh, &normalWg, "clean")
	}

	// Launch ATTACK-POOL normal users (same IPs as attack, but normal behavior)
	fmt.Printf("[Phase 4] Launching %d attack-pool-IP normal users...\n", NormalAttackPoolIPs)
	for i := 0; i < NormalAttackPoolIPs; i++ {
		normalWg.Add(1)
		go runNormalUser(attackPoolNormIps[i], attackPoolStats, stopCh, &normalWg, "attack-pool")
	}

	// Progress reporting
	remaining := duration - NormalStartDelay
	ticker := time.NewTicker(10 * time.Second)
	startTime := time.Now()
	go func() {
		for range ticker.C {
			elapsed := time.Since(startTime)
			fmt.Printf("  [%ds] Attack: sent=%d blocked=%d challenged=%d passed=%d | Clean norm: sent=%d blocked=%d passed=%d | Attack-IP norm: sent=%d blocked=%d passed=%d\n",
				int(elapsed.Seconds()),
				atomic.LoadInt64(&attackStats.sent),
				atomic.LoadInt64(&attackStats.blocked),
				atomic.LoadInt64(&attackStats.challenged),
				atomic.LoadInt64(&attackStats.passed),
				atomic.LoadInt64(&cleanStats.sent),
				atomic.LoadInt64(&cleanStats.blocked),
				atomic.LoadInt64(&cleanStats.passed),
				atomic.LoadInt64(&attackPoolStats.sent),
				atomic.LoadInt64(&attackPoolStats.blocked),
				atomic.LoadInt64(&attackPoolStats.passed),
			)
		}
	}()

	time.Sleep(remaining)
	fmt.Println("\n[Stopping] Attack duration complete, stopping all workers...")
	close(stopCh)
	ticker.Stop()

	// Wait for normal users to finish their current requests
	normalWg.Wait()
	attackWg.Wait()

	// ============================================================
	// Results
	// ============================================================
	fmt.Printf("\n%s\n", strings.Repeat("=", 70))
	fmt.Printf("  %s ATTACK RESULTS\n", attackType)
	fmt.Println(strings.Repeat("=", 70))

	as := attackStats
	atotal := atomic.LoadInt64(&as.sent)
	fmt.Printf("  Attack Requests:\n")
	fmt.Printf("    Sent: %d | Blocked(403): %d | Challenged(429): %d | Passed(200): %d | Errors: %d\n",
		atotal,
		atomic.LoadInt64(&as.blocked),
		atomic.LoadInt64(&as.challenged),
		atomic.LoadInt64(&as.passed),
		atomic.LoadInt64(&as.errors))

	fmt.Printf("\n  NORMAL REQUESTS FROM CLEAN IPs (should NOT be blocked):\n")
	cs := cleanStats
	ctotal := atomic.LoadInt64(&cs.sent)
	cblocked := atomic.LoadInt64(&cs.blocked) + atomic.LoadInt64(&cs.challenge)
	cpassed := atomic.LoadInt64(&cs.passed)
	cerrors := atomic.LoadInt64(&cs.errors)
	fmt.Printf("    Sent: %d | Blocked(403): %d | Challenged(429): %d | Passed(200): %d | Errors: %d\n",
		ctotal, atomic.LoadInt64(&cs.blocked), atomic.LoadInt64(&cs.challenge), cpassed, cerrors)
	fpr := float64(0)
	if ctotal > 0 { fpr = float64(cblocked) / float64(ctotal) * 100 }
	fmt.Printf("    FALSE POSITIVE RATE: %.1f%% (%d/%d blocked)\n", fpr, cblocked, ctotal)

	fmt.Printf("\n  NORMAL REQUESTS FROM ATTACK-POOL IPs (should NOT be blocked if WAF distinguishes):\n")
	aps := attackPoolStats
	aptotal := atomic.LoadInt64(&aps.sent)
	apblocked := atomic.LoadInt64(&aps.blocked) + atomic.LoadInt64(&aps.challenge)
	appassed := atomic.LoadInt64(&aps.passed)
	aperrors := atomic.LoadInt64(&aps.errors)
	fmt.Printf("    Sent: %d | Blocked(403): %d | Challenged(429): %d | Passed(200): %d | Errors: %d\n",
		aptotal, atomic.LoadInt64(&aps.blocked), atomic.LoadInt64(&aps.challenge), appassed, aperrors)
	apfpr := float64(0)
	if aptotal > 0 { apfpr = float64(apblocked) / float64(aptotal) * 100 }
	fmt.Printf("    COLLATERAL BLOCK RATE: %.1f%% (%d/%d blocked)\n", apfpr, apblocked, aptotal)

	fmt.Printf("\nAfter Attack:\n%s\n", getMetrics())

	// Summary for report
	fmt.Printf("\n%s\n", strings.Repeat("=", 70))
	fmt.Printf("  VERDICT FOR %s\n", attackType)
	fmt.Println(strings.Repeat("=", 70))
	if fpr > 2.0 {
		fmt.Printf("  ❌ Clean-IP false positive rate %.1f%% exceeds 2%% threshold\n", fpr)
	} else {
		fmt.Printf("  ✅ Clean-IP false positive rate %.1f%% within 2%% threshold\n", fpr)
	}
	if apfpr > 10.0 {
		fmt.Printf("  ❌ Attack-IP collateral block rate %.1f%% — WAF blocks all traffic from flagged IPs\n", apfpr)
	} else if apfpr > 2.0 {
		fmt.Printf("  ⚠️  Attack-IP collateral block rate %.1f%% — moderate collateral damage\n", apfpr)
	} else {
		fmt.Printf("  ✅ Attack-IP collateral block rate %.1f%% — WAF correctly distinguishes behavior\n", apfpr)
	}
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run round13_final_mixed_test.go [ddos|cc]")
		os.Exit(1)
	}

	mode := os.Args[1]

	rng := rand.New(rand.NewSource(time.Now().UnixNano()))

	switch mode {
	case "ddos":
		ips := make([]string, DDoSTotalIPs)
		for i := range ips { ips[i] = randomIP(rng) }
		runTest("DDoS", ips, DDoSDuration, runDDoS)

	case "cc":
		ips := make([]string, CCUniqueIPs)
		for i := range ips { ips[i] = randomIP(rng) }
		runTest("CC", ips, CCDuration, runCC)

	default:
		fmt.Printf("Unknown mode: %s (use 'ddos' or 'cc')\n", mode)
		os.Exit(1)
	}

	fmt.Println("\nDone.")
}
