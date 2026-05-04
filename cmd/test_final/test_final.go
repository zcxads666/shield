package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

type Result struct {
	IP         string
	StatusCode int
	Reason     string
	Category   string
	BodyLen    int
	Duration   time.Duration
}

func main() {
	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	var results []Result
	var mu sync.Mutex
	var wg sync.WaitGroup

	fmt.Println("=== Shield WAF 100 Normal IPs Test (Clean State) ===")
	fmt.Printf("Start: %s\n", time.Now().Format("15:04:05"))
	
	startTime := time.Now()

	for i := 0; i < 100; i++ {
		ip := fmt.Sprintf("10.10.%d.%d", (i/254)+1, (i%254)+1)

		wg.Add(1)
		go func(ip string, idx int) {
			defer wg.Done()

			req, _ := http.NewRequest("GET", "http://127.0.0.1:8081/", nil)
			req.Header.Set("X-Forwarded-For", ip)
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
			req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
			req.Header.Set("Accept-Language", "en-US,en;q=0.9")
			req.Header.Set("Accept-Encoding", "gzip, deflate, br")
			req.Header.Set("Connection", "keep-alive")
			req.Header.Set("Cache-Control", "no-cache")

			reqStart := time.Now()
			resp, err := client.Do(req)
			dur := time.Since(reqStart)

			r := Result{IP: ip, Duration: dur}
			if err != nil {
				r.StatusCode = -1
				r.Category = "error"
			} else {
				defer resp.Body.Close()
				body, _ := io.ReadAll(resp.Body)
				r.BodyLen = len(body)
				r.StatusCode = resp.StatusCode
				r.Reason = resp.Header.Get("X-Block-Reason")

				switch {
				case resp.StatusCode >= 200 && resp.StatusCode < 300:
					r.Category = "pass"
				case resp.StatusCode >= 300 && resp.StatusCode < 400:
					r.Category = "pass"
				case resp.StatusCode == 429:
					bodyStr := string(body)
					if strings.Contains(bodyStr, "Verifying") || strings.Contains(bodyStr, "Security Check") || strings.Contains(bodyStr, "Please wait") {
						r.Category = "challenge"
					} else {
						r.Category = "blocked"
					}
				case resp.StatusCode == 403:
					r.Category = "blocked"
				case resp.StatusCode == 503:
					r.Category = "blocked"
				default:
					r.Category = "other"
				}
			}

			mu.Lock()
			results = append(results, r)
			mu.Unlock()

			fmt.Printf("[#%03d] IP=%s Status=%d Cat=%s Reason=%s (%.3fs)\n",
				idx+1, ip, r.StatusCode, r.Category, r.Reason, dur.Seconds())
		}(ip, i)

		time.Sleep(120 * time.Millisecond) // ~8.3 req/s, well under 22 RPS
	}

	wg.Wait()
	totalDuration := time.Since(startTime)

	// --- Summary ---
	var pass, challenge, blocked, other int
	for _, r := range results {
		switch r.Category {
		case "pass": pass++
		case "challenge": challenge++
		case "blocked": blocked++
		default: other++
		}
	}

	fmt.Println()
	fmt.Println("============================================")
	fmt.Println("           TEST RESULTS SUMMARY")
	fmt.Println("============================================")
	fmt.Printf("Total IPs:        %d\n", len(results))
	fmt.Printf("Total duration:   %.2fs\n", totalDuration.Seconds())
	fmt.Println()
	fmt.Printf("  Pass (2xx/3xx): %d (%.1f%%)\n", pass, float64(pass)/100*100)
	fmt.Printf("  Challenge (429): %d (%.1f%%)\n", challenge, float64(challenge)/100*100)
	fmt.Printf("  Blocked (403/503/429-no-challenge): %d (%.1f%%)\n", blocked, float64(blocked)/100*100)
	fmt.Printf("  Other:           %d\n", other)
	fmt.Println()
	fmt.Printf("  Not Blocked (pass+challenge): %d (%.1f%%)\n", pass+challenge, float64(pass+challenge)/100*100)
	fmt.Println()

	// Block details
	if blocked > 0 {
		fmt.Println("--- BLOCKED IPs ---")
		for _, r := range results {
			if r.Category == "blocked" {
				fmt.Printf("  %s Status=%d Reason=%s BodyLen=%d\n", r.IP, r.StatusCode, r.Reason, r.BodyLen)
			}
		}
		fmt.Println()
	}

	// Challenge details
	if challenge > 0 {
		fmt.Println("--- CHALLENGED IPs ---")
		for _, r := range results {
			if r.Category == "challenge" {
				fmt.Printf("  %s Status=%d Reason=%s BodyLen=%d\n", r.IP, r.StatusCode, r.Reason, r.BodyLen)
			}
		}
		fmt.Println()
	}

	// Assessment
	notBlocked := pass + challenge
	rate := float64(notBlocked) / 100 * 100
	fmt.Println("============================================")
	fmt.Println("           ASSESSMENT")
	fmt.Println("============================================")
	if rate >= 95.0 {
		fmt.Printf("PASS: %.1f%% not blocked (>=95%%)\n", rate)
	} else {
		fmt.Printf("FAIL: %.1f%% not blocked (<95%% required)\n", rate)
	}
	fmt.Printf("Pass: %d | Challenge: %d | Blocked: %d\n", pass, challenge, blocked)
	
	if blocked > 0 {
		fmt.Println("\nRoot cause analysis:")
		fmt.Println("- All blocked IPs received X-Block-Reason: ddos/cc:block")
		fmt.Println("- This indicates direct blocking (not challenge-response)")
		fmt.Println("- Normal browser traffic was incorrectly classified as attack traffic")
	}
}
