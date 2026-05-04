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

const (
	targetURL    = "http://127.0.0.1:8081/"
	numIPs       = 100
	delayBetween = 150 * time.Millisecond // ~6.7 req/s, keeps global rate under 22
)

type IPResult struct {
	IP          string
	StatusCode  int
	BlockReason string
	BodyPreview string
	Category    string // "pass", "challenge", "blocked"
	Duration    time.Duration
}

func main() {
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // don't follow redirects
		},
	}

	var results []IPResult
	var mu sync.Mutex
	var wg sync.WaitGroup

	fmt.Println("=== Shield WAF 100 Normal IP Traffic Test ===")
	fmt.Printf("Target: %s\n", targetURL)
	fmt.Printf("IP count: %d, Delay between: %v\n", numIPs, delayBetween)
	fmt.Println()

	startTime := time.Now()

	for i := 0; i < numIPs; i++ {
		ip := fmt.Sprintf("192.168.%d.%d", (i/254)+1, (i%254)+1)

		wg.Add(1)
		go func(ip string) {
			defer wg.Done()

			req, _ := http.NewRequest("GET", targetURL, nil)
			req.Header.Set("X-Forwarded-For", ip)
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
			req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
			req.Header.Set("Accept-Language", "en-US,en;q=0.9,zh-CN;q=0.8")
			req.Header.Set("Accept-Encoding", "gzip, deflate, br")
			req.Header.Set("Connection", "keep-alive")
			req.Header.Set("Cache-Control", "no-cache")

			reqStart := time.Now()
			resp, err := client.Do(req)
			dur := time.Since(reqStart)

			result := IPResult{IP: ip, Duration: dur}

			if err != nil {
				result.StatusCode = -1
				result.Category = "error"
				result.BodyPreview = err.Error()
			} else {
				defer resp.Body.Close()
				result.StatusCode = resp.StatusCode
				result.BlockReason = resp.Header.Get("X-Block-Reason")

				bodyBytes := make([]byte, 500)
				n, _ := io.ReadFull(resp.Body, bodyBytes)
				if n > 0 {
					result.BodyPreview = string(bodyBytes[:n])
				}

				switch {
				case resp.StatusCode >= 200 && resp.StatusCode < 300:
					result.Category = "pass"
				case resp.StatusCode == 302 || resp.StatusCode == 301:
					result.Category = "pass"
				case resp.StatusCode == 429:
					body := string(bodyBytes[:n])
					if strings.Contains(body, "Verifying") || strings.Contains(body, "Security Check") {
						result.Category = "challenge"
					} else {
						result.Category = "blocked"
					}
				case resp.StatusCode == 403:
					result.Category = "blocked"
				case resp.StatusCode == 503:
					result.Category = "blocked"
				default:
					result.Category = "other"
				}
			}

			mu.Lock()
			results = append(results, result)
			mu.Unlock()

			fmt.Printf("[%s] IP=%s Status=%d Category=%s Reason=%s (%.2fs)\n",
				time.Now().Format("15:04:05"), ip, result.StatusCode, result.Category, result.BlockReason, dur.Seconds())
		}(ip)

		time.Sleep(delayBetween)
	}

	wg.Wait()
	totalDuration := time.Since(startTime)

	// Summary
	var pass, challenge, blocked, other int
	for _, r := range results {
		switch r.Category {
		case "pass":
			pass++
		case "challenge":
			challenge++
		case "blocked":
			blocked++
		default:
			other++
		}
	}

	fmt.Println()
	fmt.Println("============================================")
	fmt.Println("           TEST RESULTS SUMMARY")
	fmt.Println("============================================")
	fmt.Printf("Total IPs tested:  %d\n", numIPs)
	fmt.Printf("Total duration:    %.2fs\n", totalDuration.Seconds())
	fmt.Println()
	fmt.Printf("  Pass (200/302):  %d (%.1f%%)\n", pass, float64(pass)/numIPs*100)
	fmt.Printf("  Challenge (429): %d (%.1f%%)\n", challenge, float64(challenge)/numIPs*100)
	fmt.Printf("  Blocked (403/503): %d (%.1f%%)\n", blocked, float64(blocked)/numIPs*100)
	fmt.Printf("  Other:           %d\n", other)
	fmt.Println()

	combinedPass := pass + challenge
	fmt.Printf("  Pass + Challenge: %d (%.1f%%)\n", combinedPass, float64(combinedPass)/numIPs*100)
	fmt.Printf("  True Blocks:     %d (%.1f%%)\n", blocked, float64(blocked)/numIPs*100)
	fmt.Println()

	// Print challenge details
	if challenge > 0 {
		fmt.Println("--- Challenge Details ---")
		for _, r := range results {
			if r.Category == "challenge" {
				challengeType := "unknown"
				if strings.Contains(r.BodyPreview, "Environment check") || strings.Contains(r.BodyPreview, "canvas") || strings.Contains(r.BodyPreview, "fp_canvas") {
					challengeType = "env_fingerprint"
				} else if strings.Contains(r.BodyPreview, "proof of work") || strings.Contains(r.BodyPreview, "PoW") {
					challengeType = "pow"
				} else if strings.Contains(r.BodyPreview, "Verifying") {
					challengeType = "js_challenge"
				}
				fmt.Printf("  IP=%s Reason=%s Type=%s\n", r.IP, r.BlockReason, challengeType)
			}
		}
		fmt.Println()
	}

	// Print block details
	if blocked > 0 {
		fmt.Println("--- Block Details ---")
		for _, r := range results {
			if r.Category == "blocked" {
				fmt.Printf("  IP=%s Status=%d Reason=%s Body=%s\n", r.IP, r.StatusCode, r.BlockReason, strings.TrimSpace(r.BodyPreview))
			}
		}
		fmt.Println()
	}

	// Pass/fail assessment
	passRate := float64(combinedPass) / numIPs * 100
	fmt.Println("============================================")
	fmt.Println("           ASSESSMENT")
	fmt.Println("============================================")
	if passRate >= 95.0 {
		fmt.Printf("PASS: %.1f%% of normal IPs not blocked (≥95%% required)\n", passRate)
	} else {
		fmt.Printf("FAIL: %.1f%% of normal IPs not blocked (<95%% required)\n", passRate)
	}

	if blocked > 0 {
		fmt.Println("ISSUE: Normal IPs were incorrectly blocked!")
		for _, r := range results {
			if r.Category == "blocked" {
				fmt.Printf("  - %s: %d %s\n", r.IP, r.StatusCode, r.BlockReason)
			}
		}
	} else {
		fmt.Println("OK: No normal IPs were incorrectly blocked.")
	}

	// Per-IP detail table
	fmt.Println()
	fmt.Println("============================================")
	fmt.Println("           PER-IP DETAILS")
	fmt.Println("============================================")
	fmt.Printf("%-20s %-8s %-12s %-30s\n", "IP", "Status", "Category", "Block-Reason")
	fmt.Println(strings.Repeat("-", 75))
	for _, r := range results {
		fmt.Printf("%-20s %-8d %-12s %-30s\n", r.IP, r.StatusCode, r.Category, r.BlockReason)
	}
}
