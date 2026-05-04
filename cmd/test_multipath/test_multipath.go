package main

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

func main() {
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Test: 100 IPs, each hitting a DIFFERENT path (to verify path concentration is the culprit)
	fmt.Println("=== Test: 100 IPs with unique paths (avoids path concentration) ===")
	var pass, challenge, blocked int
	var wg sync.WaitGroup
	var mu sync.Mutex
	type Result struct {
		IP string
		Status int
		Reason string
		Category string
	}
	var results []Result

	for i := 0; i < 100; i++ {
		ip := fmt.Sprintf("172.16.%d.%d", (i/254)+1, (i%254)+1)
		path := fmt.Sprintf("/page%d.html", i+1)
		
		wg.Add(1)
		go func(ip, path string) {
			defer wg.Done()
			req, _ := http.NewRequest("GET", "http://127.0.0.1:8081"+path, nil)
			req.Header.Set("X-Forwarded-For", ip)
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0") 
			req.Header.Set("Accept", "text/html,application/xhtml+xml")
			req.Header.Set("Accept-Language", "en-US,en;q=0.9")
			req.Header.Set("Accept-Encoding", "gzip, deflate")
			req.Header.Set("Connection", "keep-alive")
			req.Header.Set("Cache-Control", "no-cache")

			resp, err := client.Do(req)
			r := Result{IP: ip}
			if err != nil {
				r.Status = -1
				r.Category = "error"
			} else {
				defer resp.Body.Close()
				r.Status = resp.StatusCode
				r.Reason = resp.Header.Get("X-Block-Reason")
				switch {
				case resp.StatusCode < 300:
					r.Category = "pass"
				case resp.StatusCode == 429 && strings.Contains(resp.Header.Get("X-Block-Reason"), "challenge"):
					r.Category = "challenge"
				default:
					r.Category = "blocked"
				}
			}
			mu.Lock()
			results = append(results, r)
			mu.Unlock()
		}(ip, path)
		time.Sleep(80 * time.Millisecond)
	}
	wg.Wait()

	for _, r := range results {
		switch r.Category {
		case "pass": pass++
		case "challenge": challenge++
		case "blocked": blocked++
		}
	}

	fmt.Printf("Total: %d\n", len(results))
	fmt.Printf("Pass: %d (%.1f%%)\n", pass, float64(pass)/100*100)
	fmt.Printf("Challenge: %d (%.1f%%)\n", challenge, float64(challenge)/100*100)
	fmt.Printf("Blocked: %d (%.1f%%)\n", blocked, float64(blocked)/100*100)
	fmt.Printf("Not Blocked: %d (%.1f%%)\n\n", pass+challenge, float64(pass+challenge)/100*100)

	if blocked > 0 {
		fmt.Println("--- Blocked IPs ---")
		for _, r := range results {
			if r.Category == "blocked" {
				fmt.Printf("  %s: %d %s\n", r.IP, r.Status, r.Reason)
			}
		}
	}
}
