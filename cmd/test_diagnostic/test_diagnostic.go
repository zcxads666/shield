package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
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

	// Test A: Just 49 IPs (below path_ip_threshold of 50)
	fmt.Println("=== Test A: 49 IPs (below path threshold) ===")
	for i := 0; i < 49; i++ {
		ip := fmt.Sprintf("10.1.0.%d", i+1)
		req, _ := http.NewRequest("GET", "http://127.0.0.1:8081/", nil)
		req.Header.Set("X-Forwarded-For", ip)
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0")
		req.Header.Set("Accept", "text/html,application/xhtml+xml")
		req.Header.Set("Accept-Language", "en-US,en;q=0.9")
		req.Header.Set("Accept-Encoding", "gzip, deflate, br")
		req.Header.Set("Connection", "keep-alive")
		req.Header.Set("Cache-Control", "no-cache")

		resp, err := client.Do(req)
		if err != nil {
			fmt.Printf("IP=%s ERROR: %v\n", ip, err)
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		cat := "pass"
		if resp.StatusCode >= 400 {
			cat = "blocked/challenge"
		}
		fmt.Printf("IP=%s Status=%d Reason=%s Cat=%s\n", ip, resp.StatusCode, resp.Header.Get("X-Block-Reason"), cat)
		_ = body
		time.Sleep(50 * time.Millisecond)
	}

	// Wait 30s for path stats to expire (path window is 600s, so won't expire, but let's test separately)
	fmt.Println("\nWaiting 5s before Test B...")
	time.Sleep(5 * time.Second)

	// Test B: 100 IPs, each making 4 requests (avg > 3, should avoid path concentration)
	fmt.Println("\n=== Test B: 100 IPs, 4 reqs each (avg > path_avg_req_threshold) ===")
	blockCount := 0
	passCount := 0
	for i := 0; i < 100; i++ {
		ip := fmt.Sprintf("10.2.0.%d", i+1)
		for j := 0; j < 4; j++ {
			req, _ := http.NewRequest("GET", "http://127.0.0.1:8081/", nil)
			req.Header.Set("X-Forwarded-For", ip)
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0")
			req.Header.Set("Accept", "text/html,application/xhtml+xml")
			req.Header.Set("Accept-Language", "en-US")
			req.Header.Set("Accept-Encoding", "gzip, deflate")
			req.Header.Set("Connection", "keep-alive")

			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			_ = body

			if resp.StatusCode >= 400 {
				if strings.Contains(resp.Header.Get("X-Block-Reason"), "block") &&
					!strings.Contains(resp.Header.Get("X-Block-Reason"), "challenge") {
					blockCount++
					if j == 0 {
						fmt.Printf("IP=%s req#%d BLOCKED: %d %s\n", ip, j+1, resp.StatusCode, resp.Header.Get("X-Block-Reason"))
					}
				}
			} else {
				passCount++
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	fmt.Printf("Results: Pass=%d, Block=%d\n", passCount, blockCount)

	// Test C: Check if we can get challenge page and solve it
	fmt.Println("\n=== Test C: Challenge flow test ===")
	ip := "10.3.0.1"
	req, _ := http.NewRequest("GET", "http://127.0.0.1:8081/", nil)
	req.Header.Set("X-Forwarded-For", ip)
	req.Header.Set("User-Agent", "Mozilla/5.0 Chrome/120.0.0.0")
	req.Header.Set("Accept", "text/html")
	req.Header.Set("Accept-Language", "en-US")
	req.Header.Set("Accept-Encoding", "gzip, deflate")
	req.Header.Set("Connection", "keep-alive")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		body, _ := io.ReadAll(resp.Body)
		cookies := resp.Cookies()
		resp.Body.Close()
		fmt.Printf("Status: %d, Reason: %s\n", resp.StatusCode, resp.Header.Get("X-Block-Reason"))
		fmt.Printf("Cookies: %v\n", cookies)
		bodyStr := string(body)
		if len(bodyStr) > 200 {
			bodyStr = bodyStr[:200]
		}
		fmt.Printf("Body preview: %s\n", bodyStr)
	}
}
