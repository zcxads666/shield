// Round 13 Final Mixed Test v2 — Normal users solving WAF challenges
//
// The WAF challenge flow:
//   1. Request → 429 EnvFingerprint page with _s, _t, _esig, _u
//   2. Browser JS collects Canvas/WebGL fingerprint → auto-submits
//   3. WAF verifies HMAC (client sends back server's own _esig) + checks webgl_renderer
//   4. If passed → cookie valid → Layer 0 bypass → all subsequent requests pass
//
// Our Go normal user: extracts params, provides fake fingerprint with plausible
// WebGL data, submits for verification. HMAC always matches (server's own sig).
//
// Usage: go run round13_final_mixed_v2.go [ddos|cc]

package main

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	TargetURL  = "http://127.0.0.1:8081"
	StatusFile = "./data/status.json"

	DDoSDuration = 35 * time.Second
	DDoSWorkers  = 400
	DDoSTotalIPs = 2000

	CCDuration  = 50 * time.Second
	CCWorkers   = 250
	CCUniqueIPs = 1000
	CCBurstSize = 12

	NormalCleanIPs      = 50
	NormalAttackPoolIPs = 50
	NormalRequestCycles = 4
	NormalStartDelay    = 5 * time.Second
)

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
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
		"Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Mobile Safari/537.36",
	}
	return uas[rng.Intn(len(uas))]
}

// Build a fake browser fingerprint that passes WAF checks.
// WAF checks: webgl_renderer must be non-empty, not "none"/"err".
// webdriver/phantom/selenium must not be "true".
func buildFakeFingerprint() string {
	entries := []string{
		"canvas:1280:ab12cd34",
		"webgl_renderer:ANGLE (Intel, Mesa DRI Intel(R) UHD Graphics)",
		"webgl_vendor:Intel",
		"webgl_version:WebGL 2.0 (OpenGL ES 3.0)",
		"webgl_shading:WebGL GLSL ES 3.00",
		"webgl_extensions:EXT_texture_filter_anisotropic,EXT_disjoint_timer_query",
		"screen:1920x1080x24",
		"pixelRatio:1",
		"timezone:-480",
		"platform:Win32",
		"language:en-US",
		"hwConcurrency:8",
		"deviceMemory:8",
		"maxTouchPoints:0",
		"vendor:Google Inc.",
		"productSub:20030107",
		"webdriver:false",
		"chrome:true",
		"phantom:false",
		"selenium:false",
		"domAutomation:false",
		"plugins:5",
		"languages:en-US,en",
	}
	return strings.Join(entries, ";")
}

type EnvFingerprint struct {
	SessionID string
	Token     string
	ESig      string
	OrigURL   string
}

func parseEnvFingerprint(html string) *EnvFingerprint {
	e := &EnvFingerprint{}
	// Variables are comma-separated: var _s="x",_u="/",_t="y",_esig="z";
	// So _t, _esig, _u don't have "var " prefix — match without it.
	if m := regexp.MustCompile(`_s="([^"]+)"`).FindStringSubmatch(html); len(m) > 1 { e.SessionID = m[1] }
	if m := regexp.MustCompile(`_t="([^"]+)"`).FindStringSubmatch(html); len(m) > 1 { e.Token = m[1] }
	if m := regexp.MustCompile(`_esig="([^"]+)"`).FindStringSubmatch(html); len(m) > 1 { e.ESig = m[1] }
	if m := regexp.MustCompile(`_u="([^"]+)"`).FindStringSubmatch(html); len(m) > 1 { e.OrigURL = m[1] }
	return e
}

type PoWChallenge struct {
	SessionID string
	Nonce     string
	Prefix    string
	Diff      int
	OrigURL   string
}

func parsePoWHTML(html string) *PoWChallenge {
	c := &PoWChallenge{}
	if m := regexp.MustCompile(`_s="([^"]+)"`).FindStringSubmatch(html); len(m) > 1 { c.SessionID = m[1] }
	if m := regexp.MustCompile(`_nonce="([^"]+)"`).FindStringSubmatch(html); len(m) > 1 { c.Nonce = m[1] }
	if m := regexp.MustCompile(`_prefix="([^"]+)"`).FindStringSubmatch(html); len(m) > 1 { c.Prefix = m[1] }
	if m := regexp.MustCompile(`_diff=(\d+)`).FindStringSubmatch(html); len(m) > 1 { fmt.Sscanf(m[1], "%d", &c.Diff) }
	if m := regexp.MustCompile(`_u="([^"]+)"`).FindStringSubmatch(html); len(m) > 1 { c.OrigURL = m[1] }
	if c.Diff == 0 { c.Diff = 4 }
	return c
}

func solvePoW(c *PoWChallenge) (string, string) {
	maxNonce := 1
	for i := 0; i < c.Diff; i++ { maxNonce *= 16 }
	for nonce := 0; nonce < maxNonce; nonce++ {
		input := c.Nonce + ":" + fmt.Sprintf("%d", nonce) + ":" + c.SessionID
		hash := sha256.Sum256([]byte(input))
		hashStr := hex.EncodeToString(hash[:])
		if strings.HasPrefix(hashStr, c.Prefix) {
			return fmt.Sprintf("%d", nonce), hashStr
		}
	}
	return "", ""
}

// ============================================================
// Challenge-aware HTTP client
// ============================================================
type ChallengeClient struct {
	client  *http.Client
	ip      string
	ua      string
	cookies []*http.Cookie
	passed  bool
}

func newChallengeClient(ip, ua string) *ChallengeClient {
	return &ChallengeClient{
		client: &http.Client{
			Timeout: 15 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		ip: ip,
		ua: ua,
	}
}

func (cc *ChallengeClient) addCookies(req *http.Request) {
	for _, c := range cc.cookies {
		req.AddCookie(c)
	}
}

func (cc *ChallengeClient) saveCookies(resp *http.Response) {
	for _, c := range resp.Cookies() {
		found := false
		for _, e := range cc.cookies {
			if e.Name == c.Name { found = true; break }
		}
		if !found { cc.cookies = append(cc.cookies, c) }
	}
}

func (cc *ChallengeClient) doRequest(path string) (int, []byte) {
	req, _ := http.NewRequest("GET", TargetURL+path, nil)
	req.Header.Set("User-Agent", cc.ua)
	req.Header.Set("X-Forwarded-For", cc.ip)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	cc.addCookies(req)

	resp, err := cc.client.Do(req)
	if err != nil { return 0, nil }
	defer resp.Body.Close()

	cc.saveCookies(resp)
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, body
}

// solveChallenge fakes the EnvFingerprint challenge via HMAC-replay.
func (cc *ChallengeClient) solveChallenge() bool {
	if cc.passed { return true }

	// Step 1: Initial request to trigger challenge
	status, body := cc.doRequest("/")
	if status == 200 { cc.passed = true; return true }
	if status != 429 { return false }

	// Step 2: Parse EnvFingerprint params
	fp := parseEnvFingerprint(string(body))
	if fp.SessionID == "" || fp.Token == "" || fp.ESig == "" {
		return false
	}

	// Step 3: Submit fake fingerprint with HMAC-replay
	fakeFP := buildFakeFingerprint()
	b64FP := base64.StdEncoding.EncodeToString([]byte(fakeFP))
	sep := "&"
	if !strings.Contains(fp.OrigURL, "?") { sep = "?" }
	verifyPath := fmt.Sprintf("%s%s__shield_verify=%s&__shield_token=%s&__shield_sid=%s&__shield_fp=%s",
		fp.OrigURL, sep,
		url.QueryEscape(fp.ESig),
		url.QueryEscape(fp.Token),
		url.QueryEscape(fp.SessionID),
		url.QueryEscape(b64FP))

	status2, _ := cc.doRequest(verifyPath)
	if status2 == 200 {
		cc.passed = true
		return true
	}

	// Step 4: EnvFingerprint may have been rejected. Try escalation to PoW.
	status3, body3 := cc.doRequest("/")
	if status3 == 200 { cc.passed = true; return true }
	if status3 != 429 { return false }

	pc := parsePoWHTML(string(body3))
	if pc.Nonce != "" && pc.Prefix != "" {
		answerNonce, answerHash := solvePoW(pc)
		if answerNonce != "" {
			sep := "&"
			if !strings.Contains(pc.OrigURL, "?") { sep = "?" }
			powPath := fmt.Sprintf("%s%s__shield_answer=%s&__shield_sid=%s&__shield_token=%s&__shield_hash=%s",
				pc.OrigURL, sep,
				url.QueryEscape(answerNonce),
				url.QueryEscape(pc.SessionID),
				url.QueryEscape(pc.Nonce),
				url.QueryEscape(answerHash))
			status4, _ := cc.doRequest(powPath)
			if status4 == 200 { cc.passed = true; return true }
		}
	}

	return false
}

// ============================================================
// Normal User
// ============================================================
type NormalStats struct {
	sent      int64
	blocked   int64
	challenge int64
	passed    int64
	errors    int64
}

type AttackStats struct {
	sent       int64
	blocked    int64
	challenged int64
	passed     int64
	errors     int64
}

func runNormalUserV2(ip string, stats *NormalStats, stopCh chan struct{}, wg *sync.WaitGroup) {
	defer wg.Done()

	rng := rand.New(rand.NewSource(time.Now().UnixNano() + int64(len(ip))))
	ua := randomUA(rng)
	cc := newChallengeClient(ip, ua)

	solved := cc.solveChallenge()
	if !solved { atomic.AddInt64(&stats.errors, 1); return }
	atomic.AddInt64(&stats.challenge, 1)

	for cycle := 0; cycle < NormalRequestCycles; cycle++ {
		select { case <-stopCh: return; default: }
		for _, path := range []string{"/", "/about", "/products?page=1", "/contact"} {
			select { case <-stopCh: return; default: }
			status, _ := cc.doRequest(path)
			atomic.AddInt64(&stats.sent, 1)
			switch {
			case status == 403: atomic.AddInt64(&stats.blocked, 1)
			case status == 429: atomic.AddInt64(&stats.challenge, 1)
			case status == 200: atomic.AddInt64(&stats.passed, 1)
			default: atomic.AddInt64(&stats.errors, 1)
			}
			select { case <-stopCh: return; case <-time.After(1200 * time.Millisecond): }
		}
	}
}

// ============================================================
// Attack
// ============================================================
func doAttackRequest(client *http.Client, path string, ip string, ua string) (int, error) {
	req, _ := http.NewRequest("GET", TargetURL+path, nil)
	req.Header.Set("User-Agent", ua)
	req.Header.Set("X-Forwarded-For", ip)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	resp, err := client.Do(req)
	if err != nil { return 0, err }
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode, nil
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
			TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
			MaxIdleConns: 200, MaxIdleConnsPerHost: 100,
			IdleConnTimeout: 90 * time.Second, ResponseHeaderTimeout: 10 * time.Second,
		},
		Timeout: 15 * time.Second,
	}
}

func runDDoS(ips []string, stats *AttackStats, stopCh chan struct{}, wg *sync.WaitGroup) {
	client := makeClient()
	for w := 0; w < DDoSWorkers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			lrng := rand.New(rand.NewSource(time.Now().UnixNano() + int64(workerID)))
			for {
				select { case <-stopCh: return; default: }
				ip := ips[lrng.Intn(len(ips))]
				path := fmt.Sprintf("/api/v1/%s", []string{"users","products","search","status","data"}[lrng.Intn(5)])
				status, err := doAttackRequest(client, path, ip, randomUA(lrng))
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
}

func runCC(ips []string, stats *AttackStats, stopCh chan struct{}, wg *sync.WaitGroup) {
	client := makeClient()
	ccPaths := []string{"/", "/login", "/api/v1/search?q=popular", "/index.html", "/api/v1/products"}
	for w := 0; w < CCWorkers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			lrng := rand.New(rand.NewSource(time.Now().UnixNano() + int64(workerID)))
			for {
				select { case <-stopCh: return; default: }
				ip := ips[lrng.Intn(len(ips))]
				path := ccPaths[lrng.Intn(len(ccPaths))]
				ua := randomUA(lrng)
				for i := 0; i < CCBurstSize; i++ {
					select { case <-stopCh: return; default: }
					status, err := doAttackRequest(client, path, ip, ua)
					atomic.AddInt64(&stats.sent, 1)
					if err != nil { atomic.AddInt64(&stats.errors, 1); continue }
					switch {
					case status == 403: atomic.AddInt64(&stats.blocked, 1)
					case status == 429: atomic.AddInt64(&stats.challenged, 1)
					case status == 200: atomic.AddInt64(&stats.passed, 1)
					default: atomic.AddInt64(&stats.errors, 1)
					}
				}
				time.Sleep(time.Duration(50+lrng.Intn(100)) * time.Millisecond)
			}
		}(w)
	}
}

// ============================================================
// Main
// ============================================================
func runTest(attackType string, attackIps []string, duration time.Duration,
	runAttack func([]string, *AttackStats, chan struct{}, *sync.WaitGroup)) {

	fmt.Println(strings.Repeat("=", 70))
	fmt.Printf("  V2 MIXED TEST: %s + Challenge-Solving Users\n", attackType)
	fmt.Printf("  Clean: %d | Attack-Pool: %d | Cycles: %d\n",
		NormalCleanIPs, NormalAttackPoolIPs, NormalRequestCycles)
	fmt.Println(strings.Repeat("=", 70))
	fmt.Printf("\nBefore Attack:\n%s\n\n", getMetrics())

	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	attackIPSet := make(map[string]bool)
	for _, ip := range attackIps { attackIPSet[ip] = true }

	cleanIps := make([]string, NormalCleanIPs)
	for i := 0; i < NormalCleanIPs; i++ {
		for {
			ip := randomIP(rng)
			if !attackIPSet[ip] { cleanIps[i] = ip; attackIPSet[ip] = true; break }
		}
	}

	attackPoolNormIps := make([]string, NormalAttackPoolIPs)
	perm := rng.Perm(len(attackIps))
	for i := 0; i < NormalAttackPoolIPs && i < len(perm); i++ {
		attackPoolNormIps[i] = attackIps[perm[i]]
	}

	attackStats := &AttackStats{}
	cleanStats := &NormalStats{}
	apStats := &NormalStats{}

	var attackWg, normalWg sync.WaitGroup
	stopCh := make(chan struct{})

	fmt.Printf("[Phase 1] Starting %s attack...\n", attackType)
	runAttack(attackIps, attackStats, stopCh, &attackWg)

	fmt.Printf("[Phase 2] Waiting %v for ramp-up...\n", NormalStartDelay)
	time.Sleep(NormalStartDelay)

	fmt.Printf("[Phase 3] %d clean-IP users (with challenge solving)...\n", NormalCleanIPs)
	for i := 0; i < NormalCleanIPs; i++ {
		normalWg.Add(1)
		go runNormalUserV2(cleanIps[i], cleanStats, stopCh, &normalWg)
	}

	fmt.Printf("[Phase 4] %d attack-pool-IP users (with challenge solving)...\n", NormalAttackPoolIPs)
	for i := 0; i < NormalAttackPoolIPs; i++ {
		normalWg.Add(1)
		go runNormalUserV2(attackPoolNormIps[i], apStats, stopCh, &normalWg)
	}

	remaining := duration - NormalStartDelay
	ticker := time.NewTicker(15 * time.Second)
	startTime := time.Now()
	go func() {
		for range ticker.C {
			e := time.Since(startTime)
			fmt.Printf("  [%ds] Atk(s/b/c/p)=%d/%d/%d/%d | Cln(s/b/p)=%d/%d/%d | AtkIP(s/b/p)=%d/%d/%d\n",
				int(e.Seconds()),
				atomic.LoadInt64(&attackStats.sent), atomic.LoadInt64(&attackStats.blocked),
				atomic.LoadInt64(&attackStats.challenged), atomic.LoadInt64(&attackStats.passed),
				atomic.LoadInt64(&cleanStats.sent), atomic.LoadInt64(&cleanStats.blocked),
				atomic.LoadInt64(&cleanStats.passed),
				atomic.LoadInt64(&apStats.sent), atomic.LoadInt64(&apStats.blocked),
				atomic.LoadInt64(&apStats.passed))
		}
	}()

	time.Sleep(remaining)
	fmt.Println("\n[Stopping] Closing workers...")
	close(stopCh)
	ticker.Stop()
	normalWg.Wait()
	attackWg.Wait()

	fmt.Printf("\n%s\n%s  %s RESULTS\n%s\n", strings.Repeat("=",70), strings.Repeat("=",23), attackType, strings.Repeat("=",70))

	at := atomic.LoadInt64(&attackStats.sent)
	fmt.Printf("  Attack: sent=%d blocked(403)=%d challenged(429)=%d passed(200)=%d err=%d\n",
		at, atomic.LoadInt64(&attackStats.blocked), atomic.LoadInt64(&attackStats.challenged),
		atomic.LoadInt64(&attackStats.passed), atomic.LoadInt64(&attackStats.errors))

	cs := atomic.LoadInt64(&cleanStats.sent)
	cp := atomic.LoadInt64(&cleanStats.passed)
	cb := atomic.LoadInt64(&cleanStats.blocked)
	cc := atomic.LoadInt64(&cleanStats.challenge)
	fmt.Printf("\n  CLEAN-IP NORMAL (PoW/FP-solving): sent=%d passed(200)=%d blocked(403)=%d challenged(429)=%d err=%d\n",
		cs, cp, cb, cc, atomic.LoadInt64(&cleanStats.errors))
	if cs > 0 {
		fmt.Printf("    FALSE POSITIVE RATE: %.1f%% (%d/%d blocked of post-challenge requests)\n",
			float64(cb)/float64(cs)*100, cb, cs)
	} else {
		fmt.Printf("    ❌ NONE of the clean-IP users could pass the challenge\n")
	}

	as := atomic.LoadInt64(&apStats.sent)
	ap := atomic.LoadInt64(&apStats.passed)
	ab := atomic.LoadInt64(&apStats.blocked)
	ach := atomic.LoadInt64(&apStats.challenge)
	fmt.Printf("\n  ATTACK-POOL-IP NORMAL (PoW/FP-solving): sent=%d passed(200)=%d blocked(403)=%d challenged(429)=%d err=%d\n",
		as, ap, ab, ach, atomic.LoadInt64(&apStats.errors))
	if as > 0 {
		fmt.Printf("    COLLATERAL RATE: %.1f%% (%d/%d blocked)\n",
			float64(ab)/float64(as)*100, ab, as)
	} else {
		fmt.Printf("    ❌ NONE of the attack-pool-IP users could pass the challenge\n")
	}

	fmt.Printf("\nAfter Attack:\n%s\n", getMetrics())

	// Verdict
	fmt.Printf("\n%s\n", strings.Repeat("=", 70))
	fmt.Printf("  VERDICT\n%s\n", strings.Repeat("=", 70))
	if cp > 0 {
		fmt.Printf("  ✅ Clean-IP users CAN pass challenge: %d/%d requests passed\n", cp, cs+cp+cb+cc)
	} else {
		fmt.Printf("  ❌ Clean-IP users CANNOT pass challenge — ALL blocked\n")
	}
	if ap > 0 {
		fmt.Printf("  ✅ Attack-IP users CAN pass challenge: %d/%d requests passed\n", ap, as+ap+ab+ach)
	} else {
		fmt.Printf("  ❌ Attack-IP users CANNOT pass challenge — ALL blocked\n")
	}
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run round13_final_mixed_v2.go [ddos|cc]")
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
		fmt.Printf("Unknown: %s (use ddos or cc)\n", mode)
		os.Exit(1)
	}
	fmt.Println("\nDone.")
}
