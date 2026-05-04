package ddoscc

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/shield/shield/pkg/logger"
)

func newTestDetector(cfg Config) *Detector {
	log, _ := logger.New("warn", "json", "stderr")
	return NewDetector(cfg, log)
}

// --- hasValidCookie tests ---

func TestHasValidCookie_NoCookie(t *testing.T) {
	d := newTestDetector(DefaultConfig())
	req := httptest.NewRequest("GET", "/", nil)
	ok := d.hasValidCookie(req)
	if ok {
		t.Fatal("expected false for missing cookie")
	}
}

func TestHasValidCookie_InvalidSignature(t *testing.T) {
	d := newTestDetector(DefaultConfig())
	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: "__shield_cc", Value: "fake.invalidsig"})
	ok := d.hasValidCookie(req)
	if ok {
		t.Fatal("expected false for invalid cookie")
	}
}

func TestHasValidCookie_ValidCookieAlwaysTrue(t *testing.T) {
	d := newTestDetector(DefaultConfig())
	// Generate a valid cookie from the same IP — should always return true
	// regardless of session state (crypto proof is sufficient for recognition)
	cookieVal := d.challenges.GenerateChallengeCookie("10.0.0.1")
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	req.AddCookie(&http.Cookie{Name: "__shield_cc", Value: cookieVal})
	ok := d.hasValidCookie(req)
	if !ok {
		t.Fatal("expected true for cryptographically valid cookie")
	}
}

func TestHasValidCookie_DifferentIPTampering(t *testing.T) {
	d := newTestDetector(DefaultConfig())
	// Generate cookie for IP 10.0.0.1, use from 10.0.0.2
	cookieVal := d.challenges.GenerateChallengeCookie("10.0.0.1")
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.2:12345" // Different IP
	req.AddCookie(&http.Cookie{Name: "__shield_cc", Value: cookieVal})
	ok := d.hasValidCookie(req)
	if ok {
		t.Fatal("expected false when cookie is used from a different IP")
	}
}

// --- checkTokenBucket graduated response tests ---

func TestCheckTokenBucket_Allow(t *testing.T) {
	cfg := DefaultConfig()
	cfg.RequestsPerSecond = 1000 // high limit → always allow
	cfg.BurstSize = 1000
	d := newTestDetector(cfg)
	viol := d.checkTokenBucket("10.0.0.1")
	if viol != 0 {
		t.Fatalf("expected 0 violations, got %d", viol)
	}
}

func TestCheckTokenBucket_GraduatedViolations(t *testing.T) {
	cfg := DefaultConfig()
	cfg.RequestsPerSecond = 1
	cfg.BurstSize = 1
	d := newTestDetector(cfg)

	// First request allowed (fills bucket)
	v := d.checkTokenBucket("10.0.0.1")
	if v != 0 {
		t.Fatalf("expected 0 on first allow, got %d", v)
	}

	// Burst through the bucket to trigger violations
	for i := 1; i <= 5; i++ {
		v := d.checkTokenBucket("10.0.0.1")
		if v != i {
			t.Fatalf("violation %d: expected count %d, got %d", i, i, v)
		}
	}
}

func TestCheckTokenBucket_PerIPIsolation(t *testing.T) {
	cfg := DefaultConfig()
	cfg.RequestsPerSecond = 1
	cfg.BurstSize = 1
	d := newTestDetector(cfg)

	// First request for both IPs
	d.checkTokenBucket("10.0.0.1")
	d.checkTokenBucket("10.0.0.2")

	// Burst IP1 only
	d.checkTokenBucket("10.0.0.1") // violation 1
	d.checkTokenBucket("10.0.0.1") // violation 2

	// IP2 should start at violation 1
	v2 := d.checkTokenBucket("10.0.0.2")
	if v2 != 1 {
		t.Fatalf("IP2 should have violation count 1, got %d", v2)
	}

	// IP1 should be at violation 3 (independently tracked)
	d.checkTokenBucket("10.0.0.1") // violation 3
	d.rateViolationsMu.Lock()
	rv := d.rateViolations["10.0.0.1"]
	d.rateViolationsMu.Unlock()
	if rv == nil || rv.count != 3 {
		t.Fatalf("IP1 should have count 3, got %v", rv)
	}
}

// --- Check() graduated response for token bucket ---

func TestCheck_GraduatedTokenBucketResponse(t *testing.T) {
	cfg := DefaultConfig()
	cfg.RequestsPerSecond = 1
	cfg.BurstSize = 1
	cfg.JSChallengeEnabled = true
	cfg.EnvFingerprintEnabled = false // force JSChallenge path for first violation
	cfg.PoWChallengeEnabled = true
	// Disable other detection layers to isolate token bucket behavior
	cfg.GlobalRateDangerThreshold = 10000
	cfg.GlobalRateDistributedThreshold = 10000
	cfg.MaxConnectionsPerIP = 10000
	cfg.MaxRequests = 200000
	cfg.BurstRequests = 300000
	cfg.SuspicionBlockThreshold = 10000
	cfg.SuspicionChallengeThreshold = 10000
	d := newTestDetector(cfg)

	// Use browser-like headers to get behaviorScore >= 50 so Layer 7 doesn't interfere
	makeReq := func() *http.Request {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "10.0.0.1:12345"
		req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36")
		req.Header.Set("Accept", "text/html,application/xhtml+xml")
		req.Header.Set("Accept-Language", "en-US,en;q=0.9")
		req.Header.Set("Accept-Encoding", "gzip, deflate, br")
		req.Header.Set("Referer", "https://example.com/")
		req.Header.Set("Connection", "keep-alive")
		req.Header.Set("Cache-Control", "max-age=0")
		req.AddCookie(&http.Cookie{Name: "sessionid", Value: "abc123"})
		return req
	}

	// Allow first request (fills token bucket, behaviorScore > 50 → no Layer 7 trigger)
	action := d.Check(makeReq())
	if action != ActionAllow {
		t.Fatalf("expected ActionAllow on first request, got %s", action)
	}

	// 1st token bucket violation → JSChallenge (since EnvFingerprint disabled)
	action = d.Check(makeReq())
	if action != ActionJSChallenge {
		t.Fatalf("expected ActionJSChallenge on 1st violation, got %s", action)
	}

	// 2nd violation → PoWChallenge
	action = d.Check(makeReq())
	if action != ActionPoWChallenge {
		t.Fatalf("expected ActionPoWChallenge on 2nd violation, got %s", action)
	}

	// 3rd violation → ActionBlock
	action = d.Check(makeReq())
	if action != ActionBlock {
		t.Fatalf("expected ActionBlock on 3rd violation, got %s", action)
	}
}

func TestCheck_CookieElevatedRateLimit(t *testing.T) {
	cfg := DefaultConfig()
	cfg.RequestsPerSecond = 1
	cfg.BurstSize = 1
	cfg.EnvFingerprintEnabled = true
	d := newTestDetector(cfg)

	cookieVal := d.challenges.GenerateChallengeCookie("10.0.0.1")
	parts := splitCookie(cookieVal)
	sessionID := parts[0]
	state := d.challenges.GetSession(sessionID)
	state.PassedLevels = []ChallengeLevel{ChallengeJS}
	state.Level = ChallengeNone

	makeReq := func() *http.Request {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "10.0.0.1:12345"
		req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36")
		req.Header.Set("Accept", "text/html")
		req.Header.Set("Accept-Language", "en-US,en;q=0.9")
		req.Header.Set("Accept-Encoding", "gzip, deflate")
		req.Header.Set("Connection", "keep-alive")
		req.AddCookie(&http.Cookie{Name: "__shield_cc", Value: cookieVal})
		return req
	}

	// Cookie users get elevated rate limit (4x burst=4, rps=4).
	// First few requests should be allowed.
	allowedCount := 0
	for i := 0; i < 10; i++ {
		action := d.Check(makeReq())
		if action == ActionAllow {
			allowedCount++
		}
	}
	// At least some requests should be allowed (elevated rate limit).
	if allowedCount == 0 {
		t.Fatal("expected at least some requests to be allowed for cookie users")
	}
	// Not all should be allowed (rate limit still applies).
	if allowedCount == 10 {
		t.Fatal("cookie users should not get total bypass — rate limit still applies")
	}
}

func TestCheck_CookieCleanedUpState(t *testing.T) {
	cfg := DefaultConfig()
	cfg.RequestsPerSecond = 1
	cfg.BurstSize = 1
	cfg.EnvFingerprintEnabled = true
	d := newTestDetector(cfg)

	cookieVal := d.challenges.GenerateChallengeCookie("10.0.0.1")

	makeReq := func() *http.Request {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "10.0.0.1:12345"
		req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36")
		req.Header.Set("Accept", "text/html")
		req.Header.Set("Accept-Language", "en-US,en;q=0.9")
		req.Header.Set("Accept-Encoding", "gzip, deflate")
		req.Header.Set("Connection", "keep-alive")
		req.AddCookie(&http.Cookie{Name: "__shield_cc", Value: cookieVal})
		return req
	}

	// No session state — crypto-valid cookie still gets elevated rate limits.
	allowedCount := 0
	for i := 0; i < 10; i++ {
		action := d.Check(makeReq())
		if action == ActionAllow {
			allowedCount++
		}
	}
	if allowedCount == 0 {
		t.Fatal("expected at least some requests allowed for valid cookie with no session state")
	}
	if allowedCount == 10 {
		t.Fatal("cookie without session state should not get total bypass")
	}
}

func TestCheck_Disabled(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = false
	cfg.RequestsPerSecond = 1
	cfg.BurstSize = 1
	d := newTestDetector(cfg)

	for i := 0; i < 100; i++ {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "10.0.0.1:12345"
		action := d.Check(req)
		if action != ActionAllow {
			t.Fatalf("request %d: expected ActionAllow when disabled, got %s", i, action)
		}
	}
}

// --- Rate violation cleanup test ---

func TestRateViolationCleanup(t *testing.T) {
	cfg := DefaultConfig()
	cfg.RequestsPerSecond = 1
	cfg.BurstSize = 1
	cfg.WindowSec = 1
	d := newTestDetector(cfg)

	// Trigger violations on IP1
	d.checkTokenBucket("10.0.0.1")
	d.checkTokenBucket("10.0.0.1") // violation 1
	d.checkTokenBucket("10.0.0.1") // violation 2

	// Manually age out IP1's violation record
	d.rateViolationsMu.Lock()
	if rv, ok := d.rateViolations["10.0.0.1"]; ok {
		rv.lastSeen = time.Now().Add(-time.Hour)
	}
	d.rateViolationsMu.Unlock()

	// Trigger cleanup
	cutoff := time.Now().Add(-time.Duration(cfg.WindowSec*4) * time.Second)
	d.rateViolationsMu.Lock()
	for ip, rv := range d.rateViolations {
		if rv.lastSeen.Before(cutoff) {
			delete(d.rateViolations, ip)
		}
	}
	d.rateViolationsMu.Unlock()

	// Verify IP1 cleaned up
	d.rateViolationsMu.Lock()
	_, exists := d.rateViolations["10.0.0.1"]
	d.rateViolationsMu.Unlock()
	if exists {
		t.Fatal("expected rate violation to be cleaned up after aging out")
	}

	// Fresh request from same IP → should start clean
	v := d.checkTokenBucket("10.0.0.1")
	if v != 1 {
		t.Fatalf("expected violation count reset to 1 after cleanup, got %d", v)
	}
}

// --- ServeChallenge cookie setting ---

func TestServeChallenge_SetsCookie(t *testing.T) {
	cfg := DefaultConfig()
	cfg.JSChallengeEnabled = true
	d := newTestDetector(cfg)

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "10.0.0.1:12345"

	d.ServeChallenge(w, req, ActionJSChallenge, "/test")

	resp := w.Result()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", resp.StatusCode)
	}

	cookies := resp.Cookies()
	var found bool
	for _, c := range cookies {
		if c.Name == "__shield_cc" {
			found = true
			if c.HttpOnly != true {
				t.Error("expected HttpOnly cookie")
			}
			if c.MaxAge != 86400 {
				t.Errorf("expected MaxAge 86400, got %d", c.MaxAge)
			}
			break
		}
	}
	if !found {
		t.Fatal("expected __shield_cc cookie to be set")
	}
}

// --- VerifyChallenge tests ---

func TestVerifyChallenge_NoCookie(t *testing.T) {
	d := newTestDetector(DefaultConfig())
	req := httptest.NewRequest("GET", "/?__shield_verify=test", nil)
	action := d.VerifyChallenge(req)
	if action != ActionBlock {
		t.Fatalf("expected ActionBlock when no cookie, got %s", action)
	}
}

func TestVerifyChallenge_JSChallengeRoundTrip(t *testing.T) {
	d := newTestDetector(DefaultConfig())
	cookieVal := d.challenges.GenerateChallengeCookie("10.0.0.1")
	parts := splitCookie(cookieVal)
	sessionID := parts[0]

	// Simulate JS challenge: generate a token, compute expected answer
	testToken := "deadbeefcafebabedeadbeefcafebabe"
	expectedAnswer := computeJSTestAnswer(d.challenges.secretKey, testToken, sessionID)

	// Verify correct answer passes
	if !d.challenges.VerifyJSChallengeAnswer(sessionID, testToken, expectedAnswer) {
		t.Fatal("expected VerifyJSChallengeAnswer to return true for correct answer")
	}

	// Verify wrong answer fails
	if d.challenges.VerifyJSChallengeAnswer(sessionID, testToken, "wronganswer") {
		t.Fatal("expected VerifyJSChallengeAnswer to return false for wrong answer")
	}
}

func TestHasChallengeParams(t *testing.T) {
	d := newTestDetector(DefaultConfig())
	req := httptest.NewRequest("GET", "/?__shield_verify=abc", nil)
	if !d.HasChallengeParams(req) {
		t.Fatal("expected true for __shield_verify param")
	}
	req2 := httptest.NewRequest("GET", "/?__shield_answer=42", nil)
	if !d.HasChallengeParams(req2) {
		t.Fatal("expected true for __shield_answer param")
	}
	req3 := httptest.NewRequest("GET", "/?foo=bar", nil)
	if d.HasChallengeParams(req3) {
		t.Fatal("expected false for no challenge params")
	}
}

// --- Helpers ---

func splitCookie(cookie string) []string {
	for i := 0; i < len(cookie); i++ {
		if cookie[i] == '.' {
			return []string{cookie[:i], cookie[i+1:]}
		}
	}
	return []string{cookie}
}

func computeJSTestAnswer(secretKey []byte, token, sessionID string) string {
	mac := hmac.New(sha256.New, secretKey)
	mac.Write([]byte(token + "|" + sessionID))
	return hex.EncodeToString(mac.Sum(nil))[:16]
}
