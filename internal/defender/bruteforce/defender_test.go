package bruteforce

import (
	"testing"
	"time"

	"github.com/shield/shield/pkg/logger"
	"github.com/shield/shield/pkg/metrics"
)

func TestNewDefender_Disabled(t *testing.T) {
	log, _ := logger.New("warn", "json", "stderr")
	b := NewDefender(false, 5, 60, 300, []string{"/api"}, []int{401}, log)
	if b == nil {
		t.Fatal("expected non-nil defender")
	}
	if b.ShouldBlock("1.2.3.4", "/api/login") {
		t.Error("disabled defender should not block")
	}
}

func TestBruteForceDefender_RecordAndBlock(t *testing.T) {
	log, _ := logger.New("warn", "json", "stderr")
	b := NewDefender(true, 3, 60, 300, []string{"/api"}, []int{401}, log)
	ip := "1.2.3.4"
	path := "/api/login"

	b.RecordFailure(ip, path, 401)
	b.RecordFailure(ip, path, 401)
	if b.ShouldBlock(ip, path) {
		t.Error("should not block before max failures")
	}

	b.RecordFailure(ip, path, 401)
	if !b.ShouldBlock(ip, path) {
		t.Error("should block after max failures")
	}
}

func TestBruteForceDefender_RecordRequest_BlocksOnFrequency(t *testing.T) {
	log, _ := logger.New("warn", "json", "stderr")
	b := NewDefender(true, 3, 60, 300, []string{"/login"}, nil, log)
	ip := "1.2.3.4"
	path := "/login"
	body := []byte("user=admin&pass=test")

	b.RecordRequest(ip, path, "POST", body)
	b.RecordRequest(ip, path, "POST", body)
	if b.ShouldBlock(ip, path) {
		t.Error("should not block before max requests")
	}

	b.RecordRequest(ip, path, "POST", body)
	if !b.ShouldBlock(ip, path) {
		t.Error("should block after max POST requests")
	}
}

func TestBruteForceDefender_RecordRequest_IgnoresStatusCodes(t *testing.T) {
	log, _ := logger.New("warn", "json", "stderr")
	b := NewDefender(true, 3, 60, 300, []string{"/login"}, []int{401}, log)
	ip := "1.2.3.4"
	path := "/login"
	body := []byte("user=admin&pass=test")

	b.RecordRequest(ip, path, "POST", body)
	b.RecordRequest(ip, path, "POST", body)
	b.RecordRequest(ip, path, "POST", body)
	if !b.ShouldBlock(ip, path) {
		t.Error("request-side detection should block regardless of status codes")
	}
}

func TestBruteForceDefender_RecordRequest_OnlyPOST(t *testing.T) {
	log, _ := logger.New("warn", "json", "stderr")
	b := NewDefender(true, 2, 60, 300, []string{"/login"}, nil, log)
	ip := "1.2.3.4"
	path := "/login"

	for i := 0; i < 10; i++ {
		b.RecordRequest(ip, path, "GET", nil)
	}
	if b.ShouldBlock(ip, path) {
		t.Error("GET requests should not trigger brute force block")
	}

	b.RecordRequest(ip, path, "POST", []byte("pass=1"))
	b.RecordRequest(ip, path, "POST", []byte("pass=2"))
	if !b.ShouldBlock(ip, path) {
		t.Error("POST requests should trigger brute force block")
	}
}

func TestBruteForceDefender_BodyVariation(t *testing.T) {
	log, _ := logger.New("warn", "json", "stderr")
	b := NewDefender(true, 5, 60, 300, []string{"/login"}, nil, log)
	ip := "1.2.3.4"
	path := "/login"

	bodies := [][]byte{
		[]byte("user=admin&pass=123456"),
		[]byte("user=admin&pass=password"),
		[]byte("user=admin&pass=admin123"),
		[]byte("user=admin&pass=qwerty"),
		[]byte("user=admin&pass=letmein"),
	}
	for _, body := range bodies {
		b.RecordRequest(ip, path, "POST", body)
	}
	if !b.ShouldBlock(ip, path) {
		t.Error("dictionary attack should be blocked")
	}
}

func TestBruteForceDefender_UnprotectedPath(t *testing.T) {
	log, _ := logger.New("warn", "json", "stderr")
	b := NewDefender(true, 3, 60, 300, []string{"/api"}, []int{401}, log)
	ip := "1.2.3.4"

	b.RecordFailure(ip, "/health", 401)
	b.RecordFailure(ip, "/health", 401)
	b.RecordFailure(ip, "/health", 401)
	if b.ShouldBlock(ip, "/health") {
		t.Error("should not block unprotected path")
	}
}

func TestBruteForceDefender_DefaultStatusCodes(t *testing.T) {
	log, _ := logger.New("warn", "json", "stderr")
	b := NewDefender(true, 2, 60, 300, []string{"/login"}, nil, log)
	ip := "1.2.3.4"
	path := "/login"

	b.RecordFailure(ip, path, 500)
	b.RecordFailure(ip, path, 500)
	if !b.ShouldBlock(ip, path) {
		t.Error("should block with default status code 500 (in 4xx/5xx range)")
	}
}

func TestBruteForceDefender_StatusCodeOutsideRange(t *testing.T) {
	log, _ := logger.New("warn", "json", "stderr")
	b := NewDefender(true, 2, 60, 300, []string{"/login"}, nil, log)
	ip := "1.2.3.4"
	path := "/login"

	b.RecordFailure(ip, path, 200)
	b.RecordFailure(ip, path, 200)
	if b.ShouldBlock(ip, path) {
		t.Error("should not block with status code 200 (outside 4xx/5xx)")
	}
}

func TestBruteForceDefender_Reset(t *testing.T) {
	log, _ := logger.New("warn", "json", "stderr")
	b := NewDefender(true, 2, 60, 300, []string{"/api"}, []int{401}, log)
	ip := "1.2.3.4"
	path := "/api/login"

	b.RecordFailure(ip, path, 401)
	b.RecordFailure(ip, path, 401)
	if !b.ShouldBlock(ip, path) {
		t.Fatal("should block before reset")
	}

	b.Reset(ip, path)
	if b.ShouldBlock(ip, path) {
		t.Error("should not block after reset")
	}
}

func TestBruteForceDefender_ResetClearsRequests(t *testing.T) {
	log, _ := logger.New("warn", "json", "stderr")
	b := NewDefender(true, 2, 60, 300, []string{"/login"}, nil, log)
	ip := "1.2.3.4"
	path := "/login"

	b.RecordRequest(ip, path, "POST", []byte("test"))
	b.RecordRequest(ip, path, "POST", []byte("test"))
	if !b.ShouldBlock(ip, path) {
		t.Fatal("should block before reset")
	}

	b.Reset(ip, path)
	if b.ShouldBlock(ip, path) {
		t.Error("should not block after reset")
	}
}

func TestBruteForceDefender_WindowExpiry(t *testing.T) {
	log, _ := logger.New("warn", "json", "stderr")
	b := NewDefender(true, 2, 1, 300, []string{"/api"}, []int{401}, log)
	ip := "1.2.3.4"
	path := "/api/login"

	b.RecordFailure(ip, path, 401)
	b.RecordFailure(ip, path, 401)
	if !b.ShouldBlock(ip, path) {
		t.Fatal("should block immediately")
	}

	time.Sleep(1200 * time.Millisecond)
	b.RecordFailure(ip, path, 401)
	if b.ShouldBlock(ip, path) {
		t.Error("should not block after window expiry with only 1 failure")
	}
}

func TestBruteForceDefender_BlockDurationExpiry(t *testing.T) {
	log, _ := logger.New("warn", "json", "stderr")
	b := NewDefender(true, 2, 60, 1, []string{"/api"}, []int{401}, log)
	ip := "1.2.3.4"
	path := "/api/login"

	b.RecordFailure(ip, path, 401)
	b.RecordFailure(ip, path, 401)
	if !b.ShouldBlock(ip, path) {
		t.Fatal("should block")
	}

	time.Sleep(1200 * time.Millisecond)
	if b.ShouldBlock(ip, path) {
		t.Error("should not block after block duration expiry")
	}
}

func TestBruteForceDefender_Metrics(t *testing.T) {
	metrics.Get().BruteForceBlocks = 0

	log, _ := logger.New("warn", "json", "stderr")
	b := NewDefender(true, 2, 60, 300, []string{"/api"}, []int{401}, log)

	b.RecordFailure("1.2.3.4", "/api/login", 401)
	b.RecordFailure("1.2.3.4", "/api/login", 401)

	if metrics.Get().Snapshot().BruteForceBlocks == 0 {
		t.Error("BruteForceBlocks metric should be incremented")
	}
}

func TestBruteForceDefender_MetricsFromRecordRequest(t *testing.T) {
	metrics.Get().BruteForceBlocks = 0

	log, _ := logger.New("warn", "json", "stderr")
	b := NewDefender(true, 2, 60, 300, []string{"/login"}, nil, log)

	b.RecordRequest("1.2.3.4", "/login", "POST", []byte("test"))
	b.RecordRequest("1.2.3.4", "/login", "POST", []byte("test"))

	if metrics.Get().Snapshot().BruteForceBlocks == 0 {
		t.Error("BruteForceBlocks metric should be incremented from RecordRequest")
	}
}

func TestBruteForceDefender_DisabledRecord(t *testing.T) {
	log, _ := logger.New("warn", "json", "stderr")
	b := NewDefender(false, 2, 60, 300, []string{"/api"}, []int{401}, log)
	b.RecordFailure("1.2.3.4", "/api/login", 401)
	b.RecordRequest("1.2.3.4", "/api/login", "POST", []byte("test"))
	b.Reset("1.2.3.4", "/api/login")
}

func TestBruteForceDefender_isProtected(t *testing.T) {
	log, _ := logger.New("warn", "json", "stderr")
	b := NewDefender(true, 2, 60, 300, []string{"/api", "/admin"}, []int{401}, log)

	if !b.isProtected("/api/login") {
		t.Error("should protect /api/login")
	}
	if !b.isProtected("/admin") {
		t.Error("should protect /admin")
	}
	if b.isProtected("/public") {
		t.Error("should not protect /public")
	}
}

func TestBruteForceDefender_DefaultProtectedPaths(t *testing.T) {
	log, _ := logger.New("warn", "json", "stderr")
	b := NewDefender(true, 2, 60, 300, nil, nil, log)

	for _, p := range defaultProtectedPaths {
		if !b.isProtected(p) {
			t.Errorf("should protect %s (default)", p)
		}
	}
	if b.isProtected("/anything") {
		t.Error("should not protect /anything with default paths")
	}
}

func TestBruteForceDefender_CleanupLoop(t *testing.T) {
	log, _ := logger.New("warn", "json", "stderr")
	_ = NewDefender(true, 2, 60, 300, []string{"/api"}, []int{401}, log)
	time.Sleep(100 * time.Millisecond)
}

func TestBruteForceDefender_RequestWindowExpiry(t *testing.T) {
	log, _ := logger.New("warn", "json", "stderr")
	b := NewDefender(true, 2, 1, 300, []string{"/login"}, nil, log)
	ip := "1.2.3.4"
	path := "/login"
	body := []byte("test")

	b.RecordRequest(ip, path, "POST", body)
	b.RecordRequest(ip, path, "POST", body)
	if !b.ShouldBlock(ip, path) {
		t.Fatal("should block immediately")
	}

	time.Sleep(1200 * time.Millisecond)
	b.RecordRequest(ip, path, "POST", body)
	if b.ShouldBlock(ip, path) {
		t.Error("should not block after window expiry with only 1 request")
	}
}

func TestBruteForceDefender_DefaultStatusCodesRange(t *testing.T) {
	log, _ := logger.New("warn", "json", "stderr")
	b := NewDefender(true, 2, 60, 300, []string{"/login"}, nil, log)
	ip := "1.2.3.4"
	path := "/login"

	testCodes := []int{400, 401, 403, 404, 405, 429, 500, 501, 502, 503}
	for _, code := range testCodes {
		b.Reset(ip, path)
		b.RecordFailure(ip, path, code)
		b.RecordFailure(ip, path, code)
		if !b.ShouldBlock(ip, path) {
			t.Errorf("should block with status code %d", code)
		}
	}
}

// ========== New Enhanced Tests ==========

func TestBruteForceDefender_Status501DoubleCount(t *testing.T) {
	log, _ := logger.New("warn", "json", "stderr")
	b := NewDefender(true, 4, 60, 300, []string{"/login"}, nil, log)
	ip := "1.2.3.4"
	path := "/login"

	// 501 counts double — 2 occurrences = 4 counts, triggers block at threshold 4
	b.RecordFailure(ip, path, 501)
	b.RecordFailure(ip, path, 501)
	if !b.ShouldBlock(ip, path) {
		t.Error("501 errors should be double-counted, 2 should trigger block at threshold 4")
	}
}

func TestBruteForceDefender_Status501SingleNotBlock(t *testing.T) {
	log, _ := logger.New("warn", "json", "stderr")
	b := NewDefender(true, 4, 60, 300, []string{"/login"}, nil, log)
	ip := "1.2.3.4"
	path := "/login"

	// 1 x 501 = 2 count, not enough for threshold 4
	b.RecordFailure(ip, path, 501)
	if b.ShouldBlock(ip, path) {
		t.Error("single 501 should not trigger block at threshold 4 (count=2)")
	}
}

func TestBruteForceDefender_PUTMethod(t *testing.T) {
	log, _ := logger.New("warn", "json", "stderr")
	b := NewDefender(true, 3, 60, 300, []string{"/api"}, nil, log)
	ip := "1.2.3.4"
	path := "/api/users"

	b.RecordRequest(ip, path, "PUT", []byte(`{"role":"admin"}`))
	b.RecordRequest(ip, path, "PUT", []byte(`{"role":"admin"}`))
	b.RecordRequest(ip, path, "PUT", []byte(`{"role":"admin"}`))
	if !b.ShouldBlock(ip, path) {
		t.Error("PUT requests should trigger brute force detection")
	}
}

func TestBruteForceDefender_PATCHMethod(t *testing.T) {
	log, _ := logger.New("warn", "json", "stderr")
	b := NewDefender(true, 3, 60, 300, []string{"/api"}, nil, log)
	ip := "1.2.3.4"
	path := "/api/users/profile"

	b.RecordRequest(ip, path, "PATCH", []byte(`{"status":"active"}`))
	b.RecordRequest(ip, path, "PATCH", []byte(`{"status":"active"}`))
	b.RecordRequest(ip, path, "PATCH", []byte(`{"status":"active"}`))
	if !b.ShouldBlock(ip, path) {
		t.Error("PATCH requests should trigger brute force detection")
	}
}

func TestBruteForceDefender_DELETEMethod(t *testing.T) {
	log, _ := logger.New("warn", "json", "stderr")
	b := NewDefender(true, 3, 60, 300, []string{"/api"}, nil, log)
	ip := "1.2.3.4"
	path := "/api/users/delete"

	b.RecordRequest(ip, path, "DELETE", []byte(`{"confirm":true}`))
	b.RecordRequest(ip, path, "DELETE", []byte(`{"confirm":true}`))
	b.RecordRequest(ip, path, "DELETE", []byte(`{"confirm":true}`))
	if !b.ShouldBlock(ip, path) {
		t.Error("DELETE requests should trigger brute force detection")
	}
}

func TestBruteForceDefender_GETNotTracked(t *testing.T) {
	log, _ := logger.New("warn", "json", "stderr")
	b := NewDefender(true, 2, 60, 300, []string{"/login"}, nil, log)
	ip := "1.2.3.4"
	path := "/login"

	for i := 0; i < 10; i++ {
		b.RecordRequest(ip, path, "GET", []byte("user=admin"))
	}
	for i := 0; i < 10; i++ {
		b.RecordRequest(ip, path, "HEAD", nil)
	}
	if b.ShouldBlock(ip, path) {
		t.Error("GET/HEAD should not be tracked")
	}
}

func TestBruteForceDefender_EmptyBody(t *testing.T) {
	log, _ := logger.New("warn", "json", "stderr")
	b := NewDefender(true, 3, 60, 300, []string{"/login"}, nil, log)
	ip := "1.2.3.4"
	path := "/login"

	// Empty body requests still count toward the threshold
	b.RecordRequest(ip, path, "POST", nil)
	b.RecordRequest(ip, path, "POST", nil)
	b.RecordRequest(ip, path, "POST", nil)
	if !b.ShouldBlock(ip, path) {
		t.Error("empty body POSTs should trigger block")
	}
}

func TestBruteForceDefender_DefaultPathAuthEndpoints(t *testing.T) {
	log, _ := logger.New("warn", "json", "stderr")
	b := NewDefender(true, 2, 60, 300, nil, nil, log)

	authEndpoints := []string{
		"/signin", "/auth/google", "/oauth/token",
		"/api/v1/login", "/api/v1/auth/verify",
		"/user/login", "/users/login", "/account/login",
	}
	for _, ep := range authEndpoints {
		if !b.isProtected(ep) {
			t.Errorf("default paths should protect %s", ep)
		}
	}
}

func TestBruteForceDefender_DifferentMethodsDifferentCounts(t *testing.T) {
	log, _ := logger.New("warn", "json", "stderr")
	b := NewDefender(true, 3, 60, 300, []string{"/api"}, nil, log)
	ip := "1.2.3.4"
	path := "/api/login"

	// Mix of methods: all should count
	b.RecordRequest(ip, path, "POST", []byte("a"))
	b.RecordRequest(ip, path, "PUT", []byte("b"))
	b.RecordRequest(ip, path, "PATCH", []byte("c"))
	if !b.ShouldBlock(ip, path) {
		t.Error("mixed methods POST+PUT+PATCH should trigger block")
	}
}

func TestBruteForceDefender_DistributedAttack(t *testing.T) {
	log, _ := logger.New("warn", "json", "stderr")
	b := NewDefender(true, 5, 60, 300, []string{"/login"}, nil, log)
	path := "/login"

	// 10 different IPs, 5 requests each = 50 total → triggers distributed detection
	for i := 0; i < 10; i++ {
		ip := "10.0.0." + string(rune('1'+i))
		for j := 0; j < 5; j++ {
			b.RecordRequest(ip, path, "POST", []byte("pass=test"+string(rune('0'+j))))
		}
	}

	// Any new IP to this path should be blocked
	if !b.ShouldBlock("10.0.0.99", path) {
		t.Error("distributed brute force attack should be detected")
	}
}

func TestBruteForceDefender_NewProtectedPaths(t *testing.T) {
	log, _ := logger.New("warn", "json", "stderr")

	// Check that all new default paths are in the list
	expectedPaths := []string{
		"/login", "/admin", "/wp-login", "/api/login", "/api/auth",
		"/signin", "/auth", "/oauth", "/api/v1/login", "/api/v1/auth",
		"/user/login", "/users/login", "/account/login",
	}

	b := NewDefender(true, 2, 60, 300, nil, nil, log)
	for _, p := range expectedPaths {
		if !b.isProtected(p) {
			t.Errorf("expected default path %s to be protected", p)
		}
	}
}

func TestBruteForceDefender_CredentialStuffing(t *testing.T) {
	log, _ := logger.New("warn", "json", "stderr")
	b := NewDefender(true, 5, 60, 300, []string{"/login"}, nil, log)
	ip := "1.2.3.4"
	path := "/login"

	// Same password, different usernames = credential stuffing
	users := []string{"admin", "root", "user", "test", "guest"}
	for _, user := range users {
		body := []byte("user=" + user + "&pass=password123")
		b.RecordRequest(ip, path, "POST", body)
	}
	if !b.ShouldBlock(ip, path) {
		t.Error("credential stuffing should be blocked")
	}
}

func TestBruteForceDefender_BlockDurationApplied(t *testing.T) {
	log, _ := logger.New("warn", "json", "stderr")
	b := NewDefender(true, 3, 60, 100, []string{"/login"}, nil, log)
	ip := "1.2.3.4"
	path := "/login"

	b.RecordRequest(ip, path, "POST", []byte("test"))
	b.RecordRequest(ip, path, "POST", []byte("test"))
	b.RecordRequest(ip, path, "POST", []byte("test"))
	if !b.ShouldBlock(ip, path) {
		t.Fatal("should be blocked")
	}
	// Should stay blocked within block duration
	if !b.ShouldBlock(ip, path) {
		t.Error("should stay blocked within block duration")
	}
}
