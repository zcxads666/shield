package defender

import (
	"testing"
	"time"

	"github.com/shield/shield/internal/logger"
	"github.com/shield/shield/internal/metrics"
)

func TestNewBruteForceDefender_Disabled(t *testing.T) {
	log, _ := logger.New("warn", "json", "stderr")
	b := NewBruteForceDefender(false, 5, 60, 300, []string{"/api"}, []int{401}, log)
	if b == nil {
		t.Fatal("expected non-nil defender")
	}
	if b.ShouldBlock("1.2.3.4", "/api/login") {
		t.Error("disabled defender should not block")
	}
}

func TestBruteForceDefender_RecordAndBlock(t *testing.T) {
	log, _ := logger.New("warn", "json", "stderr")
	b := NewBruteForceDefender(true, 3, 60, 300, []string{"/api"}, []int{401}, log)
	ip := "1.2.3.4"
	path := "/api/login"

	// first two failures
	b.RecordFailure(ip, path, 401)
	b.RecordFailure(ip, path, 401)
	if b.ShouldBlock(ip, path) {
		t.Error("should not block before max failures")
	}

	// third failure triggers block
	b.RecordFailure(ip, path, 401)
	if !b.ShouldBlock(ip, path) {
		t.Error("should block after max failures")
	}
}

func TestBruteForceDefender_UnprotectedPath(t *testing.T) {
	log, _ := logger.New("warn", "json", "stderr")
	b := NewBruteForceDefender(true, 3, 60, 300, []string{"/api"}, []int{401}, log)
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
	b := NewBruteForceDefender(true, 2, 60, 300, nil, nil, log)
	ip := "1.2.3.4"
	path := "/login"

	// default codes are 401 and 403
	b.RecordFailure(ip, path, 500)
	b.RecordFailure(ip, path, 500)
	if b.ShouldBlock(ip, path) {
		t.Error("should not block non-default status codes")
	}

	b.RecordFailure(ip, path, 401)
	b.RecordFailure(ip, path, 401)
	if !b.ShouldBlock(ip, path) {
		t.Error("should block with default status code 401")
	}
}

func TestBruteForceDefender_Reset(t *testing.T) {
	log, _ := logger.New("warn", "json", "stderr")
	b := NewBruteForceDefender(true, 2, 60, 300, []string{"/api"}, []int{401}, log)
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

func TestBruteForceDefender_WindowExpiry(t *testing.T) {
	log, _ := logger.New("warn", "json", "stderr")
	b := NewBruteForceDefender(true, 2, 1, 300, []string{"/api"}, []int{401}, log)
	ip := "1.2.3.4"
	path := "/api/login"

	b.RecordFailure(ip, path, 401)
	b.RecordFailure(ip, path, 401)
	if !b.ShouldBlock(ip, path) {
		t.Fatal("should block immediately")
	}

	// wait for window to expire
	time.Sleep(1200 * time.Millisecond)
	// after window expiry, a new failure starts a new window
	b.RecordFailure(ip, path, 401)
	if b.ShouldBlock(ip, path) {
		t.Error("should not block after window expiry with only 1 failure")
	}
}

func TestBruteForceDefender_BlockDurationExpiry(t *testing.T) {
	log, _ := logger.New("warn", "json", "stderr")
	b := NewBruteForceDefender(true, 2, 60, 1, []string{"/api"}, []int{401}, log)
	ip := "1.2.3.4"
	path := "/api/login"

	b.RecordFailure(ip, path, 401)
	b.RecordFailure(ip, path, 401)
	if !b.ShouldBlock(ip, path) {
		t.Fatal("should block")
	}

	// wait for block duration to expire
	time.Sleep(1200 * time.Millisecond)
	if b.ShouldBlock(ip, path) {
		t.Error("should not block after block duration expiry")
	}
}

func TestBruteForceDefender_Metrics(t *testing.T) {
	metrics.Get().BruteForceBlocks = 0

	log, _ := logger.New("warn", "json", "stderr")
	b := NewBruteForceDefender(true, 2, 60, 300, []string{"/api"}, []int{401}, log)

	b.RecordFailure("1.2.3.4", "/api/login", 401)
	b.RecordFailure("1.2.3.4", "/api/login", 401)

	if metrics.Get().Snapshot().BruteForceBlocks == 0 {
		t.Error("BruteForceBlocks metric should be incremented")
	}
}

func TestBruteForceDefender_DisabledRecord(t *testing.T) {
	log, _ := logger.New("warn", "json", "stderr")
	b := NewBruteForceDefender(false, 2, 60, 300, []string{"/api"}, []int{401}, log)
	// should not panic
	b.RecordFailure("1.2.3.4", "/api/login", 401)
	b.Reset("1.2.3.4", "/api/login")
}

func TestBruteForceDefender_isProtected(t *testing.T) {
	log, _ := logger.New("warn", "json", "stderr")
	b := NewBruteForceDefender(true, 2, 60, 300, []string{"/api", "/admin"}, []int{401}, log)

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

func TestBruteForceDefender_EmptyProtectedPaths(t *testing.T) {
	log, _ := logger.New("warn", "json", "stderr")
	b := NewBruteForceDefender(true, 2, 60, 300, nil, []int{401}, log)
	if !b.isProtected("/anything") {
		t.Error("empty protected paths should protect everything")
	}
}

func TestBruteForceDefender_CleanupLoop(t *testing.T) {
	log, _ := logger.New("warn", "json", "stderr")
	_ = NewBruteForceDefender(true, 2, 60, 300, []string{"/api"}, []int{401}, log)
	// cleanup loop should run without panic
	time.Sleep(100 * time.Millisecond)
}
