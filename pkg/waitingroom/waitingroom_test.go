package waitingroom

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestNewWaitingRoom(t *testing.T) {
	cfg := Config{
		Enabled:       true,
		MaxQueueSize:  100,
		ReleasePerSec: 10.0,
	}
	wr := New(cfg, "test-secret")
	defer wr.Stop()

	if wr == nil {
		t.Fatal("expected non-nil waiting room")
	}
	if wr.IsActive() {
		t.Error("expected inactive by default")
	}
	if wr.QueueLength() != 0 {
		t.Error("expected empty queue")
	}
}

func TestJoinAndPosition(t *testing.T) {
	cfg := Config{
		Enabled:       true,
		MaxQueueSize:  100,
		ReleasePerSec: 5.0,
	}
	wr := New(cfg, "test-secret")
	defer wr.Stop()

	pos, err := wr.Join("session-1", "1.2.3.4", "/test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pos != 1 {
		t.Errorf("expected position 1, got %d", pos)
	}

	pos, err = wr.Join("session-2", "5.6.7.8", "/other")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pos != 2 {
		t.Errorf("expected position 2, got %d", pos)
	}

	if p := wr.Position("session-1"); p != 1 {
		t.Errorf("expected position 1, got %d", p)
	}
	if p := wr.Position("session-2"); p != 2 {
		t.Errorf("expected position 2, got %d", p)
	}
	if p := wr.Position("nonexistent"); p != 0 {
		t.Errorf("expected position 0 for unknown session, got %d", p)
	}
	if wr.QueueLength() != 2 {
		t.Errorf("expected queue length 2, got %d", wr.QueueLength())
	}
}

func TestJoinDuplicate(t *testing.T) {
	cfg := Config{
		Enabled:       true,
		MaxQueueSize:  100,
		ReleasePerSec: 5.0,
	}
	wr := New(cfg, "test-secret")
	defer wr.Stop()

	wr.Join("session-1", "1.2.3.4", "/test")
	pos, err := wr.Join("session-1", "1.2.3.4", "/test")
	if err != nil {
		t.Fatalf("unexpected error on duplicate join: %v", err)
	}
	if pos != 1 {
		t.Errorf("expected position 1 on re-join, got %d", pos)
	}
	if wr.QueueLength() != 1 {
		t.Errorf("expected queue length 1 on duplicate, got %d", wr.QueueLength())
	}
}

func TestLeave(t *testing.T) {
	cfg := Config{
		Enabled:       true,
		MaxQueueSize:  100,
		ReleasePerSec: 5.0,
	}
	wr := New(cfg, "test-secret")
	defer wr.Stop()

	wr.Join("session-1", "1.2.3.4", "/test")
	wr.Join("session-2", "5.6.7.8", "/other")

	wr.Leave("session-1")

	if wr.Position("session-1") != 0 {
		t.Error("expected position 0 after leave")
	}
	if wr.Position("session-2") != 1 {
		t.Errorf("expected position 1 after first left, got %d", wr.Position("session-2"))
	}
	if wr.QueueLength() != 1 {
		t.Errorf("expected queue length 1, got %d", wr.QueueLength())
	}
}

func TestQueueFull(t *testing.T) {
	cfg := Config{
		Enabled:       true,
		MaxQueueSize:  2,
		ReleasePerSec: 5.0,
	}
	wr := New(cfg, "test-secret")
	defer wr.Stop()

	wr.Join("s1", "1.2.3.4", "/1")
	wr.Join("s2", "5.6.7.8", "/2")
	_, err := wr.Join("s3", "9.10.11.12", "/3")
	if err == nil {
		t.Error("expected error for full queue")
	}
}

func TestReleaseFlow(t *testing.T) {
	cfg := Config{
		Enabled:       true,
		MaxQueueSize:  100,
		ReleasePerSec: 50.0, // fast release for testing
	}
	wr := New(cfg, "test-secret")
	defer wr.Stop()

	wr.Join("session-1", "1.2.3.4", "/test")
	wr.Join("session-2", "5.6.7.8", "/other")

	// Session 1 should be released quickly
	err := wr.WaitForRelease("session-1", 3*time.Second)
	if err != nil {
		t.Fatalf("expected release within timeout: %v", err)
	}

	// After release, position should be 0
	if wr.Position("session-1") != 0 {
		t.Error("expected position 0 after release")
	}
	if wr.Position("session-2") == 0 {
		t.Error("session-2 should still be in queue")
	}
}

func TestWaitForReleaseTimeout(t *testing.T) {
	cfg := Config{
		Enabled:         true,
		MaxQueueSize:    100,
		ReleasePerSec:   0.5,
		QueueTimeoutSec: 5,
	}
	wr := New(cfg, "test-secret")
	defer wr.Stop()

	wr.Join("s1", "1.2.3.4", "/1")
	wr.Join("s2", "5.6.7.8", "/2")
	wr.Join("s3", "9.10.11.12", "/3")

	// s3 should time out before being released
	err := wr.WaitForRelease("s3", 100*time.Millisecond)
	if err == nil {
		t.Error("expected timeout error")
	}
	// Session should be removed after timeout
	if wr.Position("s3") != 0 {
		t.Error("expected s3 removed after timeout")
	}
}

func TestActiveToggle(t *testing.T) {
	cfg := Config{
		Enabled:       true,
		MaxQueueSize:  100,
		ReleasePerSec: 5.0,
	}
	wr := New(cfg, "test-secret")
	defer wr.Stop()

	if wr.IsActive() {
		t.Error("expected inactive")
	}

	wr.SetActive(true)
	if !wr.IsActive() {
		t.Error("expected active")
	}

	wr.SetActive(false)
	if wr.IsActive() {
		t.Error("expected inactive after toggle")
	}
}

func TestIsActiveWhenDisabled(t *testing.T) {
	cfg := Config{
		Enabled:       false,
		MaxQueueSize:  100,
		ReleasePerSec: 5.0,
	}
	wr := New(cfg, "test-secret")
	defer wr.Stop()

	wr.SetActive(true)
	if wr.IsActive() {
		t.Error("expected inactive when config disabled")
	}
}

func TestEstimatedWait(t *testing.T) {
	cfg := Config{
		Enabled:       true,
		MaxQueueSize:  100,
		ReleasePerSec: 2.0,
	}
	wr := New(cfg, "test-secret")
	defer wr.Stop()

	est := wr.EstimatedWait(5)
	if est < 2*time.Second || est > 3*time.Second {
		t.Errorf("expected ~2.5s for position 5 at 2/sec, got %v", est)
	}

	if wr.EstimatedWait(0) != 0 {
		t.Error("expected zero wait for position 0")
	}
	if wr.EstimatedWait(-1) != 0 {
		t.Error("expected zero wait for negative position")
	}
}

func TestSessionCookieRoundTrip(t *testing.T) {
	wr := New(Config{Enabled: true, MaxQueueSize: 100, ReleasePerSec: 5.0}, "my-secret-key")
	defer wr.Stop()

	cookie := wr.GenerateSessionCookie("1.2.3.4")
	if cookie == "" {
		t.Fatal("expected non-empty cookie")
	}

	parts := strings.SplitN(cookie, ".", 2)
	if len(parts) != 2 {
		t.Fatal("expected sessionID.signature format")
	}

	sessionID, ok := wr.VerifySessionCookie(cookie, "1.2.3.4")
	if !ok {
		t.Fatal("expected valid cookie verification")
	}
	if sessionID != parts[0] {
		t.Errorf("expected session ID %s, got %s", parts[0], sessionID)
	}

	// Different IP should fail
	_, ok = wr.VerifySessionCookie(cookie, "different.ip")
	if ok {
		t.Error("expected verification failure for different IP")
	}

	// Tampered cookie should fail
	_, ok = wr.VerifySessionCookie("bad.cookie", "1.2.3.4")
	if ok {
		t.Error("expected verification failure for bad cookie")
	}
}

func TestConcurrentJoinAndRelease(t *testing.T) {
	cfg := Config{
		Enabled:       true,
		MaxQueueSize:  1000,
		ReleasePerSec: 100.0,
	}
	wr := New(cfg, "test-secret")
	defer wr.Stop()

	var wg sync.WaitGroup
	n := 50

	// Concurrent joins
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sid := "session-" + string(rune('a'+i%26)) + string(rune('0'+i/26))
			wr.Join(sid, "1.2.3.4", "/test")
		}(i)
	}
	wg.Wait()

	if wr.QueueLength() > n {
		t.Errorf("queue length %d > expected max %d", wr.QueueLength(), n)
	}
}

func TestAutoActivate(t *testing.T) {
	cfg := Config{
		Enabled:         true,
		MaxQueueSize:    100,
		ReleasePerSec:   0.01, // very slow release so entries stay in queue
		ActiveThreshold: 10.0,
	}
	wr := New(cfg, "test-secret")
	defer wr.Stop()

	var rateVal float64
	var mu sync.Mutex
	rateFn := func() float64 {
		mu.Lock()
		defer mu.Unlock()
		return rateVal
	}

	go wr.AutoActivate(rateFn)

	// High rate activates
	mu.Lock()
	rateVal = 50.0
	mu.Unlock()
	time.Sleep(6 * time.Second)
	if !wr.IsActive() {
		t.Error("expected active when rate > threshold")
	}

	// Low rate + empty queue deactivates
	mu.Lock()
	rateVal = 1.0
	mu.Unlock()
	time.Sleep(6 * time.Second)
	if wr.IsActive() {
		t.Error("expected inactive when rate drops and queue empty")
	}

	// Low rate deactivates even with non-empty queue.
	// Requiring an empty queue creates a deadlock where new IPs keep joining
	// while active, preventing the queue from ever draining after the attack subsides.
	wr.SetActive(true)
	wr.Join("s1", "1.2.3.4", "/test")
	mu.Lock()
	rateVal = 1.0
	mu.Unlock()
	time.Sleep(6 * time.Second)
	if wr.IsActive() {
		t.Error("expected inactive when rate drops below threshold (queue non-empty but hysteresis allows deactivation)")
	}
}

func TestSSEHandler(t *testing.T) {
	cfg := Config{
		Enabled:       true,
		MaxQueueSize:  100,
		ReleasePerSec: 5.0,
	}
	wr := New(cfg, "test-secret")
	defer wr.Stop()

	wr.Join("test-session", "1.2.3.4", "/test")

	req := httptest.NewRequest(http.MethodGet, "/__shield_wait_stream?session=test-session", nil)
	rec := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		wr.SSEHandler()(rec, req)
		close(done)
	}()

	// Wait for a few position events
	select {
	case <-done:
	case <-time.After(5 * time.Second):
	}

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	ct := rec.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "text/event-stream") {
		t.Errorf("expected text/event-stream content type, got %s", ct)
	}
}

func TestSSEHandlerMissingSession(t *testing.T) {
	cfg := Config{
		Enabled:       true,
		MaxQueueSize:  100,
		ReleasePerSec: 5.0,
	}
	wr := New(cfg, "test-secret")
	defer wr.Stop()

	req := httptest.NewRequest(http.MethodGet, "/__shield_wait_stream", nil)
	rec := httptest.NewRecorder()
	wr.SSEHandler()(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestStatusHandler(t *testing.T) {
	cfg := Config{
		Enabled:       true,
		MaxQueueSize:  100,
		ReleasePerSec: 5.0,
	}
	wr := New(cfg, "test-secret")
	defer wr.Stop()

	wr.SetActive(true)
	wr.Join("s1", "1.2.3.4", "/test")

	req := httptest.NewRequest(http.MethodGet, "/__shield_wait_status", nil)
	rec := httptest.NewRecorder()
	wr.StatusHandler()(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"active":true`) {
		t.Errorf("expected active:true in response, got %s", body)
	}
	if !strings.Contains(body, `"queue_length":1`) {
		t.Errorf("expected queue_length:1 in response, got %s", body)
	}
}

func TestServeWaitingPage(t *testing.T) {
	cfg := Config{
		Enabled:       true,
		MaxQueueSize:  100,
		ReleasePerSec: 5.0,
	}
	wr := New(cfg, "test-secret")
	defer wr.Stop()

	wr.Join("test-session", "1.2.3.4", "/original/page")

	req := httptest.NewRequest(http.MethodGet, "/original/page", nil)
	rec := httptest.NewRecorder()
	wr.ServeWaitingPage(rec, req, "test-session", "/original/page")

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "排队") && !strings.Contains(body, "waiting") {
		t.Error("expected waiting page content")
	}
	if !strings.Contains(body, "test-session") {
		t.Error("expected session ID in page")
	}
}

func TestConcurrentReleaseSignal(t *testing.T) {
	cfg := Config{
		Enabled:       true,
		MaxQueueSize:  100,
		ReleasePerSec: 200.0,
	}
	wr := New(cfg, "test-secret")
	defer wr.Stop()

	n := 20
	for i := 0; i < n; i++ {
		sid := "sess-" + string(rune('a'+i%26))
		wr.Join(sid, "1.2.3.4", "/test")
	}

	// All should be released within reasonable time
	time.Sleep(2 * time.Second)
	if wr.QueueLength() != 0 {
		t.Errorf("expected empty queue after release period, got %d", wr.QueueLength())
	}
}

func TestSessionIDPersistenceAcrossReconnects(t *testing.T) {
	cfg := Config{
		Enabled:       true,
		MaxQueueSize:  100,
		ReleasePerSec: 1.0,
	}
	wr := New(cfg, "test-secret")
	defer wr.Stop()

	pos1, err := wr.Join("persistent-session-abc", "10.0.0.1", "/test")
	if err != nil {
		t.Fatalf("initial join: %v", err)
	}
	if pos1 != 1 {
		t.Fatalf("expected position 1, got %d", pos1)
	}

	// Reconnect with same session ID preserves position
	pos2, err := wr.Join("persistent-session-abc", "10.0.0.1", "/test")
	if err != nil {
		t.Fatalf("reconnect: %v", err)
	}
	if pos2 != 1 {
		t.Fatalf("expected position 1 after reconnect, got %d", pos2)
	}
	if wr.QueueLength() != 1 {
		t.Fatalf("expected queue length 1 after reconnect, got %d", wr.QueueLength())
	}

	// New session goes to back
	pos3, err := wr.Join("new-session-xyz", "10.0.0.2", "/test")
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	if pos3 != 2 {
		t.Fatalf("expected position 2, got %d", pos3)
	}
}

func TestQueuePositionAccuracy(t *testing.T) {
	cfg := Config{
		Enabled:       true,
		MaxQueueSize:  100,
		ReleasePerSec: 1.0,
	}
	wr := New(cfg, "test-secret")
	defer wr.Stop()

	wr.Join("s1", "10.0.0.1", "/test")
	wr.Join("s2", "10.0.0.2", "/test")
	wr.Join("s3", "10.0.0.3", "/test")

	if wr.QueueLength() != 3 {
		t.Fatalf("expected queue length 3, got %d", wr.QueueLength())
	}
	if wr.Position("s1") != 1 {
		t.Errorf("s1: expected position 1, got %d", wr.Position("s1"))
	}
	if wr.Position("s2") != 2 {
		t.Errorf("s2: expected position 2, got %d", wr.Position("s2"))
	}
	if wr.Position("s3") != 3 {
		t.Errorf("s3: expected position 3, got %d", wr.Position("s3"))
	}
}
