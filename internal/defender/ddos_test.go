package defender

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/shield/shield/internal/logger"
	"github.com/shield/shield/internal/metrics"
)

func TestNewDDoSDefender_Disabled(t *testing.T) {
	log, _ := logger.New("warn", "json", "stderr")
	d := NewDDoSDefender(false, 10, 1000, 100, 10, false, log)
	if d == nil {
		t.Fatal("expected non-nil defender")
	}
	if !d.Allow("1.2.3.4") {
		t.Error("disabled defender should allow all")
	}
}

func TestDDoSDefender_RateLimit(t *testing.T) {
	log, _ := logger.New("warn", "json", "stderr")
	d := NewDDoSDefender(true, 100, 1000, 1, 1, false, log)
	ip := "1.2.3.4"

	// first request should be allowed
	if !d.Allow(ip) {
		t.Fatal("first request should be allowed")
	}
	d.Release(ip)

	// immediately request again - rate limit should block (capacity 1, rps 1)
	if d.Allow(ip) {
		t.Error("second immediate request should be rate limited")
	}
}

func TestDDoSDefender_ConnectionLimit(t *testing.T) {
	log, _ := logger.New("warn", "json", "stderr")
	d := NewDDoSDefender(true, 2, 1000, 1000, 100, false, log)
	ip := "1.2.3.4"

	// two connections allowed
	if !d.Allow(ip) {
		t.Fatal("first connection should be allowed")
	}
	if !d.Allow(ip) {
		t.Fatal("second connection should be allowed")
	}
	// third should be blocked
	if d.Allow(ip) {
		t.Error("third connection should be blocked")
	}

	// release one, then should allow again
	d.Release(ip)
	if !d.Allow(ip) {
		t.Error("should allow after release")
	}
}

func TestDDoSDefender_Release(t *testing.T) {
	log, _ := logger.New("warn", "json", "stderr")
	d := NewDDoSDefender(true, 1, 1000, 1000, 100, false, log)
	ip := "1.2.3.4"

	if !d.Allow(ip) {
		t.Fatal("first should be allowed")
	}
	if d.Allow(ip) {
		t.Error("second should be blocked")
	}
	d.Release(ip)
	if !d.Allow(ip) {
		t.Error("should allow after release")
	}
}

func TestDDoSDefender_ReleaseDisabled(t *testing.T) {
	log, _ := logger.New("warn", "json", "stderr")
	d := NewDDoSDefender(false, 10, 1000, 100, 10, false, log)
	// should not panic
	d.Release("1.2.3.4")
}

func TestDDoSDefender_WrapHandler(t *testing.T) {
	log, _ := logger.New("warn", "json", "stderr")
	d := NewDDoSDefender(true, 1, 1000, 1000, 100, false, log)

	hold := make(chan struct{})
	done := make(chan struct{})
	handler := d.WrapHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-hold
		w.WriteHeader(http.StatusOK)
		close(done)
	}))

	// first request should succeed but hold the connection
	req1 := httptest.NewRequest("GET", "/", nil)
	req1.RemoteAddr = "1.2.3.4:1234"
	rr1 := httptest.NewRecorder()
	go handler.ServeHTTP(rr1, req1)

	// wait for the first request to acquire the connection
	time.Sleep(10 * time.Millisecond)

	// second concurrent request from same IP should be blocked (connection limit 1)
	req2 := httptest.NewRequest("GET", "/", nil)
	req2.RemoteAddr = "1.2.3.4:1235"
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429, got %d", rr2.Code)
	}

	close(hold)
	<-done
	if rr1.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr1.Code)
	}
}

func TestDDoSDefender_WrapHandlerDisabled(t *testing.T) {
	log, _ := logger.New("warn", "json", "stderr")
	d := NewDDoSDefender(false, 1, 1000, 100, 10, false, log)

	called := false
	handler := d.WrapHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if !called {
		t.Error("handler should have been called when disabled")
	}
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestDDoSDefender_Metrics(t *testing.T) {
	// Reset metrics for clean test
	metrics.Get().DDoSBlocks = 0

	log, _ := logger.New("warn", "json", "stderr")
	d := NewDDoSDefender(true, 1, 1000, 1, 1, false, log)
	ip := "1.2.3.4"

	// consume the only token
	if !d.Allow(ip) {
		t.Fatal("first should be allowed")
	}
	// second should be blocked and increment metric
	if d.Allow(ip) {
		t.Error("second should be blocked")
	}
	if metrics.Get().Snapshot().DDoSBlocks == 0 {
		t.Error("DDoSBlocks metric should be incremented")
	}
}

func TestDDoSDefender_ConcurrentAccess(t *testing.T) {
	log, _ := logger.New("warn", "json", "stderr")
	d := NewDDoSDefender(true, 100, 1000, 10000, 1000, false, log)
	ip := "1.2.3.4"

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if d.Allow(ip) {
				time.Sleep(1 * time.Millisecond)
				d.Release(ip)
			}
		}()
	}
	wg.Wait()
}

func TestDDoSDefender_CleanupLoop(t *testing.T) {
	log, _ := logger.New("warn", "json", "stderr")
	d := NewDDoSDefender(true, 10, 1000, 100, 10, false, log)
	ip := "1.2.3.4"

	if !d.Allow(ip) {
		t.Fatal("should allow")
	}
	// cleanup loop should run without panic
	time.Sleep(50 * time.Millisecond)
}
