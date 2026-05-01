package ddos

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/shield/shield/pkg/logger"
)

func TestDDoSDefender_XBlockReason(t *testing.T) {
	log, _ := logger.New("warn", "json", "stderr")
	// rate limit: 1 rps, burst 1
	d := NewDefender(true, 100, 1000, 1, 1, false, log)

	handler := d.WrapHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// first request allowed
	req1 := httptest.NewRequest("GET", "/", nil)
	req1.RemoteAddr = "1.2.3.4:1234"
	rr1 := httptest.NewRecorder()
	handler.ServeHTTP(rr1, req1)
	if rr1.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr1.Code)
	}

	// second request blocked, should have X-Block-Reason header
	req2 := httptest.NewRequest("GET", "/", nil)
	req2.RemoteAddr = "1.2.3.4:1234"
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", rr2.Code)
	}
	reason := rr2.Header().Get("X-Block-Reason")
	if reason != "ddos" {
		t.Errorf("expected X-Block-Reason=ddos, got=%q", reason)
	}
}
