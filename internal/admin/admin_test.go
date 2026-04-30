package admin

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/shield/shield/internal/blacklist"
	"github.com/shield/shield/internal/config"
	"github.com/shield/shield/internal/metrics"
)

func newTestAdminServer() *Server {
	cfg := &config.Config{
		Server: config.ServerConfig{AdminBindAddr: ":9090"},
		Blacklist: config.BlacklistConfig{Enabled: true},
	}
	bl := blacklist.NewManager("")
	return NewServer(cfg, bl)
}

func TestAdmin_HealthCheck(t *testing.T) {
	srv := newTestAdminServer()
	req := httptest.NewRequest("GET", "/health", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "ok") {
		t.Fatalf("expected status ok, got %s", body)
	}
}

func TestAdmin_Stats(t *testing.T) {
	// Reset metrics for test
	m := metrics.Get()
	m.IncTotalRequests()
	m.IncBlockedRequests()
	m.IncAllowedRequests()

	srv := newTestAdminServer()
	req := httptest.NewRequest("GET", "/stats", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var stats map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &stats); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if stats["status"] != nil {
		t.Fatalf("unexpected status field in stats")
	}
}

func TestAdmin_BlacklistGet(t *testing.T) {
	srv := newTestAdminServer()
	srv.blacklist.Add("10.0.0.1", "test", time.Hour, false)

	req := httptest.NewRequest("GET", "/blacklist", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var list []blacklist.Entry
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(list))
	}
}

func TestAdmin_BlacklistPost(t *testing.T) {
	srv := newTestAdminServer()
	body := `{"ip":"192.168.1.100","reason":"spam","duration_sec":3600}`
	req := httptest.NewRequest("POST", "/blacklist", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", rec.Code)
	}

	if !srv.blacklist.IsBlocked("192.168.1.100") {
		t.Fatal("expected IP to be blocked")
	}
}

func TestAdmin_BlacklistDelete(t *testing.T) {
	srv := newTestAdminServer()
	srv.blacklist.Add("192.168.1.100", "test", time.Hour, false)

	req := httptest.NewRequest("DELETE", "/blacklist?ip=192.168.1.100", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	if srv.blacklist.IsBlocked("192.168.1.100") {
		t.Fatal("expected IP to be unblocked")
	}
}

func TestAdmin_BlacklistDeleteMissingIP(t *testing.T) {
	srv := newTestAdminServer()
	req := httptest.NewRequest("DELETE", "/blacklist", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestAdmin_BlacklistPostInvalidJSON(t *testing.T) {
	srv := newTestAdminServer()
	req := httptest.NewRequest("POST", "/blacklist", strings.NewReader("not json"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestAdmin_StatsMethodNotAllowed(t *testing.T) {
	srv := newTestAdminServer()
	req := httptest.NewRequest("POST", "/stats", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rec.Code)
	}
}

func TestAdmin_BlacklistMethodNotAllowed(t *testing.T) {
	srv := newTestAdminServer()
	req := httptest.NewRequest("PUT", "/blacklist", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rec.Code)
	}
}

func BenchmarkAdmin_Health(b *testing.B) {
	srv := newTestAdminServer()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("GET", "/health", nil)
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		io.ReadAll(rec.Body)
	}
}
