package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/shield/shield/internal/storage/blacklist"
	"github.com/shield/shield/pkg/logger"
	"github.com/shield/shield/internal/service/rules"
)

func TestProxy_XSSPayloadFile(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg := newTestConfig()
	cfg.Proxy.TargetURL = backend.URL
	log, _ := logger.New("warn", "json", "stderr")
	bl := blacklist.NewManager("")
	rl := rules.NewEngine("", false)

	srv, err := NewProxyServer(cfg, log, bl, rl)
	if err != nil {
		t.Fatal(err)
	}

	p := httptest.NewServer(srv.Handler())
	defer p.Close()

	// Test via GET query
	resp, err := http.Get(p.URL + "/?content=<script>alert(1)</script>")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for XSS via GET, got %d", resp.StatusCode)
	}

	// Test via POST body
	resp2, err := http.Post(p.URL+"/comment", "application/x-www-form-urlencoded",
		strings.NewReader("content=<script>alert(1)</script>"))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for XSS via POST, got %d", resp2.StatusCode)
	}
}

func TestProxy_SQLiPayloadFile(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg := newTestConfig()
	cfg.Proxy.TargetURL = backend.URL
	log, _ := logger.New("warn", "json", "stderr")
	bl := blacklist.NewManager("")
	rl := rules.NewEngine("", false)

	srv, err := NewProxyServer(cfg, log, bl, rl)
	if err != nil {
		t.Fatal(err)
	}

	p := httptest.NewServer(srv.Handler())
	defer p.Close()

	// Test via GET query
	resp, err := http.Get(p.URL + "/?q=1'+UNION+SELECT+*+FROM+users--")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for SQLi via GET, got %d", resp.StatusCode)
	}

	// Test via POST body
	resp2, err := http.Post(p.URL+"/search", "application/x-www-form-urlencoded",
		strings.NewReader("q=1'+UNION+SELECT+*+FROM+users--"))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for SQLi via POST, got %d", resp2.StatusCode)
	}
}
