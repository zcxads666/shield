package handler

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/shield/shield/internal/storage/blacklist"
	"github.com/shield/shield/pkg/config"
	"github.com/shield/shield/pkg/logger"
	"github.com/shield/shield/internal/service/rules"
)

func newTestConfig() *config.Config {
	return &config.Config{
		Server: config.ServerConfig{BindAddr: ":8080", ReadTimeoutMs: 30000, WriteTimeoutMs: 30000, MaxHeaderBytes: 1 << 20},
		Proxy:  config.ProxyConfig{TargetURL: "http://127.0.0.1:80", TrustForwarded: false},
		RateLimit: config.RateLimitConfig{Enabled: true, RequestsPerSecond: 100, BurstSize: 150, BlockDurationSec: 300},
		DDoS: config.DDoSConfig{Enabled: true, MaxConnectionsPerIP: 1000, SlowlorisTimeoutMs: 30000},
		SQLInject: config.SQLInjectConfig{Enabled: true, Action: "block"},
		XSS: config.XSSConfig{Enabled: true, Action: "block"},
		BruteForce: config.BruteForceConfig{Enabled: true, MaxFailures: 5, WindowSec: 60, BlockDurationSec: 600, ProtectedPaths: []string{"/login", "/api/auth"}, StatusCodes: []int{401, 403}},
		Blacklist: config.BlacklistConfig{Enabled: true, PersistPath: "", AutoBlacklist: true},
		Log: config.LogConfig{Level: "warn", Format: "json", OutputPath: "stderr"},
		Rules: config.RulesConfig{RulesPath: "", HotReload: false},
	}
}

func TestProxy_NormalRequestPass(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok from backend"))
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

	proxy := httptest.NewServer(srv.Handler())
	defer proxy.Close()

	resp, err := http.Get(proxy.URL + "/")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if string(body) != "ok from backend" {
		t.Fatalf("unexpected body: %s", string(body))
	}
}

func TestProxy_SQLInjectionBlocked(t *testing.T) {
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

	proxy := httptest.NewServer(srv.Handler())
	defer proxy.Close()

	resp, err := http.Post(proxy.URL+"/search", "application/x-www-form-urlencoded",
		strings.NewReader("q=1'+UNION+SELECT+*+FROM+users--"))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}
}

func TestProxy_XSSBlocked(t *testing.T) {
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

	proxy := httptest.NewServer(srv.Handler())
	defer proxy.Close()

	resp, err := http.Post(proxy.URL+"/comment", "application/x-www-form-urlencoded",
		strings.NewReader("content=<script>alert(1)</script>"))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}
}

func TestProxy_BlacklistBlocked(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg := newTestConfig()
	cfg.Proxy.TargetURL = backend.URL
	cfg.Proxy.TrustForwarded = true
	log, _ := logger.New("warn", "json", "stderr")
	bl := blacklist.NewManager("")
	bl.Add("1.2.3.4", "test", time.Hour, false)
	rl := rules.NewEngine("", false)

	srv, err := NewProxyServer(cfg, log, bl, rl)
	if err != nil {
		t.Fatal(err)
	}

	proxy := httptest.NewServer(srv.Handler())
	defer proxy.Close()

	req, _ := http.NewRequest("GET", proxy.URL+"/", nil)
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for blacklisted IP, got %d", resp.StatusCode)
	}
}

func TestProxy_HeadersPreserved(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") != "test-agent" {
			t.Errorf("expected User-Agent=test-agent, got %s", r.Header.Get("User-Agent"))
		}
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

	proxy := httptest.NewServer(srv.Handler())
	defer proxy.Close()

	req, _ := http.NewRequest("GET", proxy.URL+"/", nil)
	req.Header.Set("User-Agent", "test-agent")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func BenchmarkProxy_Throughput(b *testing.B) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer backend.Close()

	cfg := newTestConfig()
	cfg.Proxy.TargetURL = backend.URL
	cfg.SQLInject.Enabled = false
	cfg.XSS.Enabled = false
	cfg.BruteForce.Enabled = false
	cfg.DDoS.Enabled = false
	cfg.Blacklist.Enabled = false
	log, _ := logger.New("warn", "json", "stderr")
	bl := blacklist.NewManager("")
	rl := rules.NewEngine("", false)

	srv, err := NewProxyServer(cfg, log, bl, rl)
	if err != nil {
		b.Fatal(err)
	}

	proxy := httptest.NewServer(srv.Handler())
	defer proxy.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp, err := http.Get(proxy.URL + "/")
		if err != nil {
			b.Fatal(err)
		}
		resp.Body.Close()
	}
}
