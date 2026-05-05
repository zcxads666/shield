package handler

import (
	"bytes"
	"io"
	"mime/multipart"
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
		DDoSCC: config.DDoSCCConfig{
			Enabled:                       true,
			MaxConnectionsPerIP:           1000,
			SlowlorisTimeoutMs:            30000,
			GlobalRateDangerThreshold:      1000,
			GlobalRateDistributedThreshold: 1000,
			GlobalDistributedPathThreshold: 1000,
			GlobalConcentratedPathThreshold: 1,
			MaxRequests:                   1000,
			BurstRequests:                 1000,
			WindowSec:                     1,
			RequestsPerSecond:             1000,
			BurstSize:                     1000,
			BehaviorScoreThreshold:        0,
			BehaviorBlockThreshold:        0,
			SuspicionBlockThreshold:       100,
			SuspicionChallengeThreshold:   100,
			JSChallengeEnabled:            false,
			EnvFingerprintEnabled:         false,
			PoWChallengeEnabled:           false,
		},
		SQLInject: config.SQLInjectConfig{Enabled: true, Action: "block"},
		XSS: config.XSSConfig{Enabled: true, Action: "block"},
		Upload: config.UploadConfig{Enabled: true, Action: "block", MaxFileSizeMB: 32},
		BruteForce: config.BruteForceConfig{Enabled: true, MaxFailures: 3, WindowSec: 60, BlockDurationSec: 600, ProtectedPaths: []string{"/login", "/api/auth"}, StatusCodes: []int{401, 403}},
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
	cfg.DDoSCC.Enabled = false
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

func TestProxy_SSIInjectionBlockedAsWebshell(t *testing.T) {
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

	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	fw, _ := w.CreateFormFile("file", "test.shtml")
	fw.Write([]byte("<!--#exec cmd='id'-->"))
	w.Close()

	req, _ := http.NewRequest("POST", proxy.URL+"/upload", &buf)
	req.Header.Set("Content-Type", w.FormDataContentType())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for SSI injection, got %d", resp.StatusCode)
	}
	if reason := resp.Header.Get("X-Block-Reason"); reason != "webshell_upload" {
		t.Fatalf("expected X-Block-Reason=webshell_upload, got %s", reason)
	}
}

func TestProxy_BruteForceBlocked(t *testing.T) {
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

	// Send 3 POST requests to /login — 3rd should be blocked (maxFailures=3).
	for i := 0; i < 3; i++ {
		req, _ := http.NewRequest("POST", proxy.URL+"/login", nil)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("request %d failed: %v", i, err)
		}
		if i < 2 {
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("request %d: expected 200, got %d", i, resp.StatusCode)
			}
		} else {
			resp.Body.Close()
			if resp.StatusCode != http.StatusTooManyRequests {
				t.Fatalf("request %d: expected 429 (brute force block), got %d (%s)", i, resp.StatusCode, resp.Header.Get("X-Block-Reason"))
			}
		}
	}

	// 4th request (GET) should also be blocked (block duration applies)
	resp, err := http.Get(proxy.URL + "/login")
	if err != nil {
		t.Fatalf("GET request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected 429 for GET after brute force block, got %d", resp.StatusCode)
	}
}

func TestProxy_CookieUserHighSemaphorePriority(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer backend.Close()

	cfg := newTestConfig()
	cfg.Proxy.TargetURL = backend.URL
	cfg.Server.MaxConcurrent = 2
	cfg.Server.HighPriorityRatio = 0.5 // 1 high, 1 normal
	cfg.Server.QueueTimeoutMs = 100
	cfg.DDoSCC.Enabled = true
	cfg.DDoSCC.EnvFingerprintEnabled = false
	cfg.DDoSCC.JSChallengeEnabled = false
	cfg.DDoSCC.PoWChallengeEnabled = false
	cfg.SQLInject.Enabled = false
	cfg.XSS.Enabled = false
	cfg.BruteForce.Enabled = false
	cfg.Blacklist.Enabled = false
	log, _ := logger.New("warn", "json", "stderr")
	bl := blacklist.NewManager("")
	rl := rules.NewEngine("", false)

	srv, err := NewProxyServer(cfg, log, bl, rl)
	if err != nil {
		t.Fatal(err)
	}

	// Generate a valid challenge cookie for IP 10.0.0.1
	cookieVal := srv.ddosCC.GenerateTestCookie("10.0.0.1")

	// Verify that a request with the valid cookie gets through (high priority)
	// even when the normal pool could be contended.
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.Header.Set("Accept", "text/html")
	req.Header.Set("Accept-Language", "en-US")
	req.Header.Set("Accept-Encoding", "gzip")
	req.AddCookie(&http.Cookie{Name: "__shield_cc", Value: cookieVal})

	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("cookie user should get through (high priority), got status %d", w.Code)
	}
}

func TestProxy_WebshellBeforeSQLiForUploads(t *testing.T) {
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

	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	fw, _ := w.CreateFormFile("file", "shell.php")
	fw.Write([]byte("<?php system($_GET['cmd']); ?>"))
	w.Close()

	req, _ := http.NewRequest("POST", proxy.URL+"/upload", &buf)
	req.Header.Set("Content-Type", w.FormDataContentType())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for webshell upload, got %d", resp.StatusCode)
	}
	if reason := resp.Header.Get("X-Block-Reason"); reason != "webshell_upload" {
		t.Fatalf("expected X-Block-Reason=webshell_upload, got %s", reason)
	}
}
