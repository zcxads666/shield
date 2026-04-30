package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/shield/shield/internal/blacklist"
	"github.com/shield/shield/internal/logger"
	"github.com/shield/shield/internal/rules"
)

func TestProxy_XSS_Erb(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Logf("Backend: Method=%s, URL=%s, Query=%v", r.Method, r.URL.String(), r.URL.Query())
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer backend.Close()

	cfg := newTestConfig()
	cfg.Proxy.TargetURL = backend.URL
	log, _ := logger.New("warn", "json", "stderr")
	bl := blacklist.NewManager("")
	rl := rules.NewEngine("", false)

	srv, err := NewServer(cfg, log, bl, rl)
	if err != nil {
		t.Fatal(err)
	}

	p := httptest.NewServer(srv.Handler())
	defer p.Close()

	// Test ERB payload via GET with raw URL
	resp, err := http.Get(p.URL + "/?content=<%=+alert(1)+%>")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	t.Logf("ERB GET Status: %d, Body: %s", resp.StatusCode, string(body))
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for ERB XSS via GET, got %d", resp.StatusCode)
	}
}
