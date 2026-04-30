package proxy

import (
    "fmt"
    "io"
    "net/http"
    "net/http/httptest"
    "strings"
    "testing"

    "github.com/shield/shield/internal/blacklist"
    "github.com/shield/shield/internal/logger"
    "github.com/shield/shield/internal/rules"
)

func TestProxy_XSS_PostBody2(t *testing.T) {
    backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        fmt.Printf("Backend: Method=%s, Content-Type=%s\n", r.Method, r.Header.Get("Content-Type"))
        w.WriteHeader(http.StatusOK)
        fmt.Fprint(w, "ok")
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

    // Test POST with URL-encoded ERB body
    resp, err := http.Post(p.URL+"/", "application/x-www-form-urlencoded",
        strings.NewReader("content=%3C%25%3Dalert%281%29%25%3E"))
    if err != nil {
        t.Fatalf("request failed: %v", err)
    }
    body, _ := io.ReadAll(resp.Body)
    resp.Body.Close()
    fmt.Printf("POST encoded ERB: status=%d body=%s\n", resp.StatusCode, string(body))
    
    if resp.StatusCode != 403 {
        t.Errorf("Expected 403 for POST ERB, got %d", resp.StatusCode)
    }
}
