package proxy

import (
    "fmt"
    "io"
    "net/http"
    "net/http/httptest"
    "testing"

    "github.com/shield/shield/internal/blacklist"
    "github.com/shield/shield/internal/logger"
    "github.com/shield/shield/internal/rules"
)

func TestProxy_XSS_Erb_Live(t *testing.T) {
    backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

    testCases := []struct {
        name       string
        rawQuery   string
        wantStatus int
    }{
        {"script_tag", "content=%3Cscript%3Ealert%281%29%3C%2Fscript%3E", 403},
        {"erb_plus", "content=%3C%25%3D+alert%281%29+%25%3E", 403},
        {"erb_space", "content=%3C%25%3D%20alert%281%29%20%25%3E", 403},
        {"erb_nospace", "content=%3C%25%3Dalert%281%29%25%3E", 403},
    }

    for _, tc := range testCases {
        t.Run(tc.name, func(t *testing.T) {
            resp, err := http.Get(p.URL + "/?" + tc.rawQuery)
            if err != nil {
                t.Fatalf("request failed: %v", err)
            }
            body, _ := io.ReadAll(resp.Body)
            resp.Body.Close()
            fmt.Printf("Test %s: status=%d body=%s\n", tc.name, resp.StatusCode, string(body))
            if resp.StatusCode != tc.wantStatus {
                t.Errorf("status=%d, want %d", resp.StatusCode, tc.wantStatus)
            }
        })
    }
}
