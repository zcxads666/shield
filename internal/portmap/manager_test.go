package portmap

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shield/shield/internal/service/rules"
	"github.com/shield/shield/internal/storage/blacklist"
	"github.com/shield/shield/pkg/config"
	"github.com/shield/shield/pkg/logger"
)

func testLogger() *logger.Logger {
	l, _ := logger.New("debug", "text", "")
	return l
}

func TestValidateMappings(t *testing.T) {
	tests := []struct {
		name     string
		mappings []config.PortMappingItem
		wantErr  bool
		errMsg   string
	}{
		{
			name:     "valid",
			mappings: []config.PortMappingItem{{ID: "m1", Listen: ":9090", Target: "127.0.0.1:80"}},
			wantErr:  false,
		},
		{
			name:     "missing id",
			mappings: []config.PortMappingItem{{Listen: ":9090", Target: "127.0.0.1:80"}},
			wantErr:  true,
			errMsg:   "missing id",
		},
		{
			name:     "duplicate id",
			mappings: []config.PortMappingItem{
				{ID: "m1", Listen: ":9090", Target: "127.0.0.1:80"},
				{ID: "m1", Listen: ":9091", Target: "127.0.0.1:81"},
			},
			wantErr: true,
			errMsg:  "duplicate",
		},
		{
			name:     "missing listen",
			mappings: []config.PortMappingItem{{ID: "m1", Target: "127.0.0.1:80"}},
			wantErr:  true,
			errMsg:   "missing listen",
		},
		{
			name:     "missing target",
			mappings: []config.PortMappingItem{{ID: "m1", Listen: ":9090"}},
			wantErr:  true,
			errMsg:   "missing target",
		},
		{
			name:     "invalid target no port",
			mappings: []config.PortMappingItem{{ID: "m1", Listen: ":9090", Target: "127.0.0.1"}},
			wantErr:  true,
			errMsg:   "invalid target",
		},
		{
			name:     "invalid target no ip",
			mappings: []config.PortMappingItem{{ID: "m1", Listen: ":9090", Target: "abc:80"}},
			wantErr:  true,
			errMsg:   "invalid target",
		},
		{
			name:     "invalid target format",
			mappings: []config.PortMappingItem{{ID: "m1", Listen: ":9090", Target: "://bad"}},
			wantErr:  true,
			errMsg:   "invalid target",
		},
		{
			name:     "empty list",
			mappings: []config.PortMappingItem{},
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateMappings(tt.mappings)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				imports := err.Error()
				if !contains(imports, tt.errMsg) {
					t.Fatalf("expected error containing %q, got %q", tt.errMsg, err.Error())
				}
			} else if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestManager_StartStop(t *testing.T) {
	port := getTestPort()

	// Start a mock backend
	backendPort := port + 1
	var backendHits int32
	backend := &http.Server{
		Addr: fmt.Sprintf("127.0.0.1:%d", backendPort),
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&backendHits, 1)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"msg": "ok"})
		}),
	}
	go backend.ListenAndServe()
	defer backend.Close()
	time.Sleep(100 * time.Millisecond)

	lg := testLogger()
	bl := blacklist.NewManager("")
	rl := rules.NewEngine("", false)

	fullCfg := &config.Config{
		Server: config.ServerConfig{
			BindAddr:       fmt.Sprintf("127.0.0.1:%d", port),
			ReadTimeoutMs:  30000,
			WriteTimeoutMs: 30000,
			MaxHeaderBytes: 1 << 20,
			MaxBodySize:    10 << 20,
			MaxConcurrent:  100,
			QueueTimeoutMs: 5000,
		},
		Proxy: config.ProxyConfig{
			TargetURL:      fmt.Sprintf("http://127.0.0.1:%d", backendPort),
			TrustForwarded: false,
		},
		RateLimit:    config.RateLimitConfig{Enabled: false},
		DDoSCC:       config.DDoSCCConfig{Enabled: false},
		SQLInject:    config.SQLInjectConfig{Enabled: false},
		XSS:          config.XSSConfig{Enabled: false},
		Upload:       config.UploadConfig{Enabled: false},
		BruteForce:   config.BruteForceConfig{Enabled: false},
		WaitingRoom:  config.WaitingRoomConfig{Enabled: false},
		Blacklist:    config.BlacklistConfig{Enabled: false},
		Log:          config.LogConfig{Level: "debug", Format: "text", OutputPath: ""},
	}

	mgr := NewManager(lg)
	mappings := []config.PortMappingItem{
		{
			ID:     "test-map",
			Listen: fmt.Sprintf("127.0.0.1:%d", port),
			Target: fmt.Sprintf("127.0.0.1:%d", backendPort),
		},
	}

	if err := mgr.Start(mappings, fullCfg, lg, bl, rl); err != nil {
		t.Fatalf("start failed: %v", err)
	}
	time.Sleep(200 * time.Millisecond)

	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/hello", port))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !contains(string(body), "ok") {
		t.Fatalf("unexpected body: %s", string(body))
	}
	if atomic.LoadInt32(&backendHits) == 0 {
		t.Fatal("backend was not hit")
	}

	mgr.Stop()

	// Verify listener is stopped
	_, err = http.Get(fmt.Sprintf("http://127.0.0.1:%d/hello", port))
	if err == nil {
		t.Fatal("expected connection refused after stop")
	}
}

var testPortCounter int32 = 18000

func getTestPort() int {
	return int(atomic.AddInt32(&testPortCounter, 1))
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && search(s, substr)
}

func search(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
