package config

import (
	"os"
	"testing"
)

func TestManager_OnChange(t *testing.T) {
	content := `
server:
  bind_addr: ":9090"
`
	f, err := os.CreateTemp("", "config*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.WriteString(content)
	f.Close()

	m := NewManager(f.Name())
	called := false
	m.OnChange(func(cfg *Config) {
		called = true
	})
	if err := m.Load(); err != nil {
		t.Fatalf("load failed: %v", err)
	}
	if !called {
		t.Fatal("expected OnChange callback to be called")
	}
}

func TestManager_Path(t *testing.T) {
	m := NewManager("/tmp/test.yaml")
	if m.Path() != "/tmp/test.yaml" {
		t.Fatalf("unexpected path: %s", m.Path())
	}
}

func TestManager_LoadInvalidYAML(t *testing.T) {
	f, err := os.CreateTemp("", "config*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.WriteString("not: valid: yaml: [")
	f.Close()

	m := NewManager(f.Name())
	if err := m.Load(); err == nil {
		t.Fatal("expected error for invalid yaml")
	}
}

func TestManager_LoadMissingFile(t *testing.T) {
	m := NewManager("/tmp/nonexistent_config_12345.yaml")
	if err := m.Load(); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestDefaults_All(t *testing.T) {
	f, err := os.CreateTemp("", "config*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.WriteString("server: {}\n")
	f.Close()

	m := NewManager(f.Name())
	if err := m.Load(); err != nil {
		t.Fatal(err)
	}
	cfg := m.Get()

	if cfg.Server.BindAddr != ":8080" {
		t.Errorf("unexpected bind: %s", cfg.Server.BindAddr)
	}
	if cfg.Server.ReadTimeoutMs != 30000 {
		t.Errorf("unexpected read timeout: %d", cfg.Server.ReadTimeoutMs)
	}
	if cfg.Server.WriteTimeoutMs != 30000 {
		t.Errorf("unexpected write timeout: %d", cfg.Server.WriteTimeoutMs)
	}
	if cfg.Server.MaxHeaderBytes != 1<<20 {
		t.Errorf("unexpected max header bytes: %d", cfg.Server.MaxHeaderBytes)
	}
	if cfg.Server.AdminBindAddr != ":9090" {
		t.Errorf("unexpected admin bind: %s", cfg.Server.AdminBindAddr)
	}
	if cfg.Proxy.TargetURL != "http://127.0.0.1:80" {
		t.Errorf("unexpected target: %s", cfg.Proxy.TargetURL)
	}
	if cfg.RateLimit.RequestsPerSecond != 100 {
		t.Errorf("unexpected rps: %d", cfg.RateLimit.RequestsPerSecond)
	}
	if cfg.RateLimit.BurstSize != 150 {
		t.Errorf("unexpected burst: %d", cfg.RateLimit.BurstSize)
	}
	if cfg.RateLimit.BlockDurationSec != 300 {
		t.Errorf("unexpected block duration: %d", cfg.RateLimit.BlockDurationSec)
	}
	if cfg.DDoS.MaxConnectionsPerIP != 1000 {
		t.Errorf("unexpected max conn: %d", cfg.DDoS.MaxConnectionsPerIP)
	}
	if cfg.DDoS.SlowlorisTimeoutMs != 30000 {
		t.Errorf("unexpected slowloris timeout: %d", cfg.DDoS.SlowlorisTimeoutMs)
	}
	if cfg.BruteForce.MaxFailures != 5 {
		t.Errorf("unexpected max failures: %d", cfg.BruteForce.MaxFailures)
	}
	if cfg.BruteForce.WindowSec != 60 {
		t.Errorf("unexpected window: %d", cfg.BruteForce.WindowSec)
	}
	if cfg.BruteForce.BlockDurationSec != 600 {
		t.Errorf("unexpected block duration: %d", cfg.BruteForce.BlockDurationSec)
	}
	if cfg.Log.Level != "info" {
		t.Errorf("unexpected log level: %s", cfg.Log.Level)
	}
	if cfg.Log.Format != "json" {
		t.Errorf("unexpected log format: %s", cfg.Log.Format)
	}
	if cfg.Log.OutputPath != "./logs/shield.log" {
		t.Errorf("unexpected log path: %s", cfg.Log.OutputPath)
	}
	if cfg.Log.MaxSizeMB != 100 {
		t.Errorf("unexpected max size: %d", cfg.Log.MaxSizeMB)
	}
	if cfg.Log.MaxBackups != 7 {
		t.Errorf("unexpected max backups: %d", cfg.Log.MaxBackups)
	}
	if cfg.Log.MaxAgeDays != 30 {
		t.Errorf("unexpected max age: %d", cfg.Log.MaxAgeDays)
	}
	if cfg.Rules.ReloadIntervalSec != 3 {
		t.Errorf("unexpected reload interval: %d", cfg.Rules.ReloadIntervalSec)
	}
}
