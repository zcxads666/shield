package config

import (
	"os"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	content := `
server:
  bind_addr: ":9090"
proxy:
  target_url: "http://localhost:3000"
rate_limit:
  enabled: true
  requests_per_second: 50
`
	f, err := os.CreateTemp("", "config*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.WriteString(content)
	f.Close()

	m := NewManager(f.Name())
	if err := m.Load(); err != nil {
		t.Fatalf("load failed: %v", err)
	}
	cfg := m.Get()
	if cfg.Server.BindAddr != ":9090" {
		t.Fatalf("unexpected bind_addr: %s", cfg.Server.BindAddr)
	}
	if cfg.RateLimit.RequestsPerSecond != 50 {
		t.Fatalf("unexpected rps: %d", cfg.RateLimit.RequestsPerSecond)
	}
	if cfg.RateLimit.BurstSize != 30 { // default burst
		t.Fatalf("unexpected burst: %d", cfg.RateLimit.BurstSize)
	}
}

func TestDefaults(t *testing.T) {
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
		t.Fatalf("unexpected default bind: %s", cfg.Server.BindAddr)
	}
}
