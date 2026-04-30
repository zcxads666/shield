package blacklist

import (
	"os"
	"testing"
	"time"
)

func TestBlacklistManager(t *testing.T) {
	path := "/tmp/test_blacklist.json"
	defer os.Remove(path)

	m := NewManager(path)
	m.Add("1.2.3.4", "test", time.Hour, false)
	if !m.IsBlocked("1.2.3.4") {
		t.Fatal("expected blocked")
	}
	if m.IsBlocked("5.6.7.8") {
		t.Fatal("expected not blocked")
	}

	m.Remove("1.2.3.4")
	if m.IsBlocked("1.2.3.4") {
		t.Fatal("expected not blocked after remove")
	}
}

func TestGetClientIP(t *testing.T) {
	ip := GetClientIP("192.168.1.1:12345", map[string][]string{
		"X-Forwarded-For": {"10.0.0.1"},
	}, true)
	if ip != "10.0.0.1" {
		t.Fatalf("expected 10.0.0.1, got %s", ip)
	}

	ip = GetClientIP("192.168.1.1:12345", nil, false)
	if ip != "192.168.1.1" {
		t.Fatalf("expected 192.168.1.1, got %s", ip)
	}
}
