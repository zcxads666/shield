package blacklist

import (
	"os"
	"testing"
	"time"
)

func TestBlacklist_Persistence(t *testing.T) {
	path := "/tmp/test_blacklist_persist.json"
	defer os.Remove(path)

	m := NewManager(path)
	m.Add("1.2.3.4", "test", time.Hour, false)
	m.Add("5.6.7.8", "permanent", 0, true)

	// Create new manager pointing to same file
	m2 := NewManager(path)
	if !m2.IsBlocked("1.2.3.4") {
		t.Fatal("expected 1.2.3.4 blocked after reload")
	}
	if !m2.IsBlocked("5.6.7.8") {
		t.Fatal("expected 5.6.7.8 blocked after reload")
	}
}

func TestBlacklist_Expiration(t *testing.T) {
	path := "/tmp/test_blacklist_expire.json"
	defer os.Remove(path)

	m := NewManager(path)
	m.Add("1.2.3.4", "test", 50*time.Millisecond, false)
	if !m.IsBlocked("1.2.3.4") {
		t.Fatal("expected blocked immediately")
	}

	time.Sleep(100 * time.Millisecond)
	if m.IsBlocked("1.2.3.4") {
		t.Fatal("expected not blocked after expiration")
	}
}

func TestBlacklist_List(t *testing.T) {
	path := "/tmp/test_blacklist_list.json"
	defer os.Remove(path)

	m := NewManager(path)
	m.Add("1.2.3.4", "test1", time.Hour, false)
	m.Add("5.6.7.8", "test2", time.Hour, false)

	list := m.List()
	if len(list) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(list))
	}
}

func TestBlacklist_ListExpiredFiltered(t *testing.T) {
	path := "/tmp/test_blacklist_list_filter.json"
	defer os.Remove(path)

	m := NewManager(path)
	m.Add("1.2.3.4", "active", time.Hour, false)
	m.Add("5.6.7.8", "expired", 50*time.Millisecond, false)

	time.Sleep(100 * time.Millisecond)
	list := m.List()
	if len(list) != 1 {
		t.Fatalf("expected 1 active entry, got %d", len(list))
	}
}

func TestBlacklist_Cleanup(t *testing.T) {
	path := "/tmp/test_blacklist_cleanup.json"
	defer os.Remove(path)

	m := NewManager(path)
	m.Add("1.2.3.4", "expired", 50*time.Millisecond, false)
	m.Add("5.6.7.8", "active", time.Hour, false)

	time.Sleep(100 * time.Millisecond)
	m.Cleanup()

	if m.IsBlocked("1.2.3.4") {
		t.Fatal("expected expired entry removed after cleanup")
	}
	if !m.IsBlocked("5.6.7.8") {
		t.Fatal("expected active entry still blocked")
	}
}

func TestBlacklist_GetClientIP_NoPort(t *testing.T) {
	ip := GetClientIP("192.168.1.1", nil, false)
	if ip != "192.168.1.1" {
		t.Fatalf("expected 192.168.1.1, got %s", ip)
	}
}

func TestBlacklist_GetClientIP_XRealIP(t *testing.T) {
	ip := GetClientIP("192.168.1.1:12345", map[string][]string{
		"X-Real-Ip": {"10.0.0.2"},
	}, true)
	if ip != "10.0.0.2" {
		t.Fatalf("expected 10.0.0.2, got %s", ip)
	}
}

func TestBlacklist_LoadInvalidJSON(t *testing.T) {
	path := "/tmp/test_blacklist_invalid.json"
	defer os.Remove(path)
	os.WriteFile(path, []byte("not json"), 0644)

	m := NewManager(path)
	// Should not panic, just have empty list
	if m.IsBlocked("1.2.3.4") {
		t.Fatal("expected empty blacklist after invalid json")
	}
}

func BenchmarkBlacklist_IsBlocked(b *testing.B) {
	m := NewManager("")
	m.Add("192.168.1.1", "test", time.Hour, false)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.IsBlocked("192.168.1.1")
	}
}
