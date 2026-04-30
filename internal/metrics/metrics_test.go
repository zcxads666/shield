package metrics

import (
	"sync"
	"testing"
)

func TestMetrics_Increment(t *testing.T) {
	m := &Metrics{}

	m.IncTotalRequests()
	m.IncTotalRequests()
	if m.TotalRequests != 2 {
		t.Fatalf("expected total=2, got %d", m.TotalRequests)
	}

	m.IncBlockedRequests()
	if m.BlockedRequests != 1 {
		t.Fatalf("expected blocked=1, got %d", m.BlockedRequests)
	}

	m.IncAllowedRequests()
	if m.AllowedRequests != 1 {
		t.Fatalf("expected allowed=1, got %d", m.AllowedRequests)
	}

	m.IncSQLInjections()
	if m.SQLInjections != 1 {
		t.Fatalf("expected sql=1, got %d", m.SQLInjections)
	}

	m.IncXSSAttempts()
	if m.XSSAttempts != 1 {
		t.Fatalf("expected xss=1, got %d", m.XSSAttempts)
	}

	m.IncBruteForceBlocks()
	if m.BruteForceBlocks != 1 {
		t.Fatalf("expected bruteforce=1, got %d", m.BruteForceBlocks)
	}

	m.IncDDoSBlocks()
	if m.DDoSBlocks != 1 {
		t.Fatalf("expected ddos=1, got %d", m.DDoSBlocks)
	}
}

func TestMetrics_ActiveConnections(t *testing.T) {
	m := &Metrics{}

	m.AddActiveConnections(5)
	if m.ActiveConnections != 5 {
		t.Fatalf("expected active=5, got %d", m.ActiveConnections)
	}

	m.AddActiveConnections(-2)
	if m.ActiveConnections != 3 {
		t.Fatalf("expected active=3, got %d", m.ActiveConnections)
	}
}

func TestMetrics_SetBlacklistedIPs(t *testing.T) {
	m := &Metrics{}
	m.SetBlacklistedIPs(42)
	if m.BlacklistedIPs != 42 {
		t.Fatalf("expected 42, got %d", m.BlacklistedIPs)
	}
}

func TestMetrics_Snapshot(t *testing.T) {
	m := &Metrics{}
	m.IncTotalRequests()
	m.IncBlockedRequests()
	m.SetBlacklistedIPs(10)

	snap := m.Snapshot()
	if snap.TotalRequests != 1 {
		t.Fatalf("expected snap total=1, got %d", snap.TotalRequests)
	}
	if snap.BlockedRequests != 1 {
		t.Fatalf("expected snap blocked=1, got %d", snap.BlockedRequests)
	}
	if snap.BlacklistedIPs != 10 {
		t.Fatalf("expected snap blacklist=10, got %d", snap.BlacklistedIPs)
	}
}

func TestMetrics_Concurrent(t *testing.T) {
	m := &Metrics{}
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.IncTotalRequests()
			m.IncBlockedRequests()
			m.AddActiveConnections(1)
			m.AddActiveConnections(-1)
		}()
	}
	wg.Wait()

	if m.TotalRequests != 100 {
		t.Fatalf("expected total=100, got %d", m.TotalRequests)
	}
	if m.BlockedRequests != 100 {
		t.Fatalf("expected blocked=100, got %d", m.BlockedRequests)
	}
}

func BenchmarkMetrics_IncTotalRequests(b *testing.B) {
	m := &Metrics{}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.IncTotalRequests()
	}
}

func BenchmarkMetrics_Snapshot(b *testing.B) {
	m := &Metrics{}
	m.IncTotalRequests()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = m.Snapshot()
	}
}
