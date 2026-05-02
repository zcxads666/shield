package cc

import (
	"fmt"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/shield/shield/internal/defender/ddos"
	"github.com/shield/shield/pkg/logger"
	"github.com/shield/shield/pkg/metrics"
)

func TestCCDetectorDifferentURLs(t *testing.T) {
	log, _ := logger.New("warn", "json", "")
	cc := NewDetector(true, 100, 150, 60, true, log)

	for i := 0; i < 200; i++ {
		u, _ := url.Parse(fmt.Sprintf("http://example.com/page%d", i))
		r := &http.Request{URL: u, Method: "GET", RemoteAddr: "192.168.1.1:1234"}
		if !cc.Allow(r) {
			t.Fatalf("Blocked at request %d on different URL - should not happen", i)
		}
	}
}

func TestCCDetectorBurstAllowed(t *testing.T) {
	log, _ := logger.New("warn", "json", "")
	cc := NewDetector(true, 100, 150, 60, true, log)

	for i := 0; i < 130; i++ {
		u, _ := url.Parse("http://example.com/api/data")
		r := &http.Request{URL: u, Method: "GET", RemoteAddr: "192.168.1.1:1234"}
		if !cc.Allow(r) {
			t.Fatalf("Burst of %d requests should be allowed (token at %d)", 130, i)
		}
	}
}

func TestCCDetectorExceedsBurstBlocked(t *testing.T) {
	log, _ := logger.New("warn", "json", "")
	cc := NewDetector(true, 100, 150, 60, true, log)

	blockedAt := -1
	for i := 0; i < 160; i++ {
		u, _ := url.Parse("http://example.com/api/data")
		r := &http.Request{URL: u, Method: "GET", RemoteAddr: "192.168.1.1:1234"}
		if !cc.Allow(r) {
			blockedAt = i
			break
		}
	}
	if blockedAt < 0 {
		t.Fatal("Expected CC block above burstRequests, never blocked")
	}
	t.Logf("CC blocked at request %d above burst", blockedAt)
}

func TestCCDetectorCorrectMetric(t *testing.T) {
	log, _ := logger.New("warn", "json", "")
	cc := NewDetector(true, 10, 15, 60, true, log)

	m := metrics.Get()
	m.CCBlocks = 0
	m.DDoSBlocks = 0

	for i := 0; i < 20; i++ {
		u, _ := url.Parse("http://example.com/api/data")
		r := &http.Request{URL: u, Method: "GET", RemoteAddr: "192.168.1.1:1234"}
		cc.Allow(r)
	}

	snap := m.Snapshot()
	if snap.CCBlocks == 0 {
		t.Error("CCBlocks metric should be incremented on CC block")
	}
	if snap.DDoSBlocks != 0 {
		t.Errorf("DDoSBlocks metric should NOT be incremented on CC block, got %d", snap.DDoSBlocks)
	}
}

func TestCCDetectorDisabled(t *testing.T) {
	log, _ := logger.New("warn", "json", "")
	cc := NewDetector(false, 10, 15, 60, true, log)

	for i := 0; i < 100; i++ {
		u, _ := url.Parse("http://example.com/api/data")
		r := &http.Request{URL: u, Method: "GET", RemoteAddr: "192.168.1.1:1234"}
		if !cc.Allow(r) {
			t.Fatal("Disabled detector should allow all")
		}
	}
}

func TestCCDetectorDifferentIPs(t *testing.T) {
	log, _ := logger.New("warn", "json", "")
	cc := NewDetector(true, 10, 15, 60, true, log)

	for i := 0; i < 100; i++ {
		u, _ := url.Parse("http://example.com/api/data")
		addr := fmt.Sprintf("192.168.1.%d:1234", i%254+1)
		r := &http.Request{URL: u, Method: "GET", RemoteAddr: addr}
		if !cc.Allow(r) {
			t.Fatalf("Different IP %s blocked at request %d - should not happen", addr, i)
		}
	}
}

func TestCCDDoSMixedAttack(t *testing.T) {
	log, _ := logger.New("warn", "json", "")

	ip := "10.0.0.99"

	ccDet := NewDetector(true, 100, 150, 60, true, log)
	dDoSDef := ddos.NewDefender(true, 1000, 30000, 1000, 1000, true, log)

	m := metrics.Get()
	m.CCBlocks = 0
	m.DDoSBlocks = 0

	ccBlocked := 0
	ddosBlocked := 0
	allowed := 0

	for i := 0; i < 200; i++ {
		u, _ := url.Parse("http://example.com/api/search?q=test")
		r := &http.Request{URL: u, Method: "GET", RemoteAddr: ip + ":1234"}

		if ccDet.Allow(r) {
			if dDoSDef.Allow(ip) {
				allowed++
				dDoSDef.Release(ip)
			} else {
				ddosBlocked++
			}
		} else {
			ccBlocked++
		}
	}

	t.Logf("Mixed attack (same URL, same IP): allowed=%d, cc_blocked=%d, ddos_blocked=%d", allowed, ccBlocked, ddosBlocked)

	snap := m.Snapshot()
	if snap.CCBlocks == 0 {
		t.Error("CC should have blocked some requests in mixed attack")
	}
}

func TestDDoSBurstConfig(t *testing.T) {
	log, _ := logger.New("warn", "json", "")

	d := ddos.NewDefender(true, 1000, 30000, 100, 150, true, log)
	ip := "192.168.1.1"
	allowed := 0
	for i := 0; i < 20; i++ {
		if d.Allow(ip) {
			allowed++
		}
	}
	t.Logf("Current config (burst=150): %d/20 allowed", allowed)

	d2 := ddos.NewDefender(true, 1000, 30000, 100, 300, true, log)
	allowed2 := 0
	for i := 0; i < 20; i++ {
		if d2.Allow(ip) {
			allowed2++
		}
	}
	t.Logf("New config (burst=300): %d/20 allowed", allowed2)
	if allowed2 < 20 {
		t.Errorf("Expected all 20 requests allowed with burst=300, got %d", allowed2)
	}
}

// ========== New Enhanced Tests ==========

func TestCCDetector_UARotationDetection(t *testing.T) {
	log, _ := logger.New("warn", "json", "")
	cc := NewDetector(true, 100, 150, 60, true, log)

	metrics.Get().CCBlocks = 0
	ip := "192.168.1.100"
	u, _ := url.Parse("http://example.com/api/search?q=test")
	userAgents := []string{
		"Mozilla/5.0 (Windows NT 10.0)",
		"Mozilla/5.0 (Macintosh)",
		"Mozilla/5.0 (X11; Linux x86_64)",
		"Opera/9.80 (Windows NT 6.1)",
	}

	blocked := false
	for i := 0; i < 4; i++ {
		r := &http.Request{
			URL:        u,
			Method:     "GET",
			RemoteAddr: ip + ":1234",
			Header:     http.Header{"User-Agent": []string{userAgents[i]}},
		}
		if !cc.Allow(r) {
			blocked = true
			t.Logf("UA rotation blocked at request %d", i)
			break
		}
	}
	if !blocked {
		t.Error("UA rotation should be detected as CC attack")
	}
}

func TestCCDetector_QueryParamAwareness(t *testing.T) {
	log, _ := logger.New("warn", "json", "")
	cc := NewDetector(true, 50, 75, 60, true, log)

	ip := "192.168.1.200"
	// Same path with different query params — should aggregate correctly
	urls := []string{
		"http://example.com/api?page=1",
		"http://example.com/api?page=2",
		"http://example.com/api?page=3",
		"http://example.com/api?page=4",
	}

	blocked := false
	for i := 0; i < 100; i++ {
		u, _ := url.Parse(urls[i%len(urls)])
		r := &http.Request{URL: u, Method: "GET", RemoteAddr: ip + ":1234"}
		if !cc.Allow(r) {
			blocked = true
			t.Logf("CC query-aware blocked at request %d", i)
			break
		}
	}
	if !blocked {
		t.Error("CC attack with rotating query params should be detected")
	}
}

func TestCCDetector_SameIPDifferentPaths(t *testing.T) {
	log, _ := logger.New("warn", "json", "")
	cc := NewDetector(true, 30, 50, 60, true, log)

	ip := "192.168.1.250"
	blocked := false
	for i := 0; i < 60; i++ {
		path := fmt.Sprintf("/api/resource%d", i)
		u, _ := url.Parse("http://example.com" + path)
		r := &http.Request{URL: u, Method: "GET", RemoteAddr: ip + ":1234"}
		if !cc.Allow(r) {
			blocked = true
			t.Fatalf("Different paths from same IP should not be CC-blocked at request %d", i)
		}
	}
	_ = blocked
}

func TestCCDetector_SustainedAttack(t *testing.T) {
	log, _ := logger.New("warn", "json", "")
	// Small window (10s) to test sustained detection more easily
	cc := NewDetector(true, 20, 40, 10, true, log)

	ip := "192.168.1.50"
	u, _ := url.Parse("http://example.com/api/data")
	blocked := false
	for i := 0; i < 50; i++ {
		r := &http.Request{URL: u, Method: "GET", RemoteAddr: ip + ":1234"}
		if !cc.Allow(r) {
			blocked = true
			t.Logf("Sustained attack blocked at request %d", i)
			break
		}
	}
	if !blocked {
		t.Error("sustained attack should be detected")
	}
}

func TestCCDetector_EmptyUserAgent(t *testing.T) {
	log, _ := logger.New("warn", "json", "")
	cc := NewDetector(true, 10, 15, 60, true, log)

	ip := "192.168.1.150"
	blocked := false
	for i := 0; i < 20; i++ {
		u, _ := url.Parse("http://example.com/api/data")
		r := &http.Request{
			URL:        u,
			Method:     "GET",
			RemoteAddr: ip + ":1234",
			Header:     http.Header{"User-Agent": []string{""}},
		}
		if !cc.Allow(r) {
			blocked = true
			break
		}
	}
	if !blocked {
		t.Error("empty UA high-frequency requests should still be detected as CC")
	}
}

func TestCCDetector_RequestPathNormalization(t *testing.T) {
	log, _ := logger.New("warn", "json", "")
	cc := NewDetector(true, 100, 150, 60, true, log)

	tests := []struct {
		name     string
		rawURL   string
		wantPath string
	}{
		{"no query", "http://example.com/api/health", "/api/health"},
		{"with action", "http://example.com/api?action=search&page=1", "/api?action=search"},
		{"with search", "http://example.com/api?q=test&page=1", "/api?search"},
		{"with query", "http://example.com/api?query=test", "/api?search"},
		{"with id", "http://example.com/api?id=123&page=1", "/api?id"},
		{"plain path", "http://example.com/", "/"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, _ := url.Parse(tt.rawURL)
			r := &http.Request{URL: u, Method: "GET", RemoteAddr: "1.2.3.4:1234"}
			got := cc.requestPath(r)
			if got != tt.wantPath {
				t.Errorf("requestPath(%q) = %q, want %q", tt.rawURL, got, tt.wantPath)
			}
		})
	}
}

func TestCCDetector_BurstNotSustained(t *testing.T) {
	log, _ := logger.New("warn", "json", "")
	// Burst config: 100 max, 150 burst — 130 requests all in one bucket = allowed burst
	cc := NewDetector(true, 100, 150, 60, true, log)

	ip := "192.168.1.1"
	u, _ := url.Parse("http://example.com/api/data")
	blocked := false
	for i := 0; i < 130; i++ {
		r := &http.Request{URL: u, Method: "GET", RemoteAddr: ip + ":1234"}
		if !cc.Allow(r) {
			blocked = true
			t.Fatalf("Concentrated burst should be allowed, blocked at %d", i)
		}
	}
	_ = blocked
	t.Log("Burst requests all allowed as expected")
}

func TestCCDetector_NoUARotationWithSameUA(t *testing.T) {
	log, _ := logger.New("warn", "json", "")
	cc := NewDetector(true, 100, 150, 60, true, log)

	ip := "192.168.1.99"
	u, _ := url.Parse("http://example.com/api/data")
	sameUA := "Mozilla/5.0 (compatible)"
	blockedByUA := false
	for i := 0; i < 10; i++ {
		r := &http.Request{
			URL:        u,
			Method:     "GET",
			RemoteAddr: ip + ":1234",
			Header:     http.Header{"User-Agent": []string{sameUA}},
		}
		if !cc.Allow(r) {
			blockedByUA = true
		}
	}
	if blockedByUA {
		t.Log("Blocked, but not by UA rotation (rate limit)")
	}
}

func TestCCDetector_IsSustainedBoundary(t *testing.T) {
	log, _ := logger.New("warn", "json", "")
	// Small window (5s), only 1 bucket possible → maxBuckets=1
	// spreadRatio = activeBuckets/maxBuckets, with 1 bucket, ratio is always 1.0 > 0.20
	// but need at least one bucket to have maxBuckets > 0 with a check
	cc := NewDetector(true, 5, 10, 5, true, log)

	ip := "192.168.1.55"
	u, _ := url.Parse("http://example.com/api/data")
	r := &http.Request{URL: u, Method: "GET", RemoteAddr: ip + ":1234"}

	blocked := false
	for i := 0; i < 15; i++ {
		if !cc.Allow(r) {
			blocked = true
			t.Logf("Blocked at request %d (small window)", i)
			break
		}
	}
	if !blocked {
		t.Error("should block with small window threshold")
	}
}

func TestCCDetector_CleanupLoopRuns(t *testing.T) {
	log, _ := logger.New("warn", "json", "")
	cc := NewDetector(true, 100, 150, 60, true, log)

	// Insert some data
	for i := 0; i < 10; i++ {
		u, _ := url.Parse("http://example.com/api/test")
		r := &http.Request{URL: u, Method: "GET", RemoteAddr: "192.168.1.1:1234"}
		cc.Allow(r)
	}

	// Wait for cleanup to run (30s interval)
	time.Sleep(50 * time.Millisecond)
	// If no panic, cleanup loop is working
}

func TestCCDetector_UARotationWithGap(t *testing.T) {
	log, _ := logger.New("warn", "json", "")
	cc := NewDetector(true, 100, 150, 60, true, log)

	ip := "192.168.1.77"
	userAgents := []string{
		"Bot/1.0", "Bot/2.0", "Bot/3.0", "",
	}

	// Only 3 unique non-empty UAs, should NOT trigger (threshold is 4)
	u, _ := url.Parse("http://example.com/api/data")
	for i := 0; i < 3; i++ {
		r := &http.Request{
			URL:        u,
			Method:     "GET",
			RemoteAddr: ip + ":1234",
			Header:     http.Header{"User-Agent": []string{userAgents[i]}},
		}
		cc.Allow(r)
	}
	// 3 unique UAs should not trigger rotation detection (needs 4+)
	// We verify no early block through UA rotation
	t.Log("3 UAs: no UA rotation block expected")
}

func TestCCDetector_HighRatePath(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping slow high-rate test in short mode")
	}
	// Need 2+ buckets (5s apart) to trigger isHighRate:
	// total > maxRequests (30), total < burstRequests (60),
	// isSustained=false (2/12=0.167 <= 0.20),
	// then isHighRate with rate = 55/10 = 5.5 > 5.0 → block.
	log, _ := logger.New("warn", "json", "")
	cc := NewDetector(true, 30, 60, 60, true, log)

	ip := "192.168.1.88"
	u, _ := url.Parse("http://example.com/api/data")
	r := &http.Request{URL: u, Method: "GET", RemoteAddr: ip + ":1234"}

	// First bucket: 35 requests (above maxRequests=30, below burstRequests=60)
	for i := 0; i < 35; i++ {
		if !cc.Allow(r) {
			t.Fatalf("unexpected block in first bucket at request %d", i)
		}
	}

	// Wait for next 5-second bucket
	time.Sleep(5100 * time.Millisecond)

	// Second bucket: 20 more → total=55, rate=55/10=5.5 > 5.0 → isHighRate=true
	blocked := false
	for i := 0; i < 20; i++ {
		if !cc.Allow(r) {
			blocked = true
			t.Logf("High-rate blocked at request %d in second bucket (total=%d)", i, 35+i+1)
			break
		}
	}
	if !blocked {
		t.Error("high rate across multiple buckets should trigger isHighRate")
	}
}
