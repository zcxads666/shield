package cc

import (
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"github.com/shield/shield/internal/defender/ddos"
	"github.com/shield/shield/pkg/logger"
)

func TestCCDetectorDifferentURLs(t *testing.T) {
	log, _ := logger.New("warn", "json", "")
	cc := NewDetector(true, 100, 60, true, log)

	// Simulate normal browsing: different URLs should all be allowed
	for i := 0; i < 200; i++ {
		u, _ := url.Parse(fmt.Sprintf("http://example.com/page%d", i))
		r := &http.Request{URL: u, Method: "GET"}
		if !cc.Allow(r) {
			t.Fatalf("Blocked at request %d on different URL - should not happen", i)
		}
	}
}

func TestCCDetectorSameURL(t *testing.T) {
	log, _ := logger.New("warn", "json", "")
	cc := NewDetector(true, 100, 60, true, log)

	// Simulate CC attack: same URL should block after 100
	blockedAt := -1
	for i := 0; i < 110; i++ {
		u, _ := url.Parse("http://example.com/api/data")
		r := &http.Request{URL: u, Method: "GET"}
		if !cc.Allow(r) {
			blockedAt = i
			break
		}
	}
	if blockedAt < 0 {
		t.Fatalf("Expected CC block on same URL, never blocked")
	}
	t.Logf("CC blocked at request %d on same URL", blockedAt)
}

func TestDDoSBurstConfig(t *testing.T) {
	log, _ := logger.New("warn", "json", "")
	
	// Current config: burst=150 - should allow 20 concurrent
	d := ddos.NewDefender(true, 1000, 30000, 100, 150, true, log)
	ip := "192.168.1.1"
	allowed := 0
	for i := 0; i < 20; i++ {
		if d.Allow(ip) {
			allowed++
		}
	}
	t.Logf("Current config (burst=150): %d/20 allowed", allowed)
	
	// New config: burst=300 - should also allow 20 concurrent
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
