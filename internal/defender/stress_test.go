package defender

import (
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/shield/shield/internal/logger"
)

func TestDDoSConcurrentBurst(t *testing.T) {
	log, _ := logger.New("warn", "json", "")
	
	// Test with burst=150 at high concurrency
	ddos := NewDDoSDefender(true, 1000, 30000, 100, 150, true, log)
	ip := "192.168.1.1"
	
	var wg sync.WaitGroup
	allowed := 0
	blocked := 0
	var mu sync.Mutex
	
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if ddos.Allow(ip) {
				mu.Lock()
				allowed++
				mu.Unlock()
				// Hold connection for a bit
				time.Sleep(10 * time.Millisecond)
				ddos.Release(ip)
			} else {
				mu.Lock()
				blocked++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	t.Logf("burst=150: allowed=%d, blocked=%d (50 concurrent)", allowed, blocked)
}

func TestDDoSConcurrentBurst300(t *testing.T) {
	log, _ := logger.New("warn", "json", "")
	
	// Test with burst=300 at high concurrency
	ddos := NewDDoSDefender(true, 1000, 30000, 100, 300, true, log)
	ip := "192.168.1.1"
	
	var wg sync.WaitGroup
	allowed := 0
	blocked := 0
	var mu sync.Mutex
	
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if ddos.Allow(ip) {
				mu.Lock()
				allowed++
				mu.Unlock()
				// Hold connection for a bit
				time.Sleep(10 * time.Millisecond)
				ddos.Release(ip)
			} else {
				mu.Lock()
				blocked++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	t.Logf("burst=300: allowed=%d, blocked=%d (50 concurrent)", allowed, blocked)
}

func TestCCDetectorConcurrentBurst(t *testing.T) {
	log, _ := logger.New("warn", "json", "")
	cc := NewCCDetector(true, 100, 60, true, log)
	
	// 20 concurrent requests to different URLs - should all pass
	var wg sync.WaitGroup
	blocked := 0
	var mu sync.Mutex
	
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			u, _ := url.Parse(fmt.Sprintf("http://example.com/page%d", idx))
			r := &http.Request{URL: u, Method: "GET"}
			if !cc.Allow(r) {
				mu.Lock()
				blocked++
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()
	t.Logf("CC different URLs: blocked=%d/20", blocked)
	if blocked > 0 {
		t.Errorf("CC should not block different URLs, blocked=%d", blocked)
	}
}
