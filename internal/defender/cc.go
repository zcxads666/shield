package defender

import (
	"net/http"
	"sync"
	"time"

	"github.com/shield/shield/internal/blacklist"
	"github.com/shield/shield/internal/logger"
	"github.com/shield/shield/internal/metrics"
)

// CCDetector detects application-layer CC (Challenge Collapsar) attacks.
// Unlike DDoS (network/connection layer), CC attacks target specific URLs
// with high-frequency legitimate-looking HTTP requests.
type CCDetector struct {
	enabled        bool
	maxRequests    int           // max requests per path per window
	window         time.Duration // detection window
	logger         *logger.Logger
	trustForwarded bool

	mu       sync.RWMutex
	requests map[string]*pathRequests // key: ip+path
}

type pathRequests struct {
	count  int
	times  []time.Time
}

// NewCCDetector creates a CC attack detector.
func NewCCDetector(enabled bool, maxRequests int, windowSec int, trustForwarded bool, log *logger.Logger) *CCDetector {
	c := &CCDetector{
		enabled:        enabled,
		maxRequests:    maxRequests,
		window:         time.Duration(windowSec) * time.Second,
		logger:         log,
		trustForwarded: trustForwarded,
		requests:       make(map[string]*pathRequests),
	}
	go c.cleanupLoop()
	return c
}

// Allow checks if a request should be allowed.
// Returns true if the request is NOT a CC attack.
func (c *CCDetector) Allow(r *http.Request) bool {
	if !c.enabled {
		return true
	}

	ip := blacklist.GetClientIP(r.RemoteAddr, r.Header, c.trustForwarded)
	path := r.URL.Path
	key := ip + "|" + path

	c.mu.Lock()
	defer c.mu.Unlock()

	pr, ok := c.requests[key]
	if !ok {
		pr = &pathRequests{times: make([]time.Time, 0, c.maxRequests+1)}
		c.requests[key] = pr
	}

	now := time.Now()
	// Remove old entries outside the window
	cutoff := now.Add(-c.window)
	newIdx := len(pr.times)
	for i, t := range pr.times {
		if t.After(cutoff) {
			newIdx = i
			break
		}
	}
	pr.times = pr.times[newIdx:]
	pr.count = len(pr.times)

	// Check if limit exceeded
	if pr.count >= c.maxRequests {
		metrics.Get().IncDDoSBlocks()
		if c.logger != nil {
			c.logger.Warn("cc_attack_detected", map[string]interface{}{
				"ip":   ip,
				"path": path,
				"count": pr.count,
			})
		}
		return false
	}

	pr.times = append(pr.times, now)
	pr.count++
	return true
}

func (c *CCDetector) cleanupLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		c.mu.Lock()
		now := time.Now()
		cutoff := now.Add(-c.window)
		for key, pr := range c.requests {
			newIdx := 0
			for i, t := range pr.times {
				if t.After(cutoff) {
					newIdx = i
					break
				}
			}
			pr.times = pr.times[newIdx:]
			pr.count = len(pr.times)
			if pr.count == 0 {
				delete(c.requests, key)
			}
		}
		c.mu.Unlock()
	}
}
