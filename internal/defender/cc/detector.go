package cc

import (
	"net/http"
	"sync"
	"time"

	"github.com/shield/shield/internal/storage/blacklist"
	"github.com/shield/shield/pkg/logger"
	"github.com/shield/shield/pkg/metrics"
)

// Detector detects application-layer CC (Challenge Collapsar) attacks.
// Unlike DDoS (network/connection layer), CC attacks target specific URLs
// with high-frequency legitimate-looking HTTP requests.
type Detector struct {
	enabled        bool
	maxRequests    int
	burstRequests  int
	window         time.Duration
	logger         *logger.Logger
	trustForwarded bool

	mu       sync.RWMutex
	requests map[string]*pathRequests // key: ip|path

	// User-Agent tracking for rotation detection
	uaMu  sync.Mutex
	uaMap map[string]*uaTracker // key: ip|path
}

const bucketSize = 5 * time.Second

type bucket struct {
	count int
	start time.Time
}

type pathRequests struct {
	buckets []bucket
	total   int
}

// uaTracker tracks user-agent rotation per IP+path for CC detection.
type uaTracker struct {
	agents map[string]int
	lastSeen time.Time
}

// NewDetector creates a CC attack detector.
func NewDetector(enabled bool, maxRequests, burstRequests, windowSec int, trustForwarded bool, log *logger.Logger) *Detector {
	if burstRequests < maxRequests {
		burstRequests = maxRequests
	}
	c := &Detector{
		enabled:        enabled,
		maxRequests:    maxRequests,
		burstRequests:  burstRequests,
		window:         time.Duration(windowSec) * time.Second,
		logger:         log,
		trustForwarded: trustForwarded,
		requests:       make(map[string]*pathRequests),
		uaMap:          make(map[string]*uaTracker),
	}
	go c.cleanupLoop()
	return c
}

// Allow checks if a request should be allowed.
func (c *Detector) Allow(r *http.Request) bool {
	if !c.enabled {
		return true
	}

	ip := blacklist.GetClientIP(r.RemoteAddr, r.Header, c.trustForwarded)
	path := c.requestPath(r)
	key := ip + "|" + path

	// User-Agent rotation detection: many different UAs = CC attack
	if c.detectUARotation(key, r) {
		metrics.Get().IncCCBlocks()
		if c.logger != nil {
			c.logger.Warn("cc_attack_detected", map[string]interface{}{
				"ip":     ip,
				"path":   path,
				"reason": "ua_rotation",
			})
		}
		return false
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	pr, ok := c.requests[key]
	if !ok {
		pr = &pathRequests{}
		c.requests[key] = pr
	}

	now := time.Now()
	cutoff := now.Add(-c.window)

	// Prune expired buckets
	valid := pr.buckets[:0]
	total := 0
	for _, b := range pr.buckets {
		if b.start.After(cutoff) || b.start.Equal(cutoff) {
			valid = append(valid, b)
			total += b.count
		}
	}
	pr.buckets = valid
	pr.total = total

	// Check burst threshold: block if above burstRequests
	if pr.total >= c.burstRequests {
		metrics.Get().IncCCBlocks()
		if c.logger != nil {
			c.logger.Warn("cc_attack_detected", map[string]interface{}{
				"ip":    ip,
				"path":  path,
				"count": pr.total,
			})
		}
		return false
	}

	// Sustained attack detection: above maxRequests and temporally spread
	if pr.total >= c.maxRequests {
		if c.isSustained(pr, now, cutoff) {
			metrics.Get().IncCCBlocks()
			if c.logger != nil {
				c.logger.Warn("cc_attack_detected", map[string]interface{}{
					"ip":     ip,
					"path":   path,
					"count":  pr.total,
					"reason": "sustained",
				})
			}
			return false
		}
		// High rate check across multiple buckets
		if c.isHighRate(pr) {
			metrics.Get().IncCCBlocks()
			if c.logger != nil {
				c.logger.Warn("cc_attack_detected", map[string]interface{}{
					"ip":     ip,
					"path":   path,
					"count":  pr.total,
					"reason": "high_rate",
				})
			}
			return false
		}
	}

	// Record this request in the current bucket
	c.addToBucket(pr, now)

	return true
}

// requestPath returns the URL path with normalized query string for CC detection.
// Query parameters that uniquely identify requests are normalized so that CC
// attacks on the same endpoint with different params are correctly aggregated.
func (c *Detector) requestPath(r *http.Request) string {
	path := r.URL.Path
	if r.URL.RawQuery == "" {
		return path
	}
	// Normalize: keep path but strip cache-busting params to group CC attacks
	// on the same endpoint. We preserve the first query key to differentiate
	// between different endpoints (e.g., /api?action=search vs /api?action=login).
	q := r.URL.Query()
	if q.Has("action") {
		path += "?action=" + q.Get("action")
	} else if q.Has("q") || q.Has("query") || q.Has("search") {
		path += "?search"
	} else if q.Has("id") {
		path += "?id"
	} else if len(q) > 0 {
		// Has query params but not known ones — group by first key
		for k := range q {
			path += "?" + k
			break
		}
	}
	return path
}

// detectUARotation checks if the IP is rotating user agents rapidly,
// which is a strong indicator of a CC attack.
func (c *Detector) detectUARotation(key string, r *http.Request) bool {
	ua := r.Header.Get("User-Agent")
	if ua == "" {
		return false
	}

	c.uaMu.Lock()
	defer c.uaMu.Unlock()

	tr, ok := c.uaMap[key]
	if !ok || time.Since(tr.lastSeen) > c.window {
		tr = &uaTracker{
			agents:   make(map[string]int),
			lastSeen: time.Now(),
		}
		c.uaMap[key] = tr
	}
	tr.agents[ua]++
	tr.lastSeen = time.Now()

	// 4+ different user agents from same IP+path in window = CC attack
	return len(tr.agents) >= 4
}

// isSustained returns true if requests are spread across time (sustained attack).
func (c *Detector) isSustained(pr *pathRequests, now, cutoff time.Time) bool {
	if len(pr.buckets) == 0 {
		return false
	}

	maxBuckets := int(c.window / bucketSize)
	if maxBuckets < 1 {
		maxBuckets = 1
	}
	activeBuckets := 0
	for _, b := range pr.buckets {
		if b.count > 0 {
			activeBuckets++
		}
	}

	// >20% spread = sustained attack (lowered from 25% for better sensitivity)
	spreadRatio := float64(activeBuckets) / float64(maxBuckets)
	return spreadRatio > 0.20
}

// isHighRate returns true if the request rate exceeds 5 req/s across multiple buckets.
func (c *Detector) isHighRate(pr *pathRequests) bool {
	if len(pr.buckets) < 2 {
		return false
	}
	active := 0
	for _, b := range pr.buckets {
		if b.count > 0 {
			active++
		}
	}
	if active < 2 {
		return false
	}
	firstBucket := pr.buckets[0]
	lastBucket := pr.buckets[len(pr.buckets)-1]
	elapsed := lastBucket.start.Sub(firstBucket.start).Seconds() + bucketSize.Seconds()
	if elapsed < 1.0 {
		elapsed = 1.0
	}
	rate := float64(pr.total) / elapsed
	return rate > 5.0
}

func (c *Detector) addToBucket(pr *pathRequests, now time.Time) {
	bucketStart := now.Truncate(bucketSize)

	for i := range pr.buckets {
		if pr.buckets[i].start.Equal(bucketStart) {
			pr.buckets[i].count++
			pr.total++
			return
		}
	}

	pr.buckets = append(pr.buckets, bucket{start: bucketStart, count: 1})
	pr.total++
}

func (c *Detector) cleanupLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		c.mu.Lock()
		now := time.Now()
		cutoff := now.Add(-c.window)
		for key, pr := range c.requests {
			valid := pr.buckets[:0]
			total := 0
			for _, b := range pr.buckets {
				if b.start.After(cutoff) || b.start.Equal(cutoff) {
					valid = append(valid, b)
					total += b.count
				}
			}
			if total == 0 {
				delete(c.requests, key)
			} else {
				pr.buckets = valid
				pr.total = total
			}
		}
		c.mu.Unlock()

		// Clean UA trackers
		c.uaMu.Lock()
		for key, tr := range c.uaMap {
			if now.Sub(tr.lastSeen) > c.window*2 {
				delete(c.uaMap, key)
			}
		}
		c.uaMu.Unlock()
	}
}

