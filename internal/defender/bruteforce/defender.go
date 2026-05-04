package bruteforce

import (
	"hash/fnv"
	"strings"
	"sync"
	"time"

	"github.com/shield/shield/pkg/logger"
	"github.com/shield/shield/pkg/metrics"
)

// failureRecord tracks failed response attempts for an IP+path combination.
type failureRecord struct {
	count       int
	windowStart time.Time
	blockedAt   time.Time
}

// requestRecord tracks request frequency for an IP+path combination.
type requestRecord struct {
	count       int
	windowStart time.Time
	blockedAt   time.Time
	bodyHashes  map[uint64]int
	lastReq     time.Time
}

// pathAggregate tracks global request rate per protected path for distributed detection.
type pathAggregate struct {
	ipCount    map[string]int
	reqCount   int
	windowStart time.Time
	bodyHashes map[uint64]int
}

// defaultProtectedPaths are used when no paths are configured.
var defaultProtectedPaths = []string{
	"/login", "/admin", "/wp-login", "/api/login", "/api/auth",
	"/signin", "/auth", "/oauth", "/api/v1/login", "/api/v1/auth",
	"/user/login", "/users/login", "/account/login",
}

// rateDetectionMethods defines which HTTP methods are tracked for request-side detection.
var rateDetectionMethods = map[string]bool{
	"POST": true, "PUT": true, "PATCH": true, "DELETE": true,
}

// Defender protects against brute force attacks.
type Defender struct {
	enabled        bool
	maxFailures    int
	window         time.Duration
	blockDuration  time.Duration
	protectedPaths []string
	statusCodes    map[int]bool
	logger         *logger.Logger

	mu       sync.RWMutex
	failures map[string]*failureRecord
	requests map[string]*requestRecord

	// Distributed brute force detection: path-level aggregation
	pathMu     sync.Mutex
	pathAgg    map[string]*pathAggregate
}

// NewDefender creates a brute force defender.
func NewDefender(enabled bool, maxFailures, windowSec, blockDurationSec int, protectedPaths []string, statusCodes []int, log *logger.Logger) *Defender {
	b := &Defender{
		enabled:        enabled,
		maxFailures:    maxFailures,
		window:         time.Duration(windowSec) * time.Second,
		blockDuration:  time.Duration(blockDurationSec) * time.Second,
		protectedPaths: protectedPaths,
		statusCodes:    make(map[int]bool),
		logger:         log,
		failures:       make(map[string]*failureRecord),
		requests:       make(map[string]*requestRecord),
		pathAgg:        make(map[string]*pathAggregate),
	}
	for _, code := range statusCodes {
		b.statusCodes[code] = true
	}
	if len(b.statusCodes) == 0 {
		for code := 400; code < 600; code++ {
			b.statusCodes[code] = true
		}
	}
	if len(b.protectedPaths) == 0 {
		b.protectedPaths = defaultProtectedPaths
	}
	go b.cleanupLoop()
	return b
}

// ShouldBlock returns true if the IP should be blocked.
func (b *Defender) ShouldBlock(ip, path string) bool {
	if !b.enabled {
		return false
	}
	if !b.isProtected(path) {
		return false
	}
	key := ip + ":" + path

	// Check request-side detection (primary)
	b.mu.RLock()
	reqRec, reqOk := b.requests[key]
	b.mu.RUnlock()
	if reqOk && reqRec.count >= b.maxFailures && (reqRec.blockedAt.IsZero() || time.Since(reqRec.blockedAt) < b.blockDuration) {
		return true
	}

	// Check response-side detection (auxiliary)
	b.mu.RLock()
	failRec, failOk := b.failures[key]
	b.mu.RUnlock()
	if failOk && failRec.count >= b.maxFailures && (failRec.blockedAt.IsZero() || time.Since(failRec.blockedAt) < b.blockDuration) {
		return true
	}

	// Check distributed attack on this path
	if b.shouldBlockDistributed(path) {
		return true
	}

	return false
}

// shouldBlockDistributed checks if this path is under a distributed brute force attack.
func (b *Defender) shouldBlockDistributed(path string) bool {
	b.pathMu.Lock()
	defer b.pathMu.Unlock()

	agg, ok := b.pathAgg[path]
	if !ok {
		return false
	}
	now := time.Now()
	if now.Sub(agg.windowStart) > b.window {
		return false
	}
	// Many unique IPs + high request rate = distributed attack
	if len(agg.ipCount) >= 10 && agg.reqCount >= 50 {
		return true
	}
	return false
}

// RecordRequest records a request for request-side brute force detection.
func (b *Defender) RecordRequest(ip, path, method string, body []byte) {
	if !b.enabled {
		return
	}
	if !b.isProtected(path) {
		return
	}
	if !rateDetectionMethods[method] {
		return
	}
	key := ip + ":" + path
	b.mu.Lock()
	defer b.mu.Unlock()

	rec, ok := b.requests[key]
	if !ok || time.Since(rec.windowStart) > b.window {
		rec = &requestRecord{count: 1, windowStart: time.Now(), bodyHashes: make(map[uint64]int), lastReq: time.Now()}
		if len(body) > 0 {
			rec.bodyHashes[hashBody(body)] = 1
		}
		b.requests[key] = rec
		b.recordPathAgg(path, ip, body)
		return
	}
	rec.count++
	rec.lastReq = time.Now()
	if len(body) > 0 {
		rec.bodyHashes[hashBody(body)]++
	}
	if rec.count >= b.maxFailures {
		rec.blockedAt = time.Now()
		metrics.Get().IncBruteForceBlocks()
		if b.logger != nil {
			b.logger.Warn("brute_force_detected", map[string]interface{}{
				"ip":            ip,
				"path":          path,
				"count":         rec.count,
				"unique_bodies": len(rec.bodyHashes),
			})
		}
	}
	b.recordPathAgg(path, ip, body)
}

// RecordFailure records a failed response for auxiliary detection.
func (b *Defender) RecordFailure(ip, path string, statusCode int) {
	if !b.enabled {
		return
	}
	if !b.isProtected(path) {
		return
	}
	if !b.statusCodes[statusCode] {
		return
	}

	// 501/502 errors get higher sensitivity (double count). 502 often means probing non-existent endpoints.
	multiplier := 1
	if statusCode == 501 || statusCode == 502 {
		multiplier = 2
	}

	key := ip + ":" + path
	b.mu.Lock()
	defer b.mu.Unlock()
	rec, ok := b.failures[key]
	if !ok || time.Since(rec.windowStart) > b.window {
		b.failures[key] = &failureRecord{count: multiplier, windowStart: time.Now()}
		return
	}
	rec.count += multiplier
	if rec.count >= b.maxFailures {
		rec.blockedAt = time.Now()
		metrics.Get().IncBruteForceBlocks()
		if b.logger != nil {
			b.logger.Warn("brute_force_detected", map[string]interface{}{
				"ip":     ip,
				"path":   path,
				"count":  rec.count,
				"source": "response_status",
			})
		}
	}
}

// recordPathAgg updates global per-path aggregation for distributed attack detection.
func (b *Defender) recordPathAgg(path, ip string, body []byte) {
	b.pathMu.Lock()
	defer b.pathMu.Unlock()

	agg, ok := b.pathAgg[path]
	if !ok || time.Since(agg.windowStart) > b.window {
		agg = &pathAggregate{
			ipCount:    make(map[string]int),
			bodyHashes: make(map[uint64]int),
			windowStart: time.Now(),
		}
		b.pathAgg[path] = agg
	}
	agg.ipCount[ip]++
	agg.reqCount++
	if len(body) > 0 {
		agg.bodyHashes[hashBody(body)]++
	}
}

// Reset clears failure and request records for an IP+path.
func (b *Defender) Reset(ip, path string) {
	if !b.enabled {
		return
	}
	key := ip + ":" + path
	b.mu.Lock()
	delete(b.failures, key)
	delete(b.requests, key)
	b.mu.Unlock()
}

func (b *Defender) isProtected(path string) bool {
	if len(b.protectedPaths) == 0 {
		return true
	}
	for _, p := range b.protectedPaths {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

func (b *Defender) cleanupLoop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		b.mu.Lock()
		now := time.Now()
		for key, rec := range b.failures {
			if now.Sub(rec.windowStart) > b.window+b.blockDuration {
				delete(b.failures, key)
			}
		}
		for key, rec := range b.requests {
			if now.Sub(rec.windowStart) > b.window+b.blockDuration {
				delete(b.requests, key)
			}
		}
		b.mu.Unlock()

		// Clean path aggregates
		b.pathMu.Lock()
		for path, agg := range b.pathAgg {
			if now.Sub(agg.windowStart) > b.window*2 {
				delete(b.pathAgg, path)
			}
		}
		b.pathMu.Unlock()
	}
}

func hashBody(body []byte) uint64 {
	h := fnv.New64a()
	h.Write(body)
	return h.Sum64()
}
