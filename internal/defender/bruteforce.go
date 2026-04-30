package defender

import (
	"strings"
	"sync"
	"time"

	"github.com/shield/shield/internal/logger"
	"github.com/shield/shield/internal/metrics"
)

// failureRecord tracks failed attempts for an IP+path combination.
type failureRecord struct {
	count     int
	windowStart time.Time
	blockedAt   time.Time
}

// BruteForceDefender protects against scanning and brute force.
type BruteForceDefender struct {
	enabled          bool
	maxFailures      int
	window           time.Duration
	blockDuration    time.Duration
	protectedPaths   []string
	statusCodes      map[int]bool
	logger           *logger.Logger

	mu       sync.RWMutex
	failures map[string]*failureRecord
}

// NewBruteForceDefender creates a brute force defender.
func NewBruteForceDefender(enabled bool, maxFailures, windowSec, blockDurationSec int, protectedPaths []string, statusCodes []int, log *logger.Logger) *BruteForceDefender {
	b := &BruteForceDefender{
		enabled:        enabled,
		maxFailures:    maxFailures,
		window:         time.Duration(windowSec) * time.Second,
		blockDuration:  time.Duration(blockDurationSec) * time.Second,
		protectedPaths: protectedPaths,
		statusCodes:    make(map[int]bool),
		logger:         log,
		failures:       make(map[string]*failureRecord),
	}
	for _, code := range statusCodes {
		b.statusCodes[code] = true
	}
	if len(b.statusCodes) == 0 {
		b.statusCodes[401] = true
		b.statusCodes[403] = true
	}
	go b.cleanupLoop()
	return b
}

// ShouldBlock returns true if the IP should be blocked.
func (b *BruteForceDefender) ShouldBlock(ip, path string) bool {
	if !b.enabled {
		return false
	}
	if !b.isProtected(path) {
		return false
	}
	key := ip + ":" + path
	b.mu.RLock()
	rec, ok := b.failures[key]
	b.mu.RUnlock()
	if !ok {
		return false
	}
	if rec.count >= b.maxFailures && (rec.blockedAt.IsZero() || time.Since(rec.blockedAt) < b.blockDuration) {
		return true
	}
	return false
}

// RecordFailure records a failed response.
func (b *BruteForceDefender) RecordFailure(ip, path string, statusCode int) {
	if !b.enabled {
		return
	}
	if !b.isProtected(path) {
		return
	}
	if !b.statusCodes[statusCode] {
		return
	}
	key := ip + ":" + path
	b.mu.Lock()
	defer b.mu.Unlock()
	rec, ok := b.failures[key]
	if !ok || time.Since(rec.windowStart) > b.window {
		b.failures[key] = &failureRecord{count: 1, windowStart: time.Now()}
		return
	}
	rec.count++
	if rec.count >= b.maxFailures {
		rec.blockedAt = time.Now()
		metrics.Get().IncBruteForceBlocks()
		if b.logger != nil {
			b.logger.Warn("brute_force_detected", map[string]interface{}{
				"ip":     ip,
				"path":   path,
				"count":  rec.count,
			})
		}
	}
}

// Reset clears failure count for an IP+path.
func (b *BruteForceDefender) Reset(ip, path string) {
	if !b.enabled {
		return
	}
	key := ip + ":" + path
	b.mu.Lock()
	delete(b.failures, key)
	b.mu.Unlock()
}

func (b *BruteForceDefender) isProtected(path string) bool {
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

func (b *BruteForceDefender) cleanupLoop() {
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
		b.mu.Unlock()
	}
}
