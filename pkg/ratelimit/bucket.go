package ratelimit

import (
	"sync"
	"time"
)

// TokenBucket implements a thread-safe token bucket rate limiter.
type TokenBucket struct {
	mu         sync.Mutex
	capacity   float64
	tokens     float64
	refillRate float64
	lastRefill time.Time
}

// NewTokenBucket creates a new token bucket.
func NewTokenBucket(capacity int, refillRatePerSec float64) *TokenBucket {
	return &TokenBucket{
		capacity:   float64(capacity),
		tokens:     float64(capacity),
		refillRate: refillRatePerSec,
		lastRefill: time.Now(),
	}
}

// Allow consumes one token if available.
func (tb *TokenBucket) Allow() bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	tb.refill()
	if tb.tokens >= 1 {
		tb.tokens--
		return true
	}
	return false
}

// Tokens returns current available tokens.
func (tb *TokenBucket) Tokens() float64 {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	tb.refill()
	return tb.tokens
}

func (tb *TokenBucket) refill() {
	now := time.Now()
	elapsed := now.Sub(tb.lastRefill).Seconds()
	tb.tokens += elapsed * tb.refillRate
	if tb.tokens > tb.capacity {
		tb.tokens = tb.capacity
	}
	tb.lastRefill = now
}

// bucketEntry wraps a TokenBucket with last-access time for TTL eviction.
type bucketEntry struct {
	bucket     *TokenBucket
	lastAccess time.Time
}

// IPLimiter manages per-IP token buckets with automatic TTL-based cleanup.
type IPLimiter struct {
	mu         sync.RWMutex
	buckets    map[string]*bucketEntry
	capacity   int
	refill     float64
	ttl        time.Duration
	cleanupInt time.Duration
}

// NewIPLimiter creates a per-IP rate limiter.
func NewIPLimiter(capacity int, refillRatePerSec float64) *IPLimiter {
	return NewIPLimiterWithTTL(capacity, refillRatePerSec, 10*time.Minute, 30*time.Second)
}

// NewIPLimiterWithTTL creates a per-IP rate limiter with TTL cleanup.
func NewIPLimiterWithTTL(capacity int, refillRatePerSec float64, ttl, cleanupInterval time.Duration) *IPLimiter {
	l := &IPLimiter{
		buckets:    make(map[string]*bucketEntry),
		capacity:   capacity,
		refill:     refillRatePerSec,
		ttl:        ttl,
		cleanupInt: cleanupInterval,
	}
	go l.cleanupLoop()
	return l
}

// Allow checks if a request from the given IP is allowed.
func (l *IPLimiter) Allow(ip string) bool {
	l.mu.RLock()
	e, ok := l.buckets[ip]
	l.mu.RUnlock()
	if ok {
		l.mu.Lock()
		e.lastAccess = time.Now()
		l.mu.Unlock()
		return e.bucket.Allow()
	}

	l.mu.Lock()
	e, ok = l.buckets[ip]
	if !ok {
		b := NewTokenBucket(l.capacity, l.refill)
		e = &bucketEntry{bucket: b, lastAccess: time.Now()}
		l.buckets[ip] = e
	} else {
		e.lastAccess = time.Now()
	}
	l.mu.Unlock()
	return e.bucket.Allow()
}

// Remove deletes the bucket for an IP.
func (l *IPLimiter) Remove(ip string) {
	l.mu.Lock()
	delete(l.buckets, ip)
	l.mu.Unlock()
}

// Size returns the current number of tracked IPs.
func (l *IPLimiter) Size() int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return len(l.buckets)
}

func (l *IPLimiter) cleanupLoop() {
	ticker := time.NewTicker(l.cleanupInt)
	defer ticker.Stop()
	for range ticker.C {
		l.mu.Lock()
		now := time.Now()
		for ip, e := range l.buckets {
			if now.Sub(e.lastAccess) > l.ttl {
				delete(l.buckets, ip)
			}
		}
		l.mu.Unlock()
	}
}
