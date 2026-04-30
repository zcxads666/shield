package ratelimit

import (
	"sync"
	"time"
)

// AdaptiveLimiter wraps an IPLimiter with dynamic threshold adjustment.
// When under attack (high request rate), it tightens the limit.
// When normal, it relaxes the limit.
type AdaptiveLimiter struct {
	mu           sync.RWMutex
	baseLimiter  *IPLimiter
	enabled      bool
	baseRPS      float64
	baseBurst    int
	currentRPS   float64
	currentBurst int
	lastAdjust   time.Time
	adjustInt    time.Duration
}

// NewAdaptiveLimiter creates an adaptive rate limiter.
func NewAdaptiveLimiter(burst int, rps float64) *AdaptiveLimiter {
	return &AdaptiveLimiter{
		baseLimiter:  NewIPLimiter(burst, rps),
		enabled:      true,
		baseRPS:      rps,
		baseBurst:    burst,
		currentRPS:   rps,
		currentBurst: burst,
		lastAdjust:   time.Now(),
		adjustInt:    5 * time.Second,
	}
}

// Allow checks if a request is allowed.
func (a *AdaptiveLimiter) Allow(ip string) bool {
	if !a.enabled {
		return true
	}
	return a.baseLimiter.Allow(ip)
}

// Tighten reduces the rate limit by the given factor (0.0~1.0).
func (a *AdaptiveLimiter) Tighten(factor float64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	
	if time.Since(a.lastAdjust) < a.adjustInt {
		return
	}
	
	newRPS := a.baseRPS * factor
	if newRPS < 1 {
		newRPS = 1
	}
	newBurst := int(float64(a.baseBurst) * factor)
	if newBurst < 1 {
		newBurst = 1
	}
	
	if newRPS != a.currentRPS {
		a.currentRPS = newRPS
		a.currentBurst = newBurst
		a.baseLimiter = NewIPLimiter(newBurst, newRPS)
		a.lastAdjust = time.Now()
	}
}

// Relax restores the rate limit to base values.
func (a *AdaptiveLimiter) Relax() {
	a.mu.Lock()
	defer a.mu.Unlock()
	
	if time.Since(a.lastAdjust) < a.adjustInt {
		return
	}
	
	if a.currentRPS != a.baseRPS {
		a.currentRPS = a.baseRPS
		a.currentBurst = a.baseBurst
		a.baseLimiter = NewIPLimiter(a.baseBurst, a.baseRPS)
		a.lastAdjust = time.Now()
	}
}

// Size returns the number of tracked IPs.
func (a *AdaptiveLimiter) Size() int {
	return a.baseLimiter.Size()
}
