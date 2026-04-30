package proxy

import (
	"sync"
	"time"
)

// IPReputation tracks request frequency and behavior for dynamic priority.
type IPReputation struct {
	mu       sync.RWMutex
	entries  map[string]*reputationEntry
	window   time.Duration
	threshold int // requests per window to be considered suspicious
}

type reputationEntry struct {
	count      int
	firstSeen  time.Time
	lastSeen   time.Time
	blocked    bool
}

// NewIPReputation creates a reputation tracker.
func NewIPReputation(window time.Duration, threshold int) *IPReputation {
	r := &IPReputation{
		entries:   make(map[string]*reputationEntry),
		window:    window,
		threshold: threshold,
	}
	go r.cleanupLoop()
	return r
}

// Record records a request from an IP.
func (r *IPReputation) Record(ip string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	
	now := time.Now()
	e, ok := r.entries[ip]
	if !ok {
		r.entries[ip] = &reputationEntry{
			count:     1,
			firstSeen: now,
			lastSeen:  now,
		}
		return
	}
	
	// Reset if window expired
	if now.Sub(e.firstSeen) > r.window {
		e.count = 1
		e.firstSeen = now
		e.blocked = false
	} else {
		e.count++
	}
	e.lastSeen = now
}

// IsSuspicious returns true if the IP exceeds the threshold.
func (r *IPReputation) IsSuspicious(ip string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	
	e, ok := r.entries[ip]
	if !ok {
		return false
	}
	
	// Reset if window expired
	if time.Since(e.firstSeen) > r.window {
		return false
	}
	
	return e.count > r.threshold
}

// Block marks an IP as blocked.
func (r *IPReputation) Block(ip string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	
	if e, ok := r.entries[ip]; ok {
		e.blocked = true
	}
}

// IsBlocked returns true if the IP is blocked.
func (r *IPReputation) IsBlocked(ip string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	
	if e, ok := r.entries[ip]; ok {
		return e.blocked
	}
	return false
}

func (r *IPReputation) cleanupLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		r.mu.Lock()
		now := time.Now()
		for ip, e := range r.entries {
			if now.Sub(e.lastSeen) > r.window*2 {
				delete(r.entries, ip)
			}
		}
		r.mu.Unlock()
	}
}
