package ddoscc

import (
	"sync"
	"time"
)

// ipStats tracks per-IP request patterns for attack classification.
type ipStats struct {
	mu             sync.Mutex
	requests       []reqSample
	reqIdx         int
	reqCount       int
	paths          map[string]int
	userAgents     map[string]int
	bodySizes      map[int]int
	headerFail     int
	lastSeen       time.Time
	firstSeen      time.Time
	emptyBodyCount int
}

type reqSample struct {
	ts       time.Time
	path     string
	bodySize int
}

func newIPStats() *ipStats {
	now := time.Now()
	return &ipStats{
		requests:   make([]reqSample, maxTrackedRequests),
		paths:      make(map[string]int),
		userAgents: make(map[string]int),
		bodySizes:  make(map[int]int),
		lastSeen:   now,
		firstSeen:  now,
	}
}

func (s *ipStats) record(path, userAgent string, bodySize int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	s.requests[s.reqIdx%maxTrackedRequests] = reqSample{ts: now, path: path, bodySize: bodySize}
	s.reqIdx++
	if s.reqCount < maxTrackedRequests {
		s.reqCount++
	}
	s.paths[path]++
	s.userAgents[userAgent]++
	s.bodySizes[bodySize]++
	s.lastSeen = now

	if userAgent == "" {
		s.headerFail++
	}
	if bodySize == 0 {
		s.emptyBodyCount++
	}
}

func (s *ipStats) uniquePathsInWindow(window time.Duration) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-window)
	paths := make(map[string]struct{})
	for i := 0; i < s.reqCount; i++ {
		sample := s.requests[i]
		if sample.ts.After(cutoff) {
			paths[sample.path] = struct{}{}
		}
	}
	return len(paths)
}

func (s *ipStats) requestRate(window time.Duration) float64 {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-window)
	count := 0
	for i := 0; i < s.reqCount; i++ {
		if s.requests[i].ts.After(cutoff) {
			count++
		}
	}
	return float64(count) / window.Seconds()
}

func (s *ipStats) uniqueBodySizes() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.bodySizes)
}

func (s *ipStats) headerFailFraction() float64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.reqCount == 0 {
		return 0
	}
	return float64(s.headerFail) / float64(s.reqCount)
}
