package ddoscc

import (
	"sync"
	"time"
)

// globalStats tracks global request rate for multi-IP DDoS detection.
type globalStats struct {
	mu        sync.Mutex
	requests  []reqSample
	reqIdx    int
	reqCount  int
	totalReqs int64
	startTime time.Time
}

func newGlobalStats() *globalStats {
	return &globalStats{
		requests:  make([]reqSample, maxTrackedRequests*4),
		startTime: time.Now(),
	}
}

func (gs *globalStats) record(path string) {
	gs.mu.Lock()
	defer gs.mu.Unlock()
	gs.requests[gs.reqIdx%len(gs.requests)] = reqSample{ts: time.Now(), path: path}
	gs.reqIdx++
	if gs.reqCount < len(gs.requests) {
		gs.reqCount++
	}
	gs.totalReqs++
}

func (gs *globalStats) requestRate(window time.Duration) float64 {
	gs.mu.Lock()
	defer gs.mu.Unlock()
	now := time.Now()
	cutoff := now.Add(-window)
	count := 0
	for i := 0; i < gs.reqCount; i++ {
		if gs.requests[i].ts.After(cutoff) {
			count++
		}
	}
	return float64(count) / window.Seconds()
}

func (gs *globalStats) uniquePathsInWindow(window time.Duration) int {
	gs.mu.Lock()
	defer gs.mu.Unlock()
	now := time.Now()
	cutoff := now.Add(-window)
	paths := make(map[string]struct{})
	for i := 0; i < gs.reqCount; i++ {
		if gs.requests[i].ts.After(cutoff) {
			paths[gs.requests[i].path] = struct{}{}
		}
	}
	return len(paths)
}
