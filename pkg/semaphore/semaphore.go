package semaphore

import (
	"context"
	"net/http"
	"time"

	"github.com/shield/shield/pkg/metrics"
)

// Semaphore is a weighted semaphore for limiting concurrent requests.
// It provides request queuing with timeout and priority support.
type Semaphore struct {
	ch       chan struct{}
	maxWeight int
}

// NewSemaphore creates a semaphore with the given maximum weight.
func NewSemaphore(maxConcurrent int) *Semaphore {
	if maxConcurrent <= 0 {
		maxConcurrent = 1000 // default
	}
	return &Semaphore{
		ch:       make(chan struct{}, maxConcurrent),
		maxWeight: maxConcurrent,
	}
}

// Acquire blocks until a slot is available or the context is cancelled.
func (s *Semaphore) Acquire(ctx context.Context) error {
	select {
	case s.ch <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// TryAcquire attempts to acquire a slot without blocking.
func (s *Semaphore) TryAcquire() bool {
	select {
	case s.ch <- struct{}{}:
		return true
	default:
		return false
	}
}

// Release returns a slot to the semaphore.
func (s *Semaphore) Release() {
	select {
	case <-s.ch:
	default:
	}
}

// Available returns the number of available slots.
func (s *Semaphore) Available() int {
	return s.maxWeight - len(s.ch)
}

// MaxWeight returns the maximum capacity.
func (s *Semaphore) MaxWeight() int {
	return s.maxWeight
}

// PrioritySemaphore wraps a Semaphore with priority-based queuing.
// High-priority requests (e.g., known good IPs) skip the queue when possible.
type PrioritySemaphore struct {
	normal *Semaphore
	high   *Semaphore // reserved slots for high-priority traffic
}

// NewPrioritySemaphore creates a priority semaphore.
// highRatio is the fraction of slots reserved for high-priority (0.0~1.0).
func NewPrioritySemaphore(maxConcurrent int, highRatio float64) *PrioritySemaphore {
	if maxConcurrent <= 0 {
		maxConcurrent = 1000
	}
	highSlots := int(float64(maxConcurrent) * highRatio)
	if highSlots < 1 {
		highSlots = 1
	}
	if highSlots >= maxConcurrent {
		highSlots = maxConcurrent / 4
	}
	normalSlots := maxConcurrent - highSlots
	return &PrioritySemaphore{
		normal: NewSemaphore(normalSlots),
		high:   NewSemaphore(highSlots),
	}
}

// AcquireWithPriority attempts to acquire a slot. If highPriority is true,
// it first tries the high-priority pool, then falls back to normal.
// Returns (true, nil) if acquired from high-priority pool, (false, nil) if from normal pool.
func (ps *PrioritySemaphore) AcquireWithPriority(ctx context.Context, highPriority bool) (bool, error) {
	if highPriority {
		// Try high-priority pool first (non-blocking)
		if ps.high.TryAcquire() {
			return true, nil
		}
		// Fall back to normal pool
		return false, ps.normal.Acquire(ctx)
	}
	// Normal priority: try normal pool first
	if ps.normal.TryAcquire() {
		return false, nil
	}
	// Queue with timeout
	return false, ps.normal.Acquire(ctx)
}

// Release returns a slot. acquiredHigh must match the return value of AcquireWithPriority.
func (ps *PrioritySemaphore) Release(acquiredHigh bool) {
	if acquiredHigh {
		ps.high.Release()
	} else {
		ps.normal.Release()
	}
}

// Middleware returns an HTTP middleware that enforces the semaphore.
// IPs in the trusted set get high-priority treatment.
func (ps *PrioritySemaphore) Middleware(timeout time.Duration, trusted func(string) bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := r.RemoteAddr
			high := false
			if trusted != nil {
				high = trusted(ip)
			}

			ctx, cancel := context.WithTimeout(r.Context(), timeout)
			defer cancel()

			acquiredHigh, err := ps.AcquireWithPriority(ctx, high)
			if err != nil {
				metrics.Get().IncBlockedRequests()
				http.Error(w, "503 Service Unavailable", http.StatusServiceUnavailable)
				return
			}
			defer ps.Release(acquiredHigh)

			next.ServeHTTP(w, r)
		})
	}
}
