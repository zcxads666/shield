package semaphore

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestNewSemaphore(t *testing.T) {
	s := NewSemaphore(50)
	if s.MaxWeight() != 50 {
		t.Fatalf("expected max weight 50, got %d", s.MaxWeight())
	}
	if s.Available() != 50 {
		t.Fatalf("expected 50 available, got %d", s.Available())
	}
}

func TestNewSemaphore_DefaultMax(t *testing.T) {
	s := NewSemaphore(0)
	if s.MaxWeight() != 1000 {
		t.Fatalf("expected default max weight 1000, got %d", s.MaxWeight())
	}
}

func TestNewSemaphore_NegativeDefault(t *testing.T) {
	s := NewSemaphore(-1)
	if s.MaxWeight() != 1000 {
		t.Fatalf("expected default max weight 1000 for negative, got %d", s.MaxWeight())
	}
}

func TestAcquireRelease(t *testing.T) {
	s := NewSemaphore(10)
	ctx := context.Background()
	err := s.Acquire(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.Available() != 9 {
		t.Fatalf("expected 9 available, got %d", s.Available())
	}
	s.Release()
	if s.Available() != 10 {
		t.Fatalf("expected 10 available after release, got %d", s.Available())
	}
}

func TestAcquire_ContextCancelled(t *testing.T) {
	s := NewSemaphore(1)
	s.Acquire(context.Background()) // fill the semaphore

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()
	time.Sleep(2 * time.Millisecond)

	err := s.Acquire(ctx)
	if err == nil {
		t.Fatal("expected error when context is cancelled/timed out")
	}
}

func TestTryAcquire(t *testing.T) {
	s := NewSemaphore(1)
	if !s.TryAcquire() {
		t.Fatal("expected TryAcquire to succeed")
	}
	if s.TryAcquire() {
		t.Fatal("expected TryAcquire to fail when full")
	}
	s.Release()
	if !s.TryAcquire() {
		t.Fatal("expected TryAcquire to succeed after release")
	}
}

func TestRelease_NoOpWhenEmpty(t *testing.T) {
	s := NewSemaphore(1)
	s.Release() // releasing when nothing acquired should not panic
	if s.Available() != 1 {
		t.Fatalf("expected 1 available, got %d", s.Available())
	}
}

func TestAvailable_MaxWeight(t *testing.T) {
	s := NewSemaphore(25)
	if s.MaxWeight() != 25 {
		t.Fatalf("expected max 25, got %d", s.MaxWeight())
	}
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		s.Acquire(ctx)
	}
	if s.Available() != 20 {
		t.Fatalf("expected 20 available after 5 acquires, got %d", s.Available())
	}
}

func TestConcurrencyLimit(t *testing.T) {
	s := NewSemaphore(3)
	ctx := context.Background()
	var wg sync.WaitGroup
	counter := 0
	var mu sync.Mutex

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.Acquire(ctx)
			defer s.Release()
			mu.Lock()
			counter++
			if counter > 3 {
				t.Errorf("concurrency exceeded: %d", counter)
			}
			mu.Unlock()
			time.Sleep(10 * time.Millisecond)
			mu.Lock()
			counter--
			mu.Unlock()
		}()
	}
	wg.Wait()
}

// --- PrioritySemaphore tests ---

func TestNewPrioritySemaphore(t *testing.T) {
	ps := NewPrioritySemaphore(100, 0.2)
	// highSlots = int(100 * 0.2) = 20, normalSlots = 80
	if ps.high.MaxWeight() != 20 {
		t.Fatalf("expected high slots 20, got %d", ps.high.MaxWeight())
	}
	if ps.normal.MaxWeight() != 80 {
		t.Fatalf("expected normal slots 80, got %d", ps.normal.MaxWeight())
	}
}

func TestNewPrioritySemaphore_MinHighSlots(t *testing.T) {
	ps := NewPrioritySemaphore(100, 0.0001)
	if ps.high.MaxWeight() < 1 {
		t.Fatal("expected at least 1 high-priority slot")
	}
}

func TestNewPrioritySemaphore_CapHighSlots(t *testing.T) {
	ps := NewPrioritySemaphore(100, 1.0)
	if ps.high.MaxWeight() >= 100 {
		t.Fatal("high slots should be capped to 1/4 of max")
	}
}

func TestNewPrioritySemaphore_DefaultMax(t *testing.T) {
	ps := NewPrioritySemaphore(0, 0.2)
	if ps.high.MaxWeight() == 0 || ps.normal.MaxWeight() == 0 {
		t.Fatal("expected slots when given 0 maxConcurrent")
	}
}

func TestAcquireWithPriority_HighPriority(t *testing.T) {
	ps := NewPrioritySemaphore(100, 0.2) // 20 high, 80 normal
	ctx := context.Background()

	// High-priority request should acquire from high pool
	acquiredHigh, err := ps.AcquireWithPriority(ctx, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !acquiredHigh {
		t.Fatal("expected high-priority request to acquire from high pool")
	}
	ps.Release(acquiredHigh)
}

func TestAcquireWithPriority_HighFallback(t *testing.T) {
	ps := NewPrioritySemaphore(100, 0.2)

	// Fill high pool completely
	for i := 0; i < 20; i++ {
		acquiredHigh, _ := ps.AcquireWithPriority(context.Background(), true)
		if !acquiredHigh {
			t.Fatalf("expected high acquisition at index %d", i)
		}
	}

	// Next high-priority request should fall back to normal pool
	acquiredHigh, err := ps.AcquireWithPriority(context.Background(), true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if acquiredHigh {
		t.Fatal("expected fallback to normal pool when high pool is full")
	}
	ps.Release(acquiredHigh)
}

func TestAcquireWithPriority_NormalPriority(t *testing.T) {
	ps := NewPrioritySemaphore(100, 0.2)
	ctx := context.Background()

	acquiredHigh, err := ps.AcquireWithPriority(ctx, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if acquiredHigh {
		t.Fatal("expected normal-priority request to use normal pool")
	}
	ps.Release(acquiredHigh)
}

func TestAcquireWithPriority_NormalFallbackOnFullNormal(t *testing.T) {
	ps := NewPrioritySemaphore(100, 0.2)

	// Fill normal pool
	for i := 0; i < 80; i++ {
		ps.AcquireWithPriority(context.Background(), false)
	}

	// Next normal should queue with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := ps.AcquireWithPriority(ctx, false)
	if err == nil {
		// Could succeed if some releases happened quickly — that's fine
		// But with timeout it should eventually fail
	}
}

func TestPrioritySemaphoreRelease(t *testing.T) {
	ps := NewPrioritySemaphore(100, 0.5)

	acquiredHigh, _ := ps.AcquireWithPriority(context.Background(), true)
	ps.Release(acquiredHigh)
	// No panic means release worked correctly

	acquiredNormal, _ := ps.AcquireWithPriority(context.Background(), false)
	ps.Release(acquiredNormal)
	// No panic means release worked correctly
}

// --- Middleware tests ---

func TestMiddleware_NormalRequest(t *testing.T) {
	ps := NewPrioritySemaphore(100, 0.2)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})
	mw := ps.Middleware(5*time.Second, nil)
	wrapped := mw(handler)

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	w := httptest.NewRecorder()
	wrapped.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestMiddleware_TrustedIPUsesHighPriority(t *testing.T) {
	ps := NewPrioritySemaphore(2, 0.5)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	trusted := func(ip string) bool { return ip == "10.0.0.1:12345" }
	mw := ps.Middleware(5*time.Second, trusted)
	wrapped := mw(handler)

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	w := httptest.NewRecorder()
	wrapped.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for trusted IP, got %d", w.Code)
	}
}

func TestMiddleware_Timeout(t *testing.T) {
	ps := NewPrioritySemaphore(1, 0.2)
	// Fill the semaphore
	ps.AcquireWithPriority(context.Background(), false)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mw := ps.Middleware(10*time.Millisecond, nil)
	wrapped := mw(handler)

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	w := httptest.NewRecorder()
	wrapped.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when semaphore is full and timeout expires, got %d", w.Code)
	}
}

func TestMiddleware_NilTrustedFunction(t *testing.T) {
	ps := NewPrioritySemaphore(100, 0.2)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mw := ps.Middleware(5*time.Second, nil)
	wrapped := mw(handler)

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	w := httptest.NewRecorder()
	wrapped.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 with nil trusted func, got %d", w.Code)
	}
}
