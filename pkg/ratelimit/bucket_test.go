package ratelimit

import (
	"testing"
	"time"
)

func TestTokenBucket(t *testing.T) {
	tb := NewTokenBucket(5, 1)
	for i := 0; i < 5; i++ {
		if !tb.Allow() {
			t.Fatalf("expected allow at iteration %d", i)
		}
	}
	if tb.Allow() {
		t.Fatal("expected deny after bucket exhausted")
	}

	time.Sleep(1100 * time.Millisecond)
	if !tb.Allow() {
		t.Fatal("expected allow after refill")
	}
}

func TestIPLimiter(t *testing.T) {
	l := NewIPLimiter(3, 10)
	for i := 0; i < 3; i++ {
		if !l.Allow("192.168.1.1") {
			t.Fatalf("expected allow at iteration %d", i)
		}
	}
	if l.Allow("192.168.1.1") {
		t.Fatal("expected deny for same IP")
	}
	if !l.Allow("192.168.1.2") {
		t.Fatal("expected allow for different IP")
	}
}
