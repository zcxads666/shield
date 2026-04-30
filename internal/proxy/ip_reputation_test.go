package proxy

import (
	"testing"
	"time"
)

func TestIPReputation_IsSuspicious(t *testing.T) {
	r := NewIPReputation(1*time.Second, 5)
	
	ip := "1.2.3.4"
	
	// Record 6 requests
	for i := 0; i < 6; i++ {
		r.Record(ip)
	}
	
	if !r.IsSuspicious(ip) {
		t.Error("expected IP to be suspicious after 6 requests")
	}
	
	// Different IP should not be suspicious
	if r.IsSuspicious("5.6.7.8") {
		t.Error("expected different IP to not be suspicious")
	}
}

func TestIPReputation_WindowReset(t *testing.T) {
	r := NewIPReputation(100*time.Millisecond, 2)
	
	ip := "1.2.3.4"
	r.Record(ip)
	r.Record(ip)
	r.Record(ip)
	
	if !r.IsSuspicious(ip) {
		t.Error("expected IP to be suspicious")
	}
	
	// Wait for window to expire
	time.Sleep(200 * time.Millisecond)
	
	if r.IsSuspicious(ip) {
		t.Error("expected IP to not be suspicious after window expires")
	}
}
