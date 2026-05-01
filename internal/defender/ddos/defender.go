package ddos

import (
	"net/http"
	"sync"
	"time"

	"github.com/shield/shield/internal/storage/blacklist"
	"github.com/shield/shield/pkg/logger"
	"github.com/shield/shield/pkg/metrics"
	"github.com/shield/shield/pkg/ratelimit"
)

// DDoSDefender provides DDoS and CC attack protection.
type Defender struct {
	enabled          bool
	maxConnPerIP     int
	slowlorisTimeout time.Duration
	logger           *logger.Logger
	trustForwarded   bool

	mu          sync.RWMutex
	connections map[string]int
	limiter     *ratelimit.IPLimiter
}

// NewDefender creates a DDoS defender.
func NewDefender(enabled bool, maxConnPerIP int, slowlorisMs int, rps, burst int, trustForwarded bool, log *logger.Logger) *Defender {
	d := &Defender{
		enabled:          enabled,
		maxConnPerIP:     maxConnPerIP,
		slowlorisTimeout: time.Duration(slowlorisMs) * time.Millisecond,
		logger:           log,
		trustForwarded:   trustForwarded,
		connections:      make(map[string]int),
		limiter:          ratelimit.NewIPLimiter(burst, float64(rps)),
	}
	go d.cleanupLoop()
	return d
}

// Allow checks if a request should be allowed.
func (d *Defender) Allow(ip string) bool {
	if !d.enabled {
		return true
	}

	// Rate limit check
	if !d.limiter.Allow(ip) {
		metrics.Get().IncDDoSBlocks()
		if d.logger != nil {
			d.logger.Warn("ddos_rate_limit_exceeded", map[string]interface{}{"ip": ip})
		}
		return false
	}

	// Connection limit check
	d.mu.Lock()
	if d.connections[ip] >= d.maxConnPerIP {
		d.mu.Unlock()
		metrics.Get().IncDDoSBlocks()
		if d.logger != nil {
			d.logger.Warn("ddos_connection_limit", map[string]interface{}{"ip": ip})
		}
		return false
	}
	d.connections[ip]++
	d.mu.Unlock()
	return true
}

// Release decrements active connection count for an IP.
func (d *Defender) Release(ip string) {
	if !d.enabled {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.connections[ip] > 0 {
		d.connections[ip]--
	}
	if d.connections[ip] == 0 {
		delete(d.connections, ip)
	}
}

// WrapHandler wraps an http.Handler with slowloris timeout.
func (d *Defender) WrapHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !d.enabled {
			next.ServeHTTP(w, r)
			return
		}
		ip := blacklist.GetClientIP(r.RemoteAddr, r.Header, d.trustForwarded)
		if !d.Allow(ip) {
			w.Header().Set("X-Block-Reason", "ddos")
			http.Error(w, "429 Too Many Requests", http.StatusTooManyRequests)
			return
		}
		defer d.Release(ip)

		// Slowloris detection via read deadline
		if d.slowlorisTimeout > 0 {
			if conn, ok := w.(interface{ SetReadDeadline(t time.Time) error }); ok {
				_ = conn.SetReadDeadline(time.Now().Add(d.slowlorisTimeout))
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (d *Defender) cleanupLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		d.mu.Lock()
		for ip, count := range d.connections {
			if count <= 0 {
				delete(d.connections, ip)
			}
		}
		d.mu.Unlock()
	}
}
