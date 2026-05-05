package metrics

import (
	"sync"
	"sync/atomic"
)

// Metrics holds runtime counters.
type Metrics struct {
	TotalRequests     uint64
	BlockedRequests   uint64
	AllowedRequests   uint64
	ActiveConnections int64
	SQLInjections     uint64
	XSSAttempts       uint64
	WebShellUploads   uint64
	DDoSCCBlocks     uint64
	DDoSCCChallenges uint64
	BruteForceBlocks uint64
	BlacklistedIPs   uint64
}

var (
	instance *Metrics
	once     sync.Once
)

// Get returns the global metrics instance.
func Get() *Metrics {
	once.Do(func() {
		instance = &Metrics{}
	})
	return instance
}

// IncTotalRequests increments total request count.
func (m *Metrics) IncTotalRequests() { atomic.AddUint64(&m.TotalRequests, 1) }

// IncBlockedRequests increments blocked request count.
func (m *Metrics) IncBlockedRequests() { atomic.AddUint64(&m.BlockedRequests, 1) }

// IncAllowedRequests increments allowed request count.
func (m *Metrics) IncAllowedRequests() { atomic.AddUint64(&m.AllowedRequests, 1) }

// AddActiveConnections changes active connection count.
func (m *Metrics) AddActiveConnections(delta int64) { atomic.AddInt64(&m.ActiveConnections, delta) }

// IncSQLInjections increments SQL injection detection count.
func (m *Metrics) IncSQLInjections() { atomic.AddUint64(&m.SQLInjections, 1) }

// IncXSSAttempts increments XSS attempt count.
func (m *Metrics) IncXSSAttempts() { atomic.AddUint64(&m.XSSAttempts, 1) }

// IncWebShellUploads increments web shell upload detection count.
func (m *Metrics) IncWebShellUploads() { atomic.AddUint64(&m.WebShellUploads, 1) }

// IncDDoSCCBlocks increments unified DDoS/CC block count.
func (m *Metrics) IncDDoSCCBlocks() { atomic.AddUint64(&m.DDoSCCBlocks, 1) }

// IncDDoSCCChallenges increments unified DDoS/CC challenge count.
func (m *Metrics) IncDDoSCCChallenges() { atomic.AddUint64(&m.DDoSCCChallenges, 1) }

// IncBruteForceBlocks increments brute force block count.
func (m *Metrics) IncBruteForceBlocks() { atomic.AddUint64(&m.BruteForceBlocks, 1) }

// SetBlacklistedIPs sets the current blacklisted IP count.
func (m *Metrics) SetBlacklistedIPs(n uint64) { atomic.StoreUint64(&m.BlacklistedIPs, n) }

// Snapshot returns a copy of current metrics.
func (m *Metrics) Snapshot() Metrics {
	return Metrics{
		TotalRequests:     atomic.LoadUint64(&m.TotalRequests),
		BlockedRequests:   atomic.LoadUint64(&m.BlockedRequests),
		AllowedRequests:   atomic.LoadUint64(&m.AllowedRequests),
		ActiveConnections: atomic.LoadInt64(&m.ActiveConnections),
		SQLInjections:     atomic.LoadUint64(&m.SQLInjections),
		XSSAttempts:       atomic.LoadUint64(&m.XSSAttempts),
		WebShellUploads:   atomic.LoadUint64(&m.WebShellUploads),
		DDoSCCBlocks:     atomic.LoadUint64(&m.DDoSCCBlocks),
			DDoSCCChallenges: atomic.LoadUint64(&m.DDoSCCChallenges),
		BruteForceBlocks: atomic.LoadUint64(&m.BruteForceBlocks),
		BlacklistedIPs:    atomic.LoadUint64(&m.BlacklistedIPs),
	}
}
