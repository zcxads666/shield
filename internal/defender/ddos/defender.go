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

// Attack type labels returned by AllowRequest.
const (
	AttackTypeNone       = ""
	AttackTypeDDoS       = "ddos_attack"
	AttackTypeHTTPFlood  = "ddos_attack:http_flood"
	AttackTypeSlowLoris  = "ddos_attack:slowloris"
	AttackTypeGoldenEye  = "ddos_attack:goldeneye"
	AttackTypeSYNFlood   = "ddos_attack:syn_flood"
	AttackTypeUDPFlood   = "ddos_attack:udp_flood"
)

const (
	defaultStatsWindow            = 10 * time.Second
	defaultGoldenEyeMinPath       = 5
	httpFloodRateThreshold        = 10 // requests per second
	httpFloodExtremeRateThreshold = 25 // requests per second
	maxTrackedRequests            = 200
	slowlorisMinRate              = 0.1 // requests per second (1 req per 10 seconds)
	slowlorisMinConns             = 5   // minimum concurrent connections for slowloris
	globalRateDangerThreshold     = 30  // global requests per second, lowered from 50
)

// ipStats tracks per-IP request patterns for attack classification.
type ipStats struct {
	mu          sync.Mutex
	requests    []reqSample
	reqIdx      int
	reqCount    int
	paths       map[string]int
	userAgents  map[string]int
	bodySizes   map[int]int
	headerFail  int
	lastSeen    time.Time
	firstSeen   time.Time
	connCount   int // concurrent connections tracked externally
	emptyBodyCount int
	nullByteCount  int
	byteRangeCount int
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

func (s *ipStats) record(r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	bodySize := 0
	if r.Body != nil {
		bodySize = int(r.ContentLength)
	}
	s.requests[s.reqIdx%maxTrackedRequests] = reqSample{ts: now, path: r.URL.Path, bodySize: bodySize}
	s.reqIdx++
	if s.reqCount < maxTrackedRequests {
		s.reqCount++
	}
	s.paths[r.URL.Path]++
	s.userAgents[r.Header.Get("User-Agent")]++
	s.bodySizes[bodySize]++
	s.lastSeen = now

	if r.Header.Get("User-Agent") == "" || r.Header.Get("Accept") == "" {
		s.headerFail++
	}
	if bodySize == 0 {
		s.emptyBodyCount++
	}
	if r.Header.Get("Range") != "" {
		s.byteRangeCount++
	}
}

// uniquePathsInWindow returns unique path count in the given window.
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

// requestRate returns requests per second over the configured window.
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

// uniqueBodySizes returns count of distinct body sizes in the current window.
func (s *ipStats) uniqueBodySizes() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.bodySizes)
}

// headerFailFraction returns the fraction of requests with incomplete headers.
func (s *ipStats) headerFailFraction() float64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.reqCount == 0 {
		return 0
	}
	return float64(s.headerFail) / float64(s.reqCount)
}

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

func (gs *globalStats) record(r *http.Request) {
	gs.mu.Lock()
	defer gs.mu.Unlock()
	bodySize := 0
	if r.Body != nil {
		bodySize = int(r.ContentLength)
	}
	gs.requests[gs.reqIdx%len(gs.requests)] = reqSample{ts: time.Now(), path: r.URL.Path, bodySize: bodySize}
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

// uniqueIPsInWindow estimates unique IPs contributing to global traffic.
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

// Defender provides DDoS protection.
type Defender struct {
	enabled          bool
	maxConnPerIP     int
	slowlorisTimeout time.Duration
	logger           *logger.Logger
	trustForwarded   bool

	mu          sync.RWMutex
	connections map[string]int
	limiter     *ratelimit.IPLimiter

	stats     map[string]*ipStats
	statsLock sync.Mutex

	global *globalStats
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
		stats:            make(map[string]*ipStats),
		global:           newGlobalStats(),
	}
	go d.cleanupLoop()
	return d
}

// Allow checks if a request should be allowed (backward compatible).
func (d *Defender) Allow(ip string) bool {
	allowed, _ := d.AllowRequest(ip, nil)
	return allowed
}

// AllowRequest checks if a request should be allowed and returns the attack type if blocked.
func (d *Defender) AllowRequest(ip string, r *http.Request) (bool, string) {
	if !d.enabled {
		return true, ""
	}

	// Record request stats for pattern analysis
	if r != nil {
		d.recordRequest(ip, r)
		d.global.record(r)
	}

	// 0. Global rate check (multi-IP DDoS detection) — adaptive threshold
	globalRate := d.global.requestRate(defaultStatsWindow)
	if globalRate > globalRateDangerThreshold {
		metrics.Get().IncDDoSBlocks()
		if d.logger != nil {
			d.logger.Warn("ddos_global_flood_detected", map[string]interface{}{
				"ip":          ip,
				"global_rate": globalRate,
			})
		}
		return false, d.classifyAttack(ip, r)
	}

	// 0.5 Global path diversity check — many IPs hitting few paths = DDoS
	globalPaths := d.global.uniquePathsInWindow(defaultStatsWindow)
	if globalRate > 20 && globalPaths > 30 {
		metrics.Get().IncDDoSBlocks()
		if d.logger != nil {
			d.logger.Warn("ddos_distributed_detected", map[string]interface{}{
				"ip":           ip,
				"global_rate":  globalRate,
				"global_paths": globalPaths,
			})
		}
		return false, AttackTypeDDoS
	}

	// 1. Connection limit check
	d.mu.Lock()
	connCount := d.connections[ip]
	if connCount >= d.maxConnPerIP {
		d.mu.Unlock()
		metrics.Get().IncDDoSBlocks()
		if d.logger != nil {
			d.logger.Warn("ddos_connection_limit", map[string]interface{}{"ip": ip})
		}
		return false, AttackTypeHTTPFlood
	}
	d.connections[ip] = connCount + 1
	d.mu.Unlock()

	// 2. Slowloris detection: very low rate + multiple long-held connections
	if r != nil && d.detectSlowLoris(ip) {
		metrics.Get().IncDDoSBlocks()
		if d.logger != nil {
			d.logger.Warn("ddos_slowloris_detected", map[string]interface{}{"ip": ip})
		}
		return false, AttackTypeSlowLoris
	}

	// 3. Global rate limit check
	if !d.limiter.Allow(ip) {
		metrics.Get().IncDDoSBlocks()
		if d.logger != nil {
			d.logger.Warn("ddos_rate_limit_exceeded", map[string]interface{}{"ip": ip})
		}
		attackType := AttackTypeHTTPFlood
		if r != nil {
			attackType = d.classifyAttack(ip, r)
		}
		return false, attackType
	}

	// 4. Detection based on request patterns
	if r != nil {
		// GoldenEye: high path diversity + high request rate
		if d.detectGoldenEye(ip) {
			metrics.Get().IncDDoSBlocks()
			if d.logger != nil {
				d.logger.Warn("ddos_goldeneye_detected", map[string]interface{}{"ip": ip})
			}
			return false, AttackTypeGoldenEye
		}
		// HTTP Flood: extreme request rate or suspicious patterns
		if d.detectHTTPFlood(ip) {
			metrics.Get().IncDDoSBlocks()
			if d.logger != nil {
				d.logger.Warn("ddos_http_flood_detected", map[string]interface{}{"ip": ip})
			}
			return false, AttackTypeHTTPFlood
		}
		// SYN-like behavior: high rate to single path with empty bodies
		if d.detectSYNFlood(ip) {
			metrics.Get().IncDDoSBlocks()
			if d.logger != nil {
				d.logger.Warn("ddos_syn_flood_detected", map[string]interface{}{"ip": ip})
			}
			return false, AttackTypeSYNFlood
		}
	}

	return true, ""
}

func (d *Defender) recordRequest(ip string, r *http.Request) {
	d.statsLock.Lock()
	s, ok := d.stats[ip]
	if !ok {
		s = newIPStats()
		d.stats[ip] = s
	}
	d.statsLock.Unlock()
	s.record(r)
}

func (d *Defender) classifyAttack(ip string, r *http.Request) string {
	d.statsLock.Lock()
	s, ok := d.stats[ip]
	d.statsLock.Unlock()
	if !ok {
		return AttackTypeHTTPFlood
	}

	rate := s.requestRate(defaultStatsWindow)
	pathsInWindow := s.uniquePathsInWindow(defaultStatsWindow)
	headerFail := s.headerFailFraction()
	bodySizes := s.uniqueBodySizes()
	emptyBodyAll := s.emptyBodyCount
	reqCount := s.reqCount

	// GoldenEye: many paths at high rate
	if pathsInWindow >= defaultGoldenEyeMinPath && rate > 10 {
		return AttackTypeGoldenEye
	}
	// HTTP Flood with tool signature (header failures + consistent body sizes)
	if rate > float64(httpFloodRateThreshold) && headerFail > 0.3 && bodySizes <= 2 {
		return AttackTypeHTTPFlood
	}
	// HTTP Flood pure volumetric
	if rate > float64(httpFloodExtremeRateThreshold) {
		return AttackTypeHTTPFlood
	}
	// SYN-like: all empty bodies, high rate, single/few paths
	if rate > 5 && reqCount > 0 && float64(emptyBodyAll)/float64(reqCount) > 0.9 && pathsInWindow <= 2 {
		return AttackTypeSYNFlood
	}
	// Slowloris pattern: very low rate but holding connections with header anomalies
	if rate > 0 && rate < 1.0 && headerFail > 0.5 {
		d.mu.RLock()
		conns := d.connections[ip]
		d.mu.RUnlock()
		if conns >= 3 {
			return AttackTypeSlowLoris
		}
	}

	return AttackTypeHTTPFlood
}

func (d *Defender) detectSlowLoris(ip string) bool {
	d.statsLock.Lock()
	s, ok := d.stats[ip]
	d.statsLock.Unlock()
	if !ok {
		return false
	}

	rate := s.requestRate(defaultStatsWindow)
	d.mu.RLock()
	conns := d.connections[ip]
	d.mu.RUnlock()

	headerFail := s.headerFailFraction()

	// Slowloris: very low send rate with multiple open connections and partial headers
	if conns >= slowlorisMinConns && rate < slowlorisMinRate && rate > 0 && headerFail > 0.5 {
		return true
	}
	// Slowloris: byte-range requests trickling in
	byteRange := s.byteRangeCount
	reqCount := s.reqCount
	if conns >= 3 && rate < 0.5 && rate > 0 && reqCount > 0 && float64(byteRange)/float64(reqCount) > 0.5 {
		return true
	}
	return false
}

func (d *Defender) detectGoldenEye(ip string) bool {
	d.statsLock.Lock()
	s, ok := d.stats[ip]
	d.statsLock.Unlock()
	if !ok {
		return false
	}

	pathsInWindow := s.uniquePathsInWindow(defaultStatsWindow)
	rate := s.requestRate(defaultStatsWindow)
	// GoldenEye: many unique paths (>threshold) at high request rate (>10 rps)
	return pathsInWindow >= defaultGoldenEyeMinPath && rate > 10
}

func (d *Defender) detectHTTPFlood(ip string) bool {
	d.statsLock.Lock()
	s, ok := d.stats[ip]
	d.statsLock.Unlock()
	if !ok {
		return false
	}

	rate := s.requestRate(defaultStatsWindow)
	headerFail := s.headerFailFraction()
	bodySizes := s.uniqueBodySizes()

	// Moderate rate with significant header incompleteness → tool signature
	if rate > float64(httpFloodRateThreshold) && headerFail > 0.3 {
		return true
	}
	// High rate with any header incompleteness
	if rate > float64(httpFloodRateThreshold*1.5) && headerFail > 0.1 {
		return true
	}
	// Very high rate alone is sufficient
	if rate > float64(httpFloodExtremeRateThreshold) {
		return true
	}
	// Moderate rate but all requests have identical body size (tool pattern)
	if rate > float64(httpFloodRateThreshold) && bodySizes == 1 {
		return true
	}
	return false
}

// detectSYNFlood detects request patterns that resemble SYN flood (empty bodies, single path).
func (d *Defender) detectSYNFlood(ip string) bool {
	d.statsLock.Lock()
	s, ok := d.stats[ip]
	d.statsLock.Unlock()
	if !ok {
		return false
	}

	rate := s.requestRate(defaultStatsWindow)
	emptyCount := s.emptyBodyCount
	reqCount := s.reqCount
	pathsInWindow := s.uniquePathsInWindow(defaultStatsWindow)

	// SYN-like: all requests have no body, hitting few paths at high rate
	if rate > 5 && reqCount > 0 && float64(emptyCount)/float64(reqCount) > 0.9 && pathsInWindow <= 2 {
		return true
	}
	return false
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

// WrapHandler wraps an http.Handler with DDoS protection.
func (d *Defender) WrapHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !d.enabled {
			next.ServeHTTP(w, r)
			return
		}
		ip := blacklist.GetClientIP(r.RemoteAddr, r.Header, d.trustForwarded)
		allowed, attackType := d.AllowRequest(ip, r)
		if !allowed {
			w.Header().Set("X-Block-Reason", attackType)
			http.Error(w, "429 Too Many Requests", http.StatusTooManyRequests)
			return
		}
		defer d.Release(ip)

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

		d.statsLock.Lock()
		cutoff := time.Now().Add(-defaultStatsWindow * 3)
		for ip, s := range d.stats {
			s.mu.Lock()
			last := s.lastSeen
			s.mu.Unlock()
			if last.Before(cutoff) {
				delete(d.stats, ip)
			}
		}
		d.statsLock.Unlock()
	}
}
