package ddoscc

import (
	"net/http"
	"sync"
	"time"

	"github.com/shield/shield/internal/storage/blacklist"
	"github.com/shield/shield/pkg/logger"
	"github.com/shield/shield/pkg/metrics"
	"github.com/shield/shield/pkg/ratelimit"
)

// pathRequests tracks bucket-based request counts per IP+path.
type pathRequests struct {
	buckets []bucket
	total   int
}

type bucket struct {
	count int
	start time.Time
}

type uaTracker struct {
	agents   map[string]int
	lastSeen time.Time
}

type ipBehaviorTrack struct {
	paths      map[string]int
	timestamps []time.Time
	lastSeen   time.Time
}

type pathConcentrationStats struct {
	ips       map[string]int
	totalReq  int
	firstSeen time.Time
	lastSeen  time.Time
}

// Detector provides unified DDoS/CC attack detection with graduated challenge-response.
type Detector struct {
	enabled        bool
	cfg            Config
	logger         *logger.Logger

	// Per-IP token bucket rate limiter
	limiter *ratelimit.IPLimiter

	// Elevated rate limiter for cookie-authenticated users (4x normal rate)
	cookieLimiter *ratelimit.IPLimiter

	// Connection tracking
	mu          sync.RWMutex
	connections map[string]int

	// Per-IP stats for DDoS pattern classification
	stats     map[string]*ipStats
	statsLock sync.Mutex

	// Global stats for multi-IP flood detection
	global *globalStats

	// Per-IP sliding window (CC legacy)
	requests map[string]*pathRequests

	// UA rotation tracking
	uaMu  sync.Mutex
	uaMap map[string]*uaTracker

	// Behavior tracking
	behaviorMu  sync.RWMutex
	behaviorIPs map[string]*ipBehaviorTrack

	// Path concentration
	pathMu    sync.RWMutex
	pathStats map[string]*pathConcentrationStats

	// IP reputation
	reputation *IPReputation

	// Challenge manager
	challenges *ChallengeManager

	// Per-IP token bucket violation tracking for graduated response
	rateViolations   map[string]*rateViolation
	rateViolationsMu sync.Mutex
}

// rateViolation tracks how many times an IP has exceeded the token bucket.
type rateViolation struct {
	count    int
	firstSeen time.Time
	lastSeen  time.Time
}

// NewDetector creates a unified DDoS/CC detector.
func NewDetector(cfg Config, log *logger.Logger) *Detector {
	if cfg.BurstRequests < cfg.MaxRequests {
		cfg.BurstRequests = cfg.MaxRequests
	}

	d := &Detector{
		enabled:      cfg.Enabled,
		cfg:          cfg,
		logger:       log,
		limiter:      ratelimit.NewIPLimiter(cfg.BurstSize, float64(cfg.RequestsPerSecond)),
		cookieLimiter: ratelimit.NewIPLimiter(cfg.BurstSize*4, float64(cfg.RequestsPerSecond)*4),
		connections:  make(map[string]int),
		stats:        make(map[string]*ipStats),
		global:       newGlobalStats(),
		requests:     make(map[string]*pathRequests),
		uaMap:        make(map[string]*uaTracker),
		behaviorIPs:  make(map[string]*ipBehaviorTrack),
		pathStats:    make(map[string]*pathConcentrationStats),
		reputation:   NewIPReputation(maxTrackedIPs),
		challenges:     NewChallengeManager("shield-ddoscc-secret-key-2026", 50000),
		rateViolations: make(map[string]*rateViolation),
	}
	go d.cleanupLoop()
	return d
}

// Check runs the unified DDoS/CC detection pipeline and returns the recommended action.
//
// Detection order:
//  Layer 0: Cookie bypass — valid __shield_cc → ActionAllow immediately
//  Layer 1: Global rate detection — multi-IP flood? → challenge new users
//  Layer 2: Token bucket — per-IP rate exceeded? → ActionBlock
//  Layer 3: Connection limit + Slowloris → ActionBlock
//  Layer 4: DDoS pattern (GoldenEye, HTTP Flood, SYN flood) → ActionBlock
//  Layer 5: Per-IP sliding window → triggers challenge system
//  Layer 6: UA rotation (>=4 UAs) → ActionBlock
//  Layer 7: Behavior + reputation + path concentration → graduated response
func (d *Detector) Check(r *http.Request) Action {
	if !d.enabled {
		return ActionAllow
	}

	ip := blacklist.GetClientIP(r.RemoteAddr, r.Header, d.cfg.TrustForwarded)
	path := d.requestPath(r)

	// Record for pattern analysis
	bodySize := 0
	if r.Body != nil {
		bodySize = int(r.ContentLength)
	}
	userAgent := r.Header.Get("User-Agent")
	d.recordRequest(ip, path, userAgent, bodySize)
	d.trackBehavior(ip, path)

	// Layer 0: Cookie recognition — proven users get elevated limits, not total bypass.
	// This ensures normal users pass smoothly through all rate checks during attacks
	// while preventing attackers from abusing a single acquired cookie.
	hasCookie := d.hasValidCookie(r)

	// Layer 1: Global rate detection — cookie users skip (they already proved legitimacy).
	// New users get challenged during multi-IP floods.
	if !hasCookie {
		if ok, _, _ := d.checkGlobalRate(ip); !ok {
			if d.cfg.EnvFingerprintEnabled {
				return ActionEnvFingerprint
			}
			return ActionJSChallenge
		}
	}

	// Layer 2: Token bucket per-IP rate limit.
	// Cookie users get elevated limits (4x) — legit users never exceed them,
	// but attackers who acquired a cookie will trip and get re-challenged.
	if hasCookie {
		if !d.cookieLimiter.Allow(ip) {
			d.logWarn(ip, path, "cookie_rate_exceeded", 0)
			if d.cfg.EnvFingerprintEnabled {
				return ActionEnvFingerprint
			}
			return ActionJSChallenge
		}
	} else {
		if violCount := d.checkTokenBucket(ip); violCount > 0 {
			suspicion := d.reputation.GetOrCreate(ip)
			suspicion.AddEvent(SuspicionEvent{
				Time:   time.Now(),
				Type:   "token_bucket_violation",
				Weight: 15,
			})
			switch {
			case violCount >= 3:
				suspicion.OnBlock(d.cfg.BlockAcceleration)
				metrics.Get().IncDDoSCCBlocks()
				return ActionBlock
			case violCount >= 2:
				if d.cfg.PoWChallengeEnabled {
					return ActionPoWChallenge
				}
				if d.cfg.EnvFingerprintEnabled {
					return ActionEnvFingerprint
				}
				return ActionJSChallenge
			default:
				if d.cfg.EnvFingerprintEnabled {
					return ActionEnvFingerprint
				}
				if d.cfg.JSChallengeEnabled {
					return ActionJSChallenge
				}
				if d.cfg.PoWChallengeEnabled {
					return ActionPoWChallenge
				}
				return ActionBlock
			}
		}
	}

	// Layer 3: Connection limit
	if ok, attackType := d.checkConnectionLimit(ip); !ok {
		_ = attackType
		return ActionBlock
	}

	// Layer 3b: Slowloris detection
	if d.detectSlowLoris(ip) {
		metrics.Get().IncDDoSCCBlocks()
		d.logWarn(ip, path, "slowloris", 0)
		return ActionBlock
	}

	// Layer 4: DDoS pattern detection (extreme per-IP patterns → direct block)
	if d.detectGoldenEye(ip) {
		metrics.Get().IncDDoSCCBlocks()
		d.logWarn(ip, path, "goldeneye", 0)
		return ActionBlock
	}
	if d.detectHTTPFlood(ip) {
		metrics.Get().IncDDoSCCBlocks()
		d.logWarn(ip, path, "http_flood", 0)
		return ActionBlock
	}
	if d.detectSYNFlood(ip) {
		metrics.Get().IncDDoSCCBlocks()
		d.logWarn(ip, path, "syn_flood", 0)
		return ActionBlock
	}

	// Layer 5: Per-IP sliding window (CC legacy — triggers challenge, not block)
	key := ip + "|" + path
	if d.rateLimitCheck(key, ip, path) {
		suspicion := d.reputation.GetOrCreate(ip)
		suspicion.AddEvent(SuspicionEvent{
			Time:   time.Now(),
			Type:   "rate_limit",
			Weight: 10,
		})

		// Per-IP sliding window exceeded → challenge (not flat block, unless extreme)
		fp := ExtractBehaviorFingerprint(r)
		behaviorScore := fp.Score()
		if behaviorScore < d.cfg.BehaviorBlockThreshold {
			suspicion.OnBlock(d.cfg.BlockAcceleration)
			metrics.Get().IncDDoSCCBlocks()
			return ActionBlock
		}
		if d.cfg.EnvFingerprintEnabled {
			return ActionEnvFingerprint
		}
		return ActionJSChallenge
	}

	// Layer 6: UA rotation detection
	if d.detectUARotation(key, userAgent) {
		suspicion := d.reputation.GetOrCreate(ip)
		suspicion.AddEvent(SuspicionEvent{
			Time:   time.Now(),
			Type:   "ua_rotation",
			Weight: 20,
		})
		metrics.Get().IncDDoSCCBlocks()
		return ActionBlock
	}

	// Layer 7: Behavior fingerprint + IP reputation + path concentration
	fp := ExtractBehaviorFingerprint(r)
	behaviorScore := fp.Score()

	d.behaviorMu.RLock()
	if bt, ok := d.behaviorIPs[ip]; ok {
		fp.TimingRandomness = calcTimingRandomness(bt.timestamps)
		fp.PathDiversity = calcPathDiversity(bt.paths, path)
	}
	d.behaviorMu.RUnlock()
	behaviorScore = fp.Score()

	suspicion := d.reputation.GetOrCreate(ip)
	suspicionScore := suspicion.GetScore()

	if suspicion.BlockCount >= d.cfg.MaxBlockCount && suspicion.Score > d.cfg.SuspicionBlockThreshold {
		metrics.Get().IncDDoSCCBlocks()
		d.logWarn(ip, path, "habitual_offender", suspicionScore)
		return ActionBlock
	}

	if d.detectPathConcentration(path) {
		suspicion.AddEvent(SuspicionEvent{
			Time:   time.Now(),
			Type:   "path_concentration",
			Weight: 40,
		})

		suspicionScore := suspicion.GetScore()

		// Path concentration is a distributed pattern: many IPs each sending few
		// requests. Individual IPs must not be blocked for this alone — only IPs
		// that independently show high-frequency malicious behavior get blocked.
		if suspicionScore > d.cfg.SuspicionBlockThreshold {
			metrics.Get().IncDDoSCCBlocks()
			suspicion.OnBlock(d.cfg.BlockAcceleration)
			d.logWarn(ip, path, "distributed_attack_block", suspicionScore)
			return ActionBlock
		}

		// Challenge escalation with global traffic pressure.
		// Heavier traffic → heavier challenge type.
		globalRate := d.global.requestRate(defaultStatsWindow)

		if globalRate > d.cfg.GlobalRateDangerThreshold {
			if d.cfg.PoWChallengeEnabled {
				return ActionPoWChallenge
			}
			if d.cfg.EnvFingerprintEnabled {
				return ActionEnvFingerprint
			}
			return ActionJSChallenge
		}
		if globalRate > d.cfg.GlobalRateDistributedThreshold {
			if d.cfg.EnvFingerprintEnabled {
				return ActionEnvFingerprint
			}
			return ActionJSChallenge
		}

		if d.cfg.JSChallengeEnabled {
			return ActionJSChallenge
		}

		d.logWarn(ip, path, "path_concentration_no_challenge", suspicionScore)
		return ActionAllow
	}

	action := d.determineAction(behaviorScore, suspicionScore, ip, path)
	if action == ActionBlock {
		metrics.Get().IncDDoSCCBlocks()
		suspicion.OnBlock(d.cfg.BlockAcceleration)
	}

	return action
}

// Release decrements active connection count for an IP.
func (d *Detector) Release(ip string) {
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

// GetSessionCookie returns the verified session ID from the request's __shield_cc cookie.
// Returns empty string and false if no valid cookie is present.
func (d *Detector) GetSessionCookie(r *http.Request) (string, bool) {
	cookie, err := r.Cookie("__shield_cc")
	if err != nil {
		return "", false
	}
	ip := blacklist.GetClientIP(r.RemoteAddr, r.Header, d.cfg.TrustForwarded)
	return d.challenges.VerifyChallengeCookie(cookie.Value, ip)
}

// GlobalRequestRate returns the current global request rate in requests per second.
func (d *Detector) GlobalRequestRate() float64 {
	return d.global.requestRate(defaultStatsWindow)
}

// --- Behavior Tracking ---

func (d *Detector) trackBehavior(ip, path string) {
	d.behaviorMu.Lock()
	bt, ok := d.behaviorIPs[ip]
	if !ok {
		bt = &ipBehaviorTrack{
			paths:      make(map[string]int),
			timestamps: make([]time.Time, 0, 64),
		}
		d.behaviorIPs[ip] = bt
	}
	bt.paths[path]++
	bt.timestamps = append(bt.timestamps, time.Now())
	bt.lastSeen = time.Now()

	if len(bt.timestamps) > 64 {
		bt.timestamps = bt.timestamps[len(bt.timestamps)-64:]
	}
	d.behaviorMu.Unlock()

	// Track path concentration
	d.pathMu.Lock()
	ps, ok := d.pathStats[path]
	if !ok {
		ps = &pathConcentrationStats{
			ips:       make(map[string]int),
			firstSeen: time.Now(),
		}
		d.pathStats[path] = ps
	}
	ps.ips[ip]++
	ps.totalReq++
	ps.lastSeen = time.Now()
	d.pathMu.Unlock()
}

// calcTimingRandomness estimates how random inter-request intervals are.
func calcTimingRandomness(timestamps []time.Time) float64 {
	if len(timestamps) < 3 {
		return 0.5
	}

	intervals := make([]float64, len(timestamps)-1)
	for i := 1; i < len(timestamps); i++ {
		intervals[i-1] = timestamps[i].Sub(timestamps[i-1]).Seconds()
	}

	var sum, sumSq float64
	for _, v := range intervals {
		sum += v
		sumSq += v * v
	}
	n := float64(len(intervals))
	mean := sum / n
	if mean < 0.001 {
		return 0
	}
	variance := sumSq/n - mean*mean
	if variance < 0 {
		variance = 0
	}
	cv := 0.0
	if mean > 0 {
		cv = sqrtVal(variance) / mean
	}
	if cv >= 1 {
		return 1.0
	}
	return cv
}

func sqrtVal(x float64) float64 {
	if x <= 0 {
		return 0
	}
	z := x
	for i := 0; i < 20; i++ {
		z -= (z*z - x) / (2 * z)
	}
	return z
}

func calcPathDiversity(paths map[string]int, currentPath string) float64 {
	if len(paths) == 0 {
		return 0
	}
	uniquePaths := len(paths)
	if uniquePaths >= 5 {
		return 1.0
	}
	if uniquePaths <= 1 {
		return 0.0
	}
	return float64(uniquePaths-1) / 4.0
}

// --- Cleanup ---

func (d *Detector) cleanupLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		windowDur := time.Duration(d.cfg.WindowSec) * time.Second

		// Cleanup connections
		d.mu.Lock()
		for ip, count := range d.connections {
			if count <= 0 {
				delete(d.connections, ip)
			}
		}
		d.mu.Unlock()

		// Cleanup per-IP stats
		d.statsLock.Lock()
		cutoff3x := now.Add(-defaultStatsWindow * 3)
		for ip, s := range d.stats {
			s.mu.Lock()
			last := s.lastSeen
			s.mu.Unlock()
			if last.Before(cutoff3x) {
				delete(d.stats, ip)
			}
		}
		d.statsLock.Unlock()

		// Cleanup rate-limit state
		d.mu.Lock()
		cutoff := now.Add(-windowDur)
		for key, pr := range d.requests {
			valid := pr.buckets[:0]
			total := 0
			for _, b := range pr.buckets {
				if !b.start.Before(cutoff) {
					valid = append(valid, b)
					total += b.count
				}
			}
			if total == 0 {
				delete(d.requests, key)
			} else {
				pr.buckets = valid
				pr.total = total
			}
		}
		d.mu.Unlock()

		// Cleanup UA trackers
		d.uaMu.Lock()
		for key, tr := range d.uaMap {
			if now.Sub(tr.lastSeen) > windowDur*2 {
				delete(d.uaMap, key)
			}
		}
		d.uaMu.Unlock()

		// Cleanup behavior tracks
		d.behaviorMu.Lock()
		for ip, bt := range d.behaviorIPs {
			if now.Sub(bt.lastSeen) > windowDur*2 {
				delete(d.behaviorIPs, ip)
			}
		}
		d.behaviorMu.Unlock()

		// Cleanup challenge states
		d.challenges.Cleanup(windowDur * 2)

		// Cleanup rate violation counters
		d.rateViolationsMu.Lock()
		rvCutoff := now.Add(-windowDur * 4)
		for ip, rv := range d.rateViolations {
			if rv.lastSeen.Before(rvCutoff) {
				delete(d.rateViolations, ip)
			}
		}
		d.rateViolationsMu.Unlock()
	}
}
