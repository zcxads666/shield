package ddoscc

import (
	"math"
	"net/http"
	"sync"
	"sync/atomic"
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

	// waitingRoomActive is set by the proxy when the waiting room is handling
	// global flood traffic. When true, global rate checks are skipped since
	// the waiting room provides the primary traffic control mechanism.
	waitingRoomActive int32
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

// CheckEarly runs low-cost pre-body-read DDoS/CC checks (Layers 0–3).
// These checks use only headers, cookies, and connection counters — no body
// inspection — so they can safely run before io.ReadAll.  Cutting off
// high-frequency attackers at this stage prevents them from wasting CPU on
// body reads and content matching (the asymmetric resource-consumption attack).
//
// Layers:
//  Layer 0: Cookie bypass recognition
//  Layer 1: Global rate detection (multi-IP flood)
//  Layer 2: Token bucket per-IP rate limit
//  Layer 3: Connection limit + Slowloris detection
func (d *Detector) CheckEarly(r *http.Request) Action {
	if !d.enabled {
		return ActionAllow
	}

	ip := blacklist.GetClientIP(r.RemoteAddr, r.Header, d.cfg.TrustForwarded)
	path := d.requestPath(r)

	// Record metadata for pattern analysis (no body read — uses ContentLength header only).
	bodySize := 0
	if r.Body != nil {
		bodySize = int(r.ContentLength)
	}
	userAgent := r.Header.Get("User-Agent")
	d.recordRequest(ip, path, userAgent, bodySize)
	d.trackBehavior(ip, path)

	// Layer 0: Cookie recognition
	hasCookie := d.hasValidCookie(r)

	// Extract behavior fingerprint for global rate check.
	fp := ExtractBehaviorFingerprint(r)

	// Layer 1: Global rate detection
	if !hasCookie {
		if !d.checkGlobalRateWithBehavior(ip, fp) {
			if d.cfg.EnvFingerprintEnabled {
				return ActionEnvFingerprint
			}
			return ActionJSChallenge
		}
	}

	// Layer 2: Token bucket per-IP rate limit
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
				if d.ipRequestRate(ip) > 50 {
					suspicion.OnBlock(d.cfg.BlockAcceleration)
					metrics.Get().IncDDoSCCBlocks()
					return ActionBlock
				}
				if d.cfg.PoWChallengeEnabled {
					return ActionPoWChallenge
				}
				if d.cfg.EnvFingerprintEnabled {
					return ActionEnvFingerprint
				}
				return ActionJSChallenge
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
	if ok, _ := d.checkConnectionLimit(ip); !ok {
		return ActionBlock
	}

	// Layer 3b: Slowloris detection
	if d.detectSlowLoris(ip) {
		metrics.Get().IncDDoSCCBlocks()
		d.logWarn(ip, path, "slowloris", 0)
		return ActionBlock
	}

	return ActionAllow
}

// Check runs the full DDoS/CC detection pipeline (Layers 0–7) and returns
// the recommended action.  For the split-pipeline use case (early + late),
// call CheckEarly for Layers 0–3 before the body read, then CheckLate for
// Layers 4–7 after content matching.
//
// Layers:
//  Layer 0: Cookie bypass recognition
//  Layer 1: Global rate detection (multi-IP flood)
//  Layer 2: Token bucket per-IP rate limit
//  Layer 3: Connection limit + Slowloris detection
//  Layer 4: DDoS pattern (GoldenEye, HTTP Flood, SYN flood)
//  Layer 5: Per-IP sliding window
//  Layer 6: UA rotation (>=4 UAs)
//  Layer 7: Behavior + reputation + path concentration
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

	// Layer 0: Cookie recognition
	hasCookie := d.hasValidCookie(r)

	// Extract behavior fingerprint early so global rate check can use it
	// to differentiate normal browsers from bots during floods.
	fp := ExtractBehaviorFingerprint(r)

	// Layer 1: Global rate detection
	if !hasCookie {
		if !d.checkGlobalRateWithBehavior(ip, fp) {
			if d.cfg.EnvFingerprintEnabled {
				return ActionEnvFingerprint
			}
			return ActionJSChallenge
		}
	}

	// Layer 2: Token bucket per-IP rate limit
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
				if d.ipRequestRate(ip) > 50 {
					suspicion.OnBlock(d.cfg.BlockAcceleration)
					metrics.Get().IncDDoSCCBlocks()
					return ActionBlock
				}
				if d.cfg.PoWChallengeEnabled {
					return ActionPoWChallenge
				}
				if d.cfg.EnvFingerprintEnabled {
					return ActionEnvFingerprint
				}
				return ActionJSChallenge
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
	if ok, _ := d.checkConnectionLimit(ip); !ok {
		return ActionBlock
	}

	// Layer 3b: Slowloris detection
	if d.detectSlowLoris(ip) {
		metrics.Get().IncDDoSCCBlocks()
		d.logWarn(ip, path, "slowloris", 0)
		return ActionBlock
	}

	return d.checkLate(ip, path, userAgent, hasCookie, fp)
}

// CheckLate runs the remaining DDoS/CC detection layers (4–7) after content
// matching.  Assumes CheckEarly was already called for this request (stats
// have been recorded, Layers 0–3 have passed).
//
// Layers:
//  Layer 4: DDoS pattern (GoldenEye, HTTP Flood, SYN flood) → ActionBlock
//  Layer 5: Per-IP sliding window → triggers challenge system
//  Layer 6: UA rotation (>=4 UAs) → ActionBlock
//  Layer 7: Behavior + reputation + path concentration → graduated response
func (d *Detector) CheckLate(r *http.Request) Action {
	if !d.enabled {
		return ActionAllow
	}

	ip := blacklist.GetClientIP(r.RemoteAddr, r.Header, d.cfg.TrustForwarded)
	path := d.requestPath(r)
	userAgent := r.Header.Get("User-Agent")
	hasCookie := d.hasValidCookie(r)
	fp := ExtractBehaviorFingerprint(r)

	return d.checkLate(ip, path, userAgent, hasCookie, fp)
}

// checkLate is the shared implementation for Layers 4–7, used by both
// Check (full pipeline) and CheckLate (split pipeline).
func (d *Detector) checkLate(ip, path, userAgent string, hasCookie bool, fp *BehaviorFingerprint) Action {
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

		behaviorScore := fp.Score()
		if behaviorScore < d.cfg.BehaviorBlockThreshold {
			if d.ipRequestRate(ip) > 50 {
				suspicion.OnBlock(d.cfg.BlockAcceleration)
				metrics.Get().IncDDoSCCBlocks()
				return ActionBlock
			}
			if d.cfg.EnvFingerprintEnabled {
				return ActionEnvFingerprint
			}
			return ActionJSChallenge
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

	// Layer 7: Behavior fingerprint + IP reputation + path concentration.
	//
	// Cookie users have already proven they are real browsers by passing a
	// challenge. Do NOT re-challenge them for path concentration or behavior
	// score — these are traffic-pattern signals that affect both attackers
	// and normal users during a distributed attack. Re-challenging cookie
	// users here creates an infinite redirect loop: user passes JS challenge,
	// gets a valid cookie, but path concentration is still detected on the
	// same URL and triggers another challenge.
	//
	// The cookie limiter (Layer 2) remains the mechanism for catching
	// cookie-bearing abusers who exceed even elevated rate limits.
	if hasCookie {
		return ActionAllow
	}

	// Skip challenge if IP is within grace period after passing a previous challenge.
	if d.challenges.IsInGracePeriod(ip) {
		return ActionAllow
	}

	d.behaviorMu.RLock()
	if bt, ok := d.behaviorIPs[ip]; ok {
		fp.TimingRandomness = calcTimingRandomness(bt.timestamps)
		fp.PathDiversity = calcPathDiversity(bt.paths, path)
	}
	d.behaviorMu.RUnlock()
	behaviorScore := fp.Score()

	suspicion := d.reputation.GetOrCreate(ip)
	suspicionScore := suspicion.GetScore()

	if suspicion.BlockCount >= d.cfg.MaxBlockCount && suspicion.Score > d.cfg.SuspicionBlockThreshold {
		metrics.Get().IncDDoSCCBlocks()
		d.logWarn(ip, path, "habitual_offender", suspicionScore)
		return ActionBlock
	}

	if d.detectPathConcentration(path) {
		// When the waiting room is active, the waiting room provides primary
		// traffic control for distributed attacks. Normal users (behaviorScore
		// >= 70) go directly to the waiting room. Risky IPs must first pass
		// a JS challenge before entering.
		if atomic.LoadInt32(&d.waitingRoomActive) == 1 {
			if behaviorScore >= 70 {
				return ActionAllow
			}
			if d.cfg.EnvFingerprintEnabled {
				return ActionEnvFingerprint
			}
			return ActionJSChallenge
		}

		suspicion.AddEvent(SuspicionEvent{
			Time:   time.Now(),
			Type:   "path_concentration",
			Weight: 40,
		})

		suspicionScore := suspicion.GetScore()

		if suspicionScore > d.cfg.SuspicionBlockThreshold {
			metrics.Get().IncDDoSCCBlocks()
			suspicion.OnBlock(d.cfg.BlockAcceleration)
			d.logWarn(ip, path, "distributed_attack_block", suspicionScore)
			return ActionBlock
		}

		// Challenge escalation with global traffic pressure.
		// Heavier traffic -> heavier challenge type.
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

// ipRequestRate returns the current request rate (req/s) for the given IP.
func (d *Detector) ipRequestRate(ip string) float64 {
	d.statsLock.Lock()
	s, ok := d.stats[ip]
	d.statsLock.Unlock()
	if !ok {
		return 0
	}
	return s.requestRate(defaultStatsWindow)
}

// GenerateTestCookie generates a signed challenge cookie for the given IP.
// Used by tests to simulate a cookie-authenticated user.
func (d *Detector) GenerateTestCookie(ip string) string {
	return d.challenges.GenerateChallengeCookie(ip)
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

// SetWaitingRoomActive tells the detector whether the waiting room is currently
// handling global flood traffic. When true, global rate challenges are skipped.
func (d *Detector) SetWaitingRoomActive(active bool) {
	var v int32
	if active {
		v = 1
	}
	atomic.StoreInt32(&d.waitingRoomActive, v)
}

// IsSuspicious returns true if the IP has a non-zero reputation score,
// indicating it has triggered at least one suspicious event.
func (d *Detector) IsSuspicious(ip string) bool {
	if !d.enabled {
		return false
	}
	suspicion := d.reputation.GetOrCreate(ip)
	return suspicion.GetScore() > 0
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
	// Cap paths map to prevent a path-scanning IP from inflating memory
	// within the behavior tracking window.
	if len(bt.paths) > 128 {
		newPaths := make(map[string]int)
		newPaths[path] = bt.paths[path]
		bt.paths = newPaths
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
		cv = math.Sqrt(variance) / mean
	}
	if cv >= 1 {
		return 1.0
	}
	return cv
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

		// Cleanup path concentration stats — remove expired entries so stale
		// data doesn't keep IsPathConcentrationActive() returning true.
		pathWin := time.Duration(d.cfg.PathTimeWindowSec) * time.Second
		d.pathMu.Lock()
		for path, ps := range d.pathStats {
			if now.Sub(ps.firstSeen) > pathWin {
				delete(d.pathStats, path)
			}
		}
		d.pathMu.Unlock()

		// Cleanup reputation entries — remove IPs with decayed scores below
		// threshold that haven't been seen recently, preventing the 10k-cap
		// map from being permanently occupied by past attackers.
		d.reputation.CleanupStale(now.Add(-windowDur * 4), 0.5)

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
