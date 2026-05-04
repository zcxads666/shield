package ddoscc

import (
	"encoding/base64"
	"net/http"
	"strings"
	"time"

	"github.com/shield/shield/internal/storage/blacklist"
	"github.com/shield/shield/pkg/metrics"
)

// --- Detection Layer 0: Cookie Recognition ---

// hasValidCookie checks whether the request carries a cryptographically valid
// __shield_cc cookie (HMAC-signed and IP-bound). A valid cookie proves the
// client previously passed a challenge from this IP and earns elevated rate
// limits — but NOT a total bypass of all detection layers.
func (d *Detector) hasValidCookie(r *http.Request) bool {
	cookie, err := r.Cookie("__shield_cc")
	if err != nil {
		return false
	}

	ip := blacklist.GetClientIP(r.RemoteAddr, r.Header, d.cfg.TrustForwarded)
	_, ok := d.challenges.VerifyChallengeCookie(cookie.Value, ip)
	return ok
}

// --- Detection Layer 1: Global Rate Detection ---

// checkGlobalRate detects multi-IP distributed DDoS floods.
// During a global flood, new users get challenged; returning users with valid cookies bypass.
func (d *Detector) checkGlobalRate(ip string) bool {
	globalRate := d.global.requestRate(defaultStatsWindow)

	if globalRate > d.cfg.GlobalRateDangerThreshold {
		metrics.Get().IncDDoSCCBlocks()
		d.logWarn(ip, "", "global_flood", globalRate)
		return false
	}

	globalPaths := d.global.uniquePathsInWindow(defaultStatsWindow)
	if globalRate > d.cfg.GlobalRateDistributedThreshold && globalPaths > d.cfg.GlobalDistributedPathThreshold {
		metrics.Get().IncDDoSCCBlocks()
		d.logWarn(ip, "", "distributed_ddos", globalRate)
		return false
	}

	if globalRate > d.cfg.GlobalRateDistributedThreshold && globalPaths <= d.cfg.GlobalConcentratedPathThreshold {
		metrics.Get().IncDDoSCCBlocks()
		d.logWarn(ip, "", "concentrated_ddos", globalRate)
		return false
	}

	return true
}

// --- Detection Layer 2: Per-IP Token Bucket ---

// checkTokenBucket enforces the per-IP token bucket rate limit.
// Returns the violation count: 0 = allowed, 1+ = number of times this IP has
// exceeded the token bucket in the current window.  The caller uses this for
// graduated response (challenge first, block only for repeat offenders).
func (d *Detector) checkTokenBucket(ip string) int {
	if d.limiter.Allow(ip) {
		return 0
	}

	d.rateViolationsMu.Lock()
	rv, ok := d.rateViolations[ip]
	if !ok {
		rv = &rateViolation{firstSeen: time.Now()}
		d.rateViolations[ip] = rv
	}
	rv.count++
	rv.lastSeen = time.Now()
	count := rv.count
	d.rateViolationsMu.Unlock()

	metrics.Get().IncDDoSCCBlocks()
	d.logWarn(ip, "", "rate_limit_exceeded", float64(count))
	return count
}

// --- Detection Layer 3: Connection Limit + Slowloris ---

func (d *Detector) checkConnectionLimit(ip string) (bool, string) {
	d.mu.Lock()
	connCount := d.connections[ip]
	if connCount >= d.cfg.MaxConnectionsPerIP {
		d.mu.Unlock()
		metrics.Get().IncDDoSCCBlocks()
		d.logWarn(ip, "", "connection_limit", 0)
		return false, AttackTypeHTTPFlood
	}
	d.connections[ip] = connCount + 1
	d.mu.Unlock()
	return true, ""
}

func (d *Detector) detectSlowLoris(ip string) bool {
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

	if conns >= slowlorisMinConns && rate < slowlorisMinRate && rate > 0 && headerFail > 0.5 {
		return true
	}
	return false
}

// --- Detection Layer 4: DDoS Pattern Detection ---

func (d *Detector) detectGoldenEye(ip string) bool {
	d.statsLock.Lock()
	s, ok := d.stats[ip]
	d.statsLock.Unlock()
	if !ok {
		return false
	}

	pathsInWindow := s.uniquePathsInWindow(defaultStatsWindow)
	rate := s.requestRate(defaultStatsWindow)
	return pathsInWindow >= defaultGoldenEyeMinPath && rate > 10
}

func (d *Detector) detectHTTPFlood(ip string) bool {
	d.statsLock.Lock()
	s, ok := d.stats[ip]
	d.statsLock.Unlock()
	if !ok {
		return false
	}

	rate := s.requestRate(defaultStatsWindow)
	headerFail := s.headerFailFraction()
	bodySizes := s.uniqueBodySizes()

	if rate > float64(httpFloodPureRateThreshold) {
		return true
	}
	if rate > float64(httpFloodRateThreshold) && headerFail > 0.5 {
		return true
	}
	if rate > float64(httpFloodRateThreshold) && bodySizes == 1 {
		return true
	}
	return false
}

func (d *Detector) detectSYNFlood(ip string) bool {
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

	if rate > 5 && reqCount > 0 && float64(emptyCount)/float64(reqCount) > 0.9 && pathsInWindow <= 2 {
		return true
	}
	return false
}

// --- Detection Layer 5: Per-IP Sliding Window (CC legacy) ---

func (d *Detector) rateLimitCheck(key, ip, path string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	pr, ok := d.requests[key]
	if !ok {
		pr = &pathRequests{}
		d.requests[key] = pr
	}

	now := time.Now()
	cutoff := now.Add(-time.Duration(d.cfg.WindowSec) * time.Second)

	valid := pr.buckets[:0]
	total := 0
	for _, b := range pr.buckets {
		if !b.start.Before(cutoff) {
			valid = append(valid, b)
			total += b.count
		}
	}
	pr.buckets = valid
	pr.total = total

	if pr.total >= d.cfg.BurstRequests {
		return true
	}

	if pr.total >= d.cfg.MaxRequests {
		if d.isSustained(pr) {
			return true
		}
		if d.isHighRate(pr) {
			return true
		}
	}

	d.addToBucket(pr, now)
	return false
}

func (d *Detector) isSustained(pr *pathRequests) bool {
	if len(pr.buckets) == 0 {
		return false
	}
	maxBuckets := int(time.Duration(d.cfg.WindowSec)*time.Second / bucketSize)
	if maxBuckets < 1 {
		maxBuckets = 1
	}
	activeBuckets := 0
	for _, b := range pr.buckets {
		if b.count > 0 {
			activeBuckets++
		}
	}
	return float64(activeBuckets)/float64(maxBuckets) > 0.20
}

func (d *Detector) isHighRate(pr *pathRequests) bool {
	if len(pr.buckets) < 2 {
		return false
	}
	active := 0
	for _, b := range pr.buckets {
		if b.count > 0 {
			active++
		}
	}
	if active < 2 {
		return false
	}
	elapsed := pr.buckets[len(pr.buckets)-1].start.Sub(pr.buckets[0].start).Seconds() + bucketSize.Seconds()
	if elapsed < 1.0 {
		elapsed = 1.0
	}
	return float64(pr.total)/elapsed > 5.0
}

func (d *Detector) addToBucket(pr *pathRequests, now time.Time) {
	bucketStart := now.Truncate(bucketSize)
	for i := range pr.buckets {
		if pr.buckets[i].start.Equal(bucketStart) {
			pr.buckets[i].count++
			pr.total++
			return
		}
	}
	pr.buckets = append(pr.buckets, bucket{start: bucketStart, count: 1})
	pr.total++
}

// --- Detection Layer 6: UA Rotation ---

func (d *Detector) detectUARotation(key string, ua string) bool {
	if ua == "" {
		return false
	}
	d.uaMu.Lock()
	defer d.uaMu.Unlock()

	tr, ok := d.uaMap[key]
	if !ok || time.Since(tr.lastSeen) > time.Duration(d.cfg.WindowSec)*time.Second {
		tr = &uaTracker{agents: make(map[string]int), lastSeen: time.Now()}
		d.uaMap[key] = tr
	}
	tr.agents[ua]++
	tr.lastSeen = time.Now()
	return len(tr.agents) >= 4
}

// --- Detection Layer 7: Path Concentration ---

func (d *Detector) detectPathConcentration(path string) bool {
	d.pathMu.RLock()
	ps, ok := d.pathStats[path]
	d.pathMu.RUnlock()

	if !ok {
		return false
	}

	window := time.Duration(d.cfg.PathTimeWindowSec) * time.Second
	if time.Since(ps.firstSeen) > window {
		d.pathMu.Lock()
		delete(d.pathStats, path)
		d.pathMu.Unlock()
		return false
	}

	uniqueIPs := len(ps.ips)
	if uniqueIPs < d.cfg.PathIPThreshold {
		return false
	}

	avgReqPerIP := float64(ps.totalReq) / float64(uniqueIPs)
	return avgReqPerIP <= d.cfg.PathAvgReqThreshold
}

// IsPathConcentrationActive returns true if any path currently has enough unique
// IPs to qualify as a path concentration attack (used by the waiting room to
// decide whether to activate during distributed attacks).
func (d *Detector) IsPathConcentrationActive() bool {
	d.pathMu.RLock()
	defer d.pathMu.RUnlock()
	for _, ps := range d.pathStats {
		if len(ps.ips) >= d.cfg.PathIPThreshold {
			return true
		}
	}
	return false
}

// --- Action Determination ---

func (d *Detector) determineAction(behaviorScore, suspicionScore float64, ip, path string) Action {
	if suspicionScore > d.cfg.SuspicionBlockThreshold {
		d.logWarn(ip, path, "high_suspicion_block", suspicionScore)
		return ActionBlock
	}
	if behaviorScore < d.cfg.BehaviorBlockThreshold && suspicionScore > d.cfg.SuspicionChallengeThreshold {
		d.logWarn(ip, path, "low_behavior_and_suspicion", behaviorScore)
		return ActionBlock
	}

	if behaviorScore < 50 {
		if d.cfg.EnvFingerprintEnabled {
			return ActionEnvFingerprint
		}
		if d.cfg.JSChallengeEnabled {
			return ActionJSChallenge
		}
		// No challenges available — allow but log
		d.logWarn(ip, path, "low_behavior_no_challenge", behaviorScore)
		return ActionAllow
	}
	if behaviorScore < d.cfg.BehaviorScoreThreshold {
		if d.cfg.JSChallengeEnabled {
			return ActionJSChallenge
		}
		return ActionAllow
	}

	if suspicionScore > d.cfg.SuspicionChallengeThreshold {
		if d.cfg.PoWChallengeEnabled {
			return ActionPoWChallenge
		}
		return ActionBlock
	}

	return ActionAllow
}

// --- Challenge Serving ---

// ServeChallenge writes a challenge page to the response writer.
func (d *Detector) ServeChallenge(w http.ResponseWriter, r *http.Request, action Action, originalURL string) {
	ip := blacklist.GetClientIP(r.RemoteAddr, r.Header, d.cfg.TrustForwarded)
	sessionCookie := d.challenges.GenerateChallengeCookie(ip)

	parts := strings.SplitN(sessionCookie, ".", 2)
	sessionID := parts[0]
	d.challenges.GetSession(sessionID)

	http.SetCookie(w, &http.Cookie{
		Name:     "__shield_cc",
		Value:    sessionCookie,
		Path:     "/",
		HttpOnly: true,
		MaxAge:   86400,
		SameSite: http.SameSiteLaxMode,
	})

	metrics.Get().IncDDoSCCBlocks()
	w.Header().Set("X-Block-Reason", "ddos/cc:challenge")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusTooManyRequests)

	switch action {
	case ActionJSChallenge:
		html := d.challenges.GenerateJSChallengeHTML(sessionID, originalURL)
		w.Write([]byte(html))
	case ActionEnvFingerprint:
		html := d.challenges.GenerateEnvFingerprintHTML(sessionID, originalURL)
		w.Write([]byte(html))
	case ActionPoWChallenge:
		html := d.challenges.GeneratePoWHTML(sessionID, originalURL, d.cfg.PoWDifficulty)
		w.Write([]byte(html))
	default:
		http.Error(w, "Access denied", http.StatusForbidden)
	}
}

// VerifyChallenge checks a challenge response and returns the next action.
func (d *Detector) VerifyChallenge(r *http.Request) Action {
	sessionCookie, err := r.Cookie("__shield_cc")
	if err != nil {
		return ActionBlock
	}

	ip := blacklist.GetClientIP(r.RemoteAddr, r.Header, d.cfg.TrustForwarded)
	sessionID, ok := d.challenges.VerifyChallengeCookie(sessionCookie.Value, ip)
	if !ok {
		return ActionBlock
	}

	suspicion := d.reputation.GetOrCreate(ip)
	q := r.URL.Query()

	// Env fingerprint challenge (Stage 1)
	if verify := q.Get("__shield_verify"); verify != "" {
		token := q.Get("__shield_token")
		fpDataB64 := q.Get("__shield_fp")
		if fpDataB64 != "" {
			fpDataBytes, err := base64.StdEncoding.DecodeString(fpDataB64)
			if err == nil {
				if d.challenges.VerifyEnvFingerprint(sessionID, token, verify, string(fpDataBytes)) {
					d.challenges.RecordChallengeResult(sessionID, true)
					suspicion.OnChallengePass()
					return ActionAllow
				}
			}
			d.challenges.RecordChallengeResult(sessionID, false)
			suspicion.OnChallengeFail()
			return ActionBlock
		}
		// Legacy JS challenge
		if d.challenges.VerifyJSChallengeAnswer(sessionID, token, verify) {
			d.challenges.RecordChallengeResult(sessionID, true)
			suspicion.OnChallengePass()
			return ActionAllow
		}
		d.challenges.RecordChallengeResult(sessionID, false)
		suspicion.OnChallengeFail()
		return ActionBlock
	}

	// PoW response (Stage 2)
	if answer := q.Get("__shield_answer"); answer != "" {
		powToken := q.Get("__shield_token")
		powHash := q.Get("__shield_hash")
		if powToken != "" && powHash != "" {
			if d.challenges.VerifyPoW(sessionID, powToken, answer, powHash, d.cfg.PoWDifficulty) {
				d.challenges.RecordChallengeResult(sessionID, true)
				suspicion.OnChallengePass()
				return ActionAllow
			}
			d.challenges.RecordChallengeResult(sessionID, false)
			suspicion.OnChallengeFail()
			return ActionBlock
		}
		d.challenges.RecordChallengeResult(sessionID, false)
		suspicion.OnChallengeFail()
		return ActionBlock
	}

	return ActionBlock
}

// HasChallengeParams returns true if the request contains challenge verification params.
func (d *Detector) HasChallengeParams(r *http.Request) bool {
	q := r.URL.Query()
	return q.Get("__shield_verify") != "" || q.Get("__shield_answer") != ""
}

// --- Helpers ---

func (d *Detector) requestPath(r *http.Request) string {
	path := r.URL.Path
	if r.URL.RawQuery == "" {
		return path
	}
	q := r.URL.Query()
	if q.Has("action") {
		return path + "?action=" + q.Get("action")
	}
	if q.Has("q") || q.Has("query") || q.Has("search") {
		return path + "?search"
	}
	for k := range q {
		return path + "?" + k
	}
	return path
}

func (d *Detector) logWarn(ip, path, reason string, score float64) {
	if d.logger != nil {
		d.logger.Warn("ddos_cc_detected", map[string]interface{}{
			"ip":     ip,
			"path":   path,
			"reason": reason,
			"score":  score,
		})
	}
}

// recordRequest adds request stats for pattern analysis.
func (d *Detector) recordRequest(ip, path, userAgent string, bodySize int) {
	d.statsLock.Lock()
	s, ok := d.stats[ip]
	if !ok {
		s = newIPStats()
		d.stats[ip] = s
	}
	d.statsLock.Unlock()
	s.record(path, userAgent, bodySize)
	d.global.record(path)
}

// classifyAttack determines the specific attack type from per-IP patterns.
func (d *Detector) classifyAttack(ip string) string {
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

	if pathsInWindow >= defaultGoldenEyeMinPath && rate > 15 {
		return AttackTypeGoldenEye
	}
	if rate > float64(httpFloodRateThreshold) && headerFail > 0.5 && bodySizes <= 2 {
		return AttackTypeHTTPFlood
	}
	if rate > float64(httpFloodExtremeRateThreshold) {
		return AttackTypeHTTPFlood
	}
	if rate > 20 && reqCount > 0 && float64(emptyBodyAll)/float64(reqCount) > 0.9 && pathsInWindow <= 2 {
		return AttackTypeSYNFlood
	}
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
