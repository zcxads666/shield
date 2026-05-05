package handler

import (
	"bytes"
	"context"
	"io"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/shield/shield/internal/defender/bruteforce"
	"github.com/shield/shield/internal/defender/ddoscc"
	"github.com/shield/shield/internal/defender/sqlinject"
	"github.com/shield/shield/internal/defender/webshell"
	"github.com/shield/shield/internal/defender/xss"
	"github.com/shield/shield/internal/service/rules"
	"github.com/shield/shield/internal/storage/blacklist"
	"github.com/shield/shield/pkg/config"
	"github.com/shield/shield/pkg/logger"
	"github.com/shield/shield/pkg/metrics"
	"github.com/shield/shield/pkg/semaphore"
	"github.com/shield/shield/pkg/waitingroom"
)

// Server wraps the reverse proxy and defense middleware.
type ProxyServer struct {
	cfg          *config.Config
	proxy        *httputil.ReverseProxy
	logger       *logger.Logger
	blacklist    *blacklist.Manager
	ddosCC       *ddoscc.Detector
	sqlInject    *sqlinject.Detector
	xss          *xss.Detector
	webShell     *webshell.Detector
	bruteForce   *bruteforce.Defender
	rules        *rules.Engine
	semaphore    *semaphore.PrioritySemaphore
	waitingRoom  *waitingroom.WaitingRoom
}

// NewServer creates a shield proxy server.
func NewProxyServer(cfg *config.Config, log *logger.Logger, bl *blacklist.Manager, rl *rules.Engine) (*ProxyServer, error) {
	target, err := url.Parse(cfg.Proxy.TargetURL)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL: %w", err)
	}

	rp := httputil.NewSingleHostReverseProxy(target)
	rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Error("proxy_error", map[string]interface{}{"error": err.Error(), "path": r.URL.Path})
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
	}

	sem := semaphore.NewPrioritySemaphore(cfg.Server.MaxConcurrent, cfg.Server.HighPriorityRatio)

	s := &ProxyServer{
		cfg:          cfg,
		proxy:        rp,
		logger:       log,
		blacklist:    bl,
		rules:        rl,
		semaphore:    sem,
	}

	// Initialize unified DDoS/CC defender
	s.ddosCC = ddoscc.NewDetector(
		ddoscc.Config{
			Enabled:                       cfg.DDoSCC.Enabled,
			RequestsPerSecond:             cfg.DDoSCC.RequestsPerSecond,
			BurstSize:                     cfg.DDoSCC.BurstSize,
			MaxConnectionsPerIP:           cfg.DDoSCC.MaxConnectionsPerIP,
			SlowlorisTimeoutMs:            cfg.DDoSCC.SlowlorisTimeoutMs,
			GlobalRateDangerThreshold:     cfg.DDoSCC.GlobalRateDangerThreshold,
			GlobalRateDistributedThreshold: cfg.DDoSCC.GlobalRateDistributedThreshold,
			GlobalDistributedPathThreshold: cfg.DDoSCC.GlobalDistributedPathThreshold,
			GlobalConcentratedPathThreshold: cfg.DDoSCC.GlobalConcentratedPathThreshold,
			MaxRequests:                   cfg.DDoSCC.MaxRequests,
			BurstRequests:                 cfg.DDoSCC.BurstRequests,
			WindowSec:                     cfg.DDoSCC.WindowSec,
			BehaviorScoreThreshold:        cfg.DDoSCC.BehaviorScoreThreshold,
			BehaviorBlockThreshold:        cfg.DDoSCC.BehaviorBlockThreshold,
			PathIPThreshold:               cfg.DDoSCC.PathIPThreshold,
			PathAvgReqThreshold:           cfg.DDoSCC.PathAvgReqThreshold,
			PathTimeWindowSec:             cfg.DDoSCC.PathTimeWindowSec,
			SuspicionBlockThreshold:       cfg.DDoSCC.SuspicionBlockThreshold,
			SuspicionChallengeThreshold:   cfg.DDoSCC.SuspicionChallengeThreshold,
			BlockDurationSec:              cfg.DDoSCC.BlockDurationSec,
			BlockAcceleration:             cfg.DDoSCC.BlockAcceleration,
			MaxBlockCount:                 cfg.DDoSCC.MaxBlockCount,
			JSChallengeEnabled:            cfg.DDoSCC.JSChallengeEnabled,
			CaptchaChallengeEnabled:       cfg.DDoSCC.CaptchaChallengeEnabled,
			EnvFingerprintEnabled:         cfg.DDoSCC.EnvFingerprintEnabled,
			PoWChallengeEnabled:           cfg.DDoSCC.PoWChallengeEnabled,
			PoWDifficulty:                 cfg.DDoSCC.PoWDifficulty,
			TrustForwarded:                cfg.Proxy.TrustForwarded,
		},
		log,
	)
	s.sqlInject = sqlinject.NewDetector(cfg.SQLInject.Enabled, cfg.SQLInject.Action, log)
	s.xss = xss.NewDetector(cfg.XSS.Enabled, cfg.XSS.Action, cfg.XSS.FilterResponse, log)
	s.webShell = webshell.NewDetector(cfg.Upload.Enabled, cfg.Upload.Action, log)
	s.bruteForce = bruteforce.NewDefender(
		cfg.BruteForce.Enabled,
		cfg.BruteForce.MaxFailures,
		cfg.BruteForce.WindowSec,
		cfg.BruteForce.BlockDurationSec,
		cfg.BruteForce.ProtectedPaths,
		cfg.BruteForce.StatusCodes,
		log,
	)

	wrCfg := waitingroom.Config{
		Enabled:         cfg.WaitingRoom.Enabled,
		MaxQueueSize:    cfg.WaitingRoom.MaxQueueSize,
		ReleasePerSec:   cfg.WaitingRoom.ReleasePerSec,
		SessionTTLSec:   cfg.WaitingRoom.SessionTTLSec,
		QueueTimeoutSec: cfg.WaitingRoom.QueueTimeoutSec,
		ActiveThreshold: cfg.WaitingRoom.ActiveThreshold,
	}
	s.waitingRoom = waitingroom.New(wrCfg, "shield-wr-secret-key-2026")

	// Auto-activate waiting room based on global request rate and path concentration
	if cfg.WaitingRoom.Enabled {
		go s.waitingRoomAutoActivate()
	}

	return s, nil
}

// waitingRoomAutoActivate periodically checks global rate and path concentration
// and toggles the waiting room on/off accordingly.
// Uses hysteresis: activates when rate exceeds ActiveThreshold or path concentration
// is detected; deactivates only when rate drops to 70% of threshold AND no path
// concentration is active. Queue length is NOT a deactivation condition — requiring
// an empty queue creates a deadlock where new IPs keep joining while active,
// preventing the queue from ever draining after the attack subsides.
func (s *ProxyServer) waitingRoomAutoActivate() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		rate := s.ddosCC.GlobalRequestRate()
		pc := s.ddosCC.IsPathConcentrationActive()
		shouldActivate := rate > s.cfg.WaitingRoom.ActiveThreshold || pc
		shouldDeactivate := rate <= s.cfg.WaitingRoom.ActiveThreshold*0.7 && !pc

		if shouldActivate && !s.waitingRoom.IsActive() {
			s.waitingRoom.SetActive(true)
			s.ddosCC.SetWaitingRoomActive(true)
		} else if shouldDeactivate && s.waitingRoom.IsActive() {
			s.waitingRoom.SetActive(false)
			s.ddosCC.SetWaitingRoomActive(false)
		}
	}
}

// Handler returns the main HTTP handler with all defenses applied.
func (s *ProxyServer) Handler() http.Handler {
	return http.HandlerFunc(s.handle)
}

func (s *ProxyServer) handle(w http.ResponseWriter, r *http.Request) {
	metrics.Get().IncTotalRequests()
	metrics.Get().AddActiveConnections(1)
	defer metrics.Get().AddActiveConnections(-1)

	ip := blacklist.GetClientIP(r.RemoteAddr, r.Header, s.cfg.Proxy.TrustForwarded)

	// Special paths for waiting room (SSE stream, status, release redirect — bypass all checks)
	if s.waitingRoom != nil && r.Method == http.MethodGet {
		switch r.URL.Path {
		case "/__shield_wait_stream":
			s.waitingRoom.SSEHandler()(w, r)
			return
		case "/__shield_wait_status":
			s.waitingRoom.StatusHandler()(w, r)
			return
		}
		// Release callback from waiting room SSE
		if r.URL.Query().Get("__shield_wr_release") == "1" {
			wrCookie := s.waitingRoom.GenerateSessionCookie(ip)
			http.SetCookie(w, &http.Cookie{
				Name:     "__shield_wr",
				Value:    wrCookie,
				Path:     "/",
				HttpOnly: true,
				MaxAge:   s.cfg.WaitingRoom.SessionTTLSec,
				SameSite: http.SameSiteLaxMode,
			})
			cleanURL := r.URL.Path
			q := r.URL.Query()
			q.Del("__shield_wr_release")
			if len(q) > 0 {
				cleanURL += "?" + q.Encode()
			}
			http.Redirect(w, r, cleanURL, http.StatusFound)
			return
		}
	}

	// 0. Global concurrency limit with priority queuing
	if s.semaphore != nil {
		ctx, cancel := context.WithTimeout(r.Context(), time.Duration(s.cfg.Server.QueueTimeoutMs)*time.Millisecond)
		defer cancel()
		// High priority for:
		// 1. Cookie-authenticated users (have proven legitimacy via challenge)
		// 2. IPs not in blacklist AND not marked as suspicious
		hasCookie := s.ddosCC != nil && func() bool {
			_, ok := s.ddosCC.GetSessionCookie(r)
			return ok
		}()
		highPriority := hasCookie ||
			((!s.cfg.Blacklist.Enabled || !s.blacklist.IsBlocked(ip)) &&
				(s.ddosCC == nil || !s.ddosCC.IsSuspicious(ip)))
		acquiredHigh, err := s.semaphore.AcquireWithPriority(ctx, highPriority)
		if err != nil {
			metrics.Get().IncBlockedRequests()
			w.Header().Set("X-Block-Reason", "server_overloaded")
			s.logger.Warn("request_queue_timeout", map[string]interface{}{"ip": ip, "path": r.URL.Path, "error": err.Error()})
			http.Error(w, "503 Service Unavailable", http.StatusServiceUnavailable)
			return
		}
		defer s.semaphore.Release(acquiredHigh)
	}

	// 1. Blacklist check
	if s.cfg.Blacklist.Enabled && s.blacklist.IsBlocked(ip) {
		metrics.Get().IncBlockedRequests()
		w.Header().Set("X-Block-Reason", "blacklist")
		s.logger.Warn("request_blocked_blacklist", map[string]interface{}{"ip": ip, "path": r.URL.Path, "attack_type": "blacklist"})
		http.Error(w, "403 Forbidden", http.StatusForbidden)
		return
	}

	// 2. DDoS/CC early check (Layers 0–3): cookie bypass, global rate, token bucket,
	//    connection limit, slowloris. These low-cost checks use only headers and
	//    counters — no body inspection. Running them BEFORE io.ReadAll cuts off
	//    high-frequency attackers before they can force expensive body reads and
	//    content matching (asymmetric resource-consumption attack).
	var earlyDDoSCCPassed bool
	if s.cfg.DDoSCC.Enabled {
		defer s.ddosCC.Release(ip)
		if s.ddosCC.HasChallengeParams(r) {
			action := s.ddosCC.VerifyChallenge(r)
			switch action {
			case ddoscc.ActionAllow:
				cleanURL := r.URL.Path
				q := r.URL.Query()
				q.Del("__shield_verify")
				q.Del("__shield_token")
				q.Del("__shield_sid")
				q.Del("__shield_answer")
				q.Del("__shield_sig")
				q.Del("__shield_fp")
				q.Del("__shield_hash")
				if len(q) > 0 {
					cleanURL += "?" + q.Encode()
				}
				http.Redirect(w, r, cleanURL, http.StatusFound)
				return
			case ddoscc.ActionJSChallenge, ddoscc.ActionEnvFingerprint, ddoscc.ActionPoWChallenge:
				originalURL := r.URL.Path
				if r.URL.RawQuery != "" {
					q := r.URL.Query()
					q.Del("__shield_verify")
					q.Del("__shield_token")
					q.Del("__shield_sid")
					q.Del("__shield_answer")
					q.Del("__shield_sig")
					q.Del("__shield_fp")
					q.Del("__shield_hash")
					originalURL = r.URL.Path
					if len(q) > 0 {
						originalURL += "?" + q.Encode()
					}
				}
				s.ddosCC.ServeChallenge(w, r, action, originalURL)
				return
			default:
				metrics.Get().IncBlockedRequests()
				w.Header().Set("X-Block-Reason", "ddos/cc:challenge_failed")
				s.logger.Warn("request_blocked_ddoscc", map[string]interface{}{"ip": ip, "path": r.URL.Path, "attack_type": "ddos/cc:challenge", "reason": "challenge_failed"})
				http.Error(w, "403 Forbidden", http.StatusForbidden)
				return
			}
		} else {
			action := s.ddosCC.CheckEarly(r)
			switch action {
			case ddoscc.ActionAllow:
				earlyDDoSCCPassed = true
			case ddoscc.ActionJSChallenge, ddoscc.ActionEnvFingerprint, ddoscc.ActionPoWChallenge:
				originalURL := r.URL.Path
				if r.URL.RawQuery != "" {
					originalURL += "?" + r.URL.RawQuery
				}
				s.ddosCC.ServeChallenge(w, r, action, originalURL)
				return
			case ddoscc.ActionBlock:
				metrics.Get().IncBlockedRequests()
				w.Header().Set("X-Block-Reason", "ddos/cc:block")
				s.logger.Warn("request_blocked_ddoscc", map[string]interface{}{"ip": ip, "path": r.URL.Path, "attack_type": "ddos/cc:block"})
				http.Error(w, "429 Too Many Requests", http.StatusTooManyRequests)
				return
			}
		}
	}

	// Read request body so content detectors can inspect payloads.
	// Use http.MaxBytesReader (not io.LimitReader) to cap memory consumption.
	// http.MaxBytesReader implements io.ReadCloser and properly propagates
	// Close() to the underlying http.connReader, avoiding "invalid concurrent
	// Body.Read call" panics on HTTP connection reuse.
	maxBodySize := int64(s.cfg.Server.MaxBodySize)
	if maxBodySize <= 0 {
		maxBodySize = 10 << 20 // 10 MB default
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBodySize)
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		if strings.Contains(err.Error(), "request body too large") {
			metrics.Get().IncBlockedRequests()
			w.Header().Set("X-Block-Reason", "body_too_large")
			s.logger.Warn("request_body_too_large", map[string]interface{}{
				"ip": ip, "path": r.URL.Path, "size_i64": maxBodySize,
			})
			http.Error(w, "413 Request Entity Too Large", http.StatusRequestEntityTooLarge)
			return
		}
		metrics.Get().IncBlockedRequests()
		http.Error(w, "400 Bad Request", http.StatusBadRequest)
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	r.ContentLength = int64(len(bodyBytes))
	r.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(bodyBytes)), nil
	}

	// 3. Content detectors — inspect body for attack payloads.
	//    Fixed pattern matching (SQLi / XSS / WebShell) runs after the
	//    early DDoS/CC check but before the late-stage DDoS/CC layers,
	//    so signature-based attacks are correctly labeled.
	if s.labelAndBlockContentAttack(w, r, ip, bodyBytes) {
		return
	}

	// 4. Custom rules engine
	if s.rules.Count() > 0 {
		targets := map[string]string{
			"url":    r.URL.String(),
			"method": r.Method,
			"host":   r.Host,
		}
		for k, v := range r.URL.Query() {
			targets["arg_"+k] = v[0]
		}
		if matched, rule := s.rules.MatchRequest("request", targets); matched {
			s.logger.Warn("rule_matched", map[string]interface{}{"rule_id": rule.ID, "ip": ip, "path": r.URL.Path})
			if rule.Action == "block" {
				metrics.Get().IncBlockedRequests()
				w.Header().Set("X-Block-Reason", "rule_matched")
				s.logger.Warn("request_blocked_rule", map[string]interface{}{"rule_id": rule.ID, "ip": ip, "path": r.URL.Path, "attack_type": "rule_matched"})
				http.Error(w, "403 Forbidden", http.StatusForbidden)
				return
			}
		}
	}

	// 5. DDoS/CC late check (Layers 4–7): DDoS pattern detection, sliding window,
	//    UA rotation, behavior + reputation + path concentration. These heavier
	//    checks run AFTER content matching so signature-based attacks are already
	//    intercepted and correctly labeled.
	if s.cfg.DDoSCC.Enabled && earlyDDoSCCPassed {
		action := s.ddosCC.CheckLate(r)
		switch action {
		case ddoscc.ActionAllow:
			// Continue processing
		case ddoscc.ActionJSChallenge, ddoscc.ActionEnvFingerprint, ddoscc.ActionPoWChallenge:
			originalURL := r.URL.Path
			if r.URL.RawQuery != "" {
				originalURL += "?" + r.URL.RawQuery
			}
			s.ddosCC.ServeChallenge(w, r, action, originalURL)
			return
		case ddoscc.ActionBlock:
			metrics.Get().IncBlockedRequests()
			w.Header().Set("X-Block-Reason", "ddos/cc:block")
			s.logger.Warn("request_blocked_ddoscc", map[string]interface{}{"ip": ip, "path": r.URL.Path, "attack_type": "ddos/cc:block"})
			http.Error(w, "429 Too Many Requests", http.StatusTooManyRequests)
			return
		}
	}

	// 6. Brute force detection — runs BEFORE the waiting room so credential
	//    stuffing and brute-force attacks on login endpoints are intercepted
	//    immediately rather than queued behind general peak traffic.
	if s.cfg.BruteForce.Enabled {
		s.bruteForce.RecordRequest(ip, r.URL.Path, r.Method, bodyBytes)
	}
	if s.cfg.BruteForce.Enabled && s.bruteForce.ShouldBlock(ip, r.URL.Path) {
		metrics.Get().IncBlockedRequests()
		w.Header().Set("X-Block-Reason", "brute_force")
		s.logger.Warn("request_blocked_bruteforce", map[string]interface{}{"ip": ip, "path": r.URL.Path, "attack_type": "brute_force"})
		http.Error(w, "429 Too Many Requests", http.StatusTooManyRequests)
		return
	}

	// 7. Waiting room check — peak traffic queuing for users cleared by DDoS/CC
	//    AND brute force detection.
	if s.waitingRoom != nil && s.waitingRoom.IsActive() {
		hasWRBypass := false
		if wrCookie, err := r.Cookie("__shield_wr"); err == nil {
			if _, ok := s.waitingRoom.VerifySessionCookie(wrCookie.Value, ip); ok {
				hasWRBypass = true
			}
		}
		if !hasWRBypass {
			// Reuse existing waiting room session ID from cookie for persistence
			// across page refreshes and reconnections.
			sessionID := ""
			hasSession := false
			if wrSidCookie, err := r.Cookie("__shield_wr_sid"); err == nil {
				sessionID = wrSidCookie.Value
				hasSession = true
			}
			if !hasSession {
				sessionID, hasSession = s.ddosCC.GetSessionCookie(r)
			}
			if !hasSession {
				tmpCookie := s.waitingRoom.GenerateSessionCookie(ip)
				sessionID = strings.SplitN(tmpCookie, ".", 2)[0]
			}

			originalURL := r.URL.Path
			if r.URL.RawQuery != "" {
				originalURL += "?" + r.URL.RawQuery
			}

			pos, err := s.waitingRoom.Join(sessionID, ip, originalURL)
			if err != nil {
				w.Header().Set("X-Block-Reason", "waiting_room_full")
				s.logger.Warn("waiting_room_full", map[string]interface{}{"ip": ip, "path": r.URL.Path})
				http.Error(w, "503 Service Unavailable", http.StatusServiceUnavailable)
				return
			}

			s.logger.Info("waiting_room_joined", map[string]interface{}{
				"ip": ip, "position": pos, "session": sessionID,
			})

			// Persist session ID so the user keeps their queue position across
			// page refreshes and browser reconnections.
			http.SetCookie(w, &http.Cookie{
				Name:     "__shield_wr_sid",
				Value:    sessionID,
				Path:     "/",
				HttpOnly: true,
				MaxAge:   s.cfg.WaitingRoom.QueueTimeoutSec,
				SameSite: http.SameSiteLaxMode,
			})

			s.waitingRoom.ServeWaitingPage(w, r, sessionID, originalURL)
			return
		}
	}

	// Proxy to backend.
	// Reset r.Body before forwarding — content detectors may have consumed
	// it via ParseForm, leaving the bytes.NewReader at EOF.
	r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	r.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(bodyBytes)), nil
	}
	rec := newResponseRecorder(w)
	s.proxy.ServeHTTP(rec, r)

	// Record brute force failures based on backend response (auxiliary detection)
	if s.cfg.BruteForce.Enabled {
		s.bruteForce.RecordFailure(ip, r.URL.Path, rec.statusCode)
	}

	if rec.statusCode >= 400 {
		metrics.Get().IncBlockedRequests()
	} else {
		metrics.Get().IncAllowedRequests()
	}
}


// responseRecorder captures the status code.
type responseRecorder struct {
	http.ResponseWriter
	statusCode int
	written    bool
}

func newResponseRecorder(w http.ResponseWriter) *responseRecorder {
	return &responseRecorder{ResponseWriter: w, statusCode: http.StatusOK}
}

func (rec *responseRecorder) WriteHeader(code int) {
	if rec.written {
		return
	}
	rec.statusCode = code
	rec.written = true
	rec.ResponseWriter.WriteHeader(code)
}

func (rec *responseRecorder) Write(b []byte) (int, error) {
	if !rec.written {
		rec.WriteHeader(http.StatusOK)
	}
	return rec.ResponseWriter.Write(b)
}

// labelAndBlockContentAttack runs all content detectors against the request body.
// If an attack is found, it blocks the request with the correct attack type label and returns true.
func (s *ProxyServer) labelAndBlockContentAttack(w http.ResponseWriter, r *http.Request, ip string, bodyBytes []byte) bool {
	isUpload := strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") || r.Header.Get("X-Filename") != ""

	if isUpload {
		// Check web shell FIRST for uploads to avoid XSS/SQL false positives on multipart body
		if s.cfg.Upload.Enabled {
			if matched, pattern := s.webShell.InspectRequestWithBody(r, bodyBytes); matched {
				if s.cfg.Upload.Action == "block" {
					metrics.Get().IncBlockedRequests()
					w.Header().Set("X-Block-Reason", "webshell_upload")
					s.logger.Warn("request_blocked_webshell", map[string]interface{}{"ip": ip, "pattern": pattern, "path": r.URL.Path, "attack_type": "webshell_upload"})
					http.Error(w, "403 Forbidden", http.StatusForbidden)
					return true
				}
			}
		}
		if s.cfg.SQLInject.Enabled {
			if matched, pattern := s.sqlInject.InspectWithBody(r, bodyBytes); matched {
				if s.cfg.SQLInject.Action == "block" {
					metrics.Get().IncBlockedRequests()
					w.Header().Set("X-Block-Reason", "sql_injection")
					s.logger.Warn("request_blocked_sqlinject", map[string]interface{}{"ip": ip, "pattern": pattern, "path": r.URL.Path, "attack_type": "sql_injection"})
					http.Error(w, "403 Forbidden", http.StatusForbidden)
					return true
				}
			}
		}
		if s.cfg.XSS.Enabled {
			if matched, pattern := s.xss.InspectRequestWithBody(r, bodyBytes); matched {
				if s.cfg.XSS.Action == "block" {
					metrics.Get().IncBlockedRequests()
					w.Header().Set("X-Block-Reason", "xss")
					s.logger.Warn("request_blocked_xss", map[string]interface{}{"ip": ip, "pattern": pattern, "path": r.URL.Path, "attack_type": "xss"})
					http.Error(w, "403 Forbidden", http.StatusForbidden)
					return true
				}
			}
		}
	} else {
		// SQL injection first for non-upload requests
		if s.cfg.SQLInject.Enabled {
			if matched, pattern := s.sqlInject.InspectWithBody(r, bodyBytes); matched {
				if s.cfg.SQLInject.Action == "block" {
					metrics.Get().IncBlockedRequests()
					w.Header().Set("X-Block-Reason", "sql_injection")
					s.logger.Warn("request_blocked_sqlinject", map[string]interface{}{"ip": ip, "pattern": pattern, "path": r.URL.Path, "attack_type": "sql_injection"})
					http.Error(w, "403 Forbidden", http.StatusForbidden)
					return true
				}
			}
		}
		if s.cfg.XSS.Enabled {
			if matched, pattern := s.xss.InspectRequestWithBody(r, bodyBytes); matched {
				if s.cfg.XSS.Action == "block" {
					metrics.Get().IncBlockedRequests()
					w.Header().Set("X-Block-Reason", "xss")
					s.logger.Warn("request_blocked_xss", map[string]interface{}{"ip": ip, "pattern": pattern, "path": r.URL.Path, "attack_type": "xss"})
					http.Error(w, "403 Forbidden", http.StatusForbidden)
					return true
				}
			}
		}
		if s.cfg.Upload.Enabled {
			if matched, pattern := s.webShell.InspectRequestWithBody(r, bodyBytes); matched {
				if s.cfg.Upload.Action == "block" {
					metrics.Get().IncBlockedRequests()
					w.Header().Set("X-Block-Reason", "webshell_upload")
					s.logger.Warn("request_blocked_webshell", map[string]interface{}{"ip": ip, "pattern": pattern, "path": r.URL.Path, "attack_type": "webshell_upload"})
					http.Error(w, "403 Forbidden", http.StatusForbidden)
					return true
				}
			}
		}
	}
	return false
}

// Run starts the shield server.
func RunProxy(cfg *config.Config, log *logger.Logger, bl *blacklist.Manager, rl *rules.Engine) error {
	srv, err := NewProxyServer(cfg, log, bl, rl)
	if err != nil {
		return err
	}

	server := &http.Server{
		Addr:           cfg.Server.BindAddr,
		Handler:        srv.Handler(),
		ReadTimeout:    time.Duration(cfg.Server.ReadTimeoutMs) * time.Millisecond,
		WriteTimeout:   time.Duration(cfg.Server.WriteTimeoutMs) * time.Millisecond,
		MaxHeaderBytes: cfg.Server.MaxHeaderBytes,
	}

	log.Info("shield_server_starting", map[string]interface{}{
		"bind":   cfg.Server.BindAddr,
		"target": cfg.Proxy.TargetURL,
	})
	return server.ListenAndServe()
}
