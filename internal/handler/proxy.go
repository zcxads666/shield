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
func (s *ProxyServer) waitingRoomAutoActivate() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		rate := s.ddosCC.GlobalRequestRate()
		pc := s.ddosCC.IsPathConcentrationActive()
		shouldActivate := rate > s.cfg.WaitingRoom.ActiveThreshold || pc

		if shouldActivate && !s.waitingRoom.IsActive() {
			s.waitingRoom.SetActive(true)
		} else if !shouldActivate && s.waitingRoom.IsActive() && s.waitingRoom.QueueLength() == 0 {
			s.waitingRoom.SetActive(false)
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
		// 1. IPs not in blacklist
		// 2. IPs not marked as suspicious by reputation tracker
		highPriority := (!s.cfg.Blacklist.Enabled || !s.blacklist.IsBlocked(ip)) &&
			(s.ddosCC == nil || !s.ddosCC.IsSuspicious(ip))
		acquiredHigh, err := s.semaphore.AcquireWithPriority(ctx, highPriority)
		if err != nil {
			metrics.Get().IncBlockedRequests()
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

	// Read request body early — before CC — so content detectors can inspect
	// payloads even when rate limiting triggers. This enables correct attack
	// type labeling (SQLi / XSS / WebShell) instead of everything being "cc_attack".
	bodyBytes, _ := io.ReadAll(r.Body)
	r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	r.ContentLength = int64(len(bodyBytes))

	// 2. Unified DDoS/CC detection (global flood, multi-IP, per-IP rate, challenge-response)
	if s.cfg.DDoSCC.Enabled {
		if s.ddosCC.HasChallengeParams(r) {
			action := s.ddosCC.VerifyChallenge(r)
			switch action {
			case ddoscc.ActionAllow:
				// Challenge passed — strip shield params and redirect to clean URL
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
			action := s.ddosCC.Check(r)
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
				// Before blocking, check if body contains attack payloads
				// so we label the block with the correct attack type.
				if s.labelAndBlockContentAttack(w, r, ip, bodyBytes) {
					return
				}
				metrics.Get().IncBlockedRequests()
				w.Header().Set("X-Block-Reason", "ddos/cc:block")
				s.logger.Warn("request_blocked_ddoscc", map[string]interface{}{"ip": ip, "path": r.URL.Path, "attack_type": "ddos/cc:block"})
				http.Error(w, "429 Too Many Requests", http.StatusTooManyRequests)
				return
			}
		}
		defer s.ddosCC.Release(ip)
	}

	// 3. Waiting room check — peak traffic queuing for users cleared by DDoS/CC
	if s.waitingRoom != nil && s.waitingRoom.IsActive() {
		hasWRBypass := false
		if wrCookie, err := r.Cookie("__shield_wr"); err == nil {
			if _, ok := s.waitingRoom.VerifySessionCookie(wrCookie.Value, ip); ok {
				hasWRBypass = true
			}
		}
		if !hasWRBypass {
			sessionID, hasSession := s.ddosCC.GetSessionCookie(r)
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
				s.logger.Warn("waiting_room_full", map[string]interface{}{"ip": ip, "path": r.URL.Path})
				http.Error(w, "503 Service Unavailable", http.StatusServiceUnavailable)
				return
			}

			s.logger.Info("waiting_room_joined", map[string]interface{}{
				"ip": ip, "position": pos, "session": sessionID,
			})

			s.waitingRoom.ServeWaitingPage(w, r, sessionID, originalURL)
			return
		}
	}

	// 4. Record request for brute force detection BEFORE the block check
	if s.cfg.BruteForce.Enabled {
		s.bruteForce.RecordRequest(ip, r.URL.Path, r.Method, bodyBytes)
	}

	// 5. Brute force check (after RecordRequest for correct concurrent counting)
	if s.cfg.BruteForce.Enabled && s.bruteForce.ShouldBlock(ip, r.URL.Path) {
		metrics.Get().IncBlockedRequests()
		w.Header().Set("X-Block-Reason", "brute_force")
		s.logger.Warn("request_blocked_bruteforce", map[string]interface{}{"ip": ip, "path": r.URL.Path, "attack_type": "brute_force"})
		http.Error(w, "429 Too Many Requests", http.StatusTooManyRequests)
		return
	}

	// 6. Custom rules engine
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

	// 7. Content detectors — inspect body for attack payloads
	if s.labelAndBlockContentAttack(w, r, ip, bodyBytes) {
		return
	}

	// Proxy to backend
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

// blockRequest is a helper to block requests with a reason header.
func (s *ProxyServer) blockRequest(w http.ResponseWriter, reason string, statusCode int) {
	metrics.Get().IncBlockedRequests()
	w.Header().Set("X-Block-Reason", reason)
	http.Error(w, http.StatusText(statusCode), statusCode)
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
