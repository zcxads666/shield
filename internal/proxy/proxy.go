package proxy

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

	"github.com/shield/shield/internal/blacklist"
	"github.com/shield/shield/internal/config"
	"github.com/shield/shield/internal/defender"
	"github.com/shield/shield/internal/logger"
	"github.com/shield/shield/internal/metrics"
	"github.com/shield/shield/internal/rules"
)

// Server wraps the reverse proxy and defense middleware.
type Server struct {
	cfg           *config.Config
	proxy         *httputil.ReverseProxy
	logger        *logger.Logger
	blacklist     *blacklist.Manager
	dDOS          *defender.DDoSDefender
	cc            *defender.CCDetector
	sqlInject     *defender.SQLInjector
	xss           *defender.XSSDetector
	webShell      *defender.WebShellDetector
	bruteForce    *defender.BruteForceDefender
	rules         *rules.Engine
	semaphore     *PrioritySemaphore
	ipReputation  *IPReputation
}

// NewServer creates a shield proxy server.
func NewServer(cfg *config.Config, log *logger.Logger, bl *blacklist.Manager, rl *rules.Engine) (*Server, error) {
	target, err := url.Parse(cfg.Proxy.TargetURL)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL: %w", err)
	}

	rp := httputil.NewSingleHostReverseProxy(target)
	rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Error("proxy_error", map[string]interface{}{"error": err.Error(), "path": r.URL.Path})
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
	}

	semaphore := NewPrioritySemaphore(cfg.Server.MaxConcurrent, cfg.Server.HighPriorityRatio)
	// IP reputation: 10-second window, 20 requests threshold for suspicious
	ipReputation := NewIPReputation(10*time.Second, 20)

	s := &Server{
		cfg:          cfg,
		proxy:        rp,
		logger:       log,
		blacklist:    bl,
		rules:        rl,
		semaphore:    semaphore,
		ipReputation: ipReputation,
	}

	// Initialize defenders
	s.dDOS = defender.NewDDoSDefender(
		cfg.DDoS.Enabled,
		cfg.DDoS.MaxConnectionsPerIP,
		cfg.DDoS.SlowlorisTimeoutMs,
		cfg.RateLimit.RequestsPerSecond,
		cfg.RateLimit.BurstSize,
		cfg.Proxy.TrustForwarded,
		log,
	)
	s.cc = defender.NewCCDetector(
		cfg.CC.Enabled,
		cfg.CC.MaxRequests,
		cfg.CC.WindowSec,
		cfg.Proxy.TrustForwarded,
		log,
	)
	s.sqlInject = defender.NewSQLInjector(cfg.SQLInject.Enabled, cfg.SQLInject.Action, log)
	s.xss = defender.NewXSSDetector(cfg.XSS.Enabled, cfg.XSS.Action, cfg.XSS.FilterResponse, log)
	s.webShell = defender.NewWebShellDetector(cfg.Upload.Enabled, cfg.Upload.Action, log)
	s.bruteForce = defender.NewBruteForceDefender(
		cfg.BruteForce.Enabled,
		cfg.BruteForce.MaxFailures,
		cfg.BruteForce.WindowSec,
		cfg.BruteForce.BlockDurationSec,
		cfg.BruteForce.ProtectedPaths,
		cfg.BruteForce.StatusCodes,
		log,
	)

	return s, nil
}

// Handler returns the main HTTP handler with all defenses applied.
func (s *Server) Handler() http.Handler {
	return s.dDOS.WrapHandler(http.HandlerFunc(s.handle))
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	metrics.Get().IncTotalRequests()
	metrics.Get().AddActiveConnections(1)
	defer metrics.Get().AddActiveConnections(-1)

	ip := blacklist.GetClientIP(r.RemoteAddr, r.Header, s.cfg.Proxy.TrustForwarded)

	// Record IP for reputation tracking
	if s.ipReputation != nil {
		s.ipReputation.Record(ip)
	}

	// 0. Global concurrency limit with priority queuing
	if s.semaphore != nil {
		ctx, cancel := context.WithTimeout(r.Context(), time.Duration(s.cfg.Server.QueueTimeoutMs)*time.Millisecond)
		defer cancel()
		// High priority for:
		// 1. IPs not in blacklist
		// 2. IPs not marked as suspicious by reputation tracker
		highPriority := (!s.cfg.Blacklist.Enabled || !s.blacklist.IsBlocked(ip)) &&
			(s.ipReputation == nil || !s.ipReputation.IsSuspicious(ip))
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

	// 2. CC attack check (application-layer, same URL high frequency)
	if s.cfg.CC.Enabled && !s.cc.Allow(r) {
		metrics.Get().IncBlockedRequests()
		metrics.Get().IncCCBlocks()
		w.Header().Set("X-Block-Reason", "cc_attack")
		s.logger.Warn("request_blocked_cc", map[string]interface{}{"ip": ip, "path": r.URL.Path, "attack_type": "cc_attack"})
		http.Error(w, "429 Too Many Requests", http.StatusTooManyRequests)
		return
	}

	// 3. Brute force check
	if s.cfg.BruteForce.Enabled && s.bruteForce.ShouldBlock(ip, r.URL.Path) {
		metrics.Get().IncBlockedRequests()
		w.Header().Set("X-Block-Reason", "brute_force")
		s.logger.Warn("request_blocked_bruteforce", map[string]interface{}{"ip": ip, "path": r.URL.Path, "attack_type": "brute_force"})
		http.Error(w, "429 Too Many Requests", http.StatusTooManyRequests)
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

	// Save and restore request body for inspection + proxy forwarding
	bodyBytes, _ := io.ReadAll(r.Body)
	r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	r.ContentLength = int64(len(bodyBytes))

	// Check if this is an upload request (multipart or has X-Filename header)
	isUpload := strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") || r.Header.Get("X-Filename") != ""

	// For upload requests, check web shell FIRST to avoid XSS/SQL false positives
	// on multipart body content. For non-upload requests, keep original order.
	if isUpload {
		// 5a. Web shell upload check (first for uploads)
		if s.cfg.Upload.Enabled {
			if matched, pattern := s.webShell.InspectRequestWithBody(r, bodyBytes); matched {
				if s.cfg.Upload.Action == "block" {
					metrics.Get().IncBlockedRequests()
					w.Header().Set("X-Block-Reason", "webshell_upload")
					s.logger.Warn("request_blocked_webshell", map[string]interface{}{"ip": ip, "pattern": pattern, "path": r.URL.Path, "attack_type": "webshell_upload"})
					http.Error(w, "403 Forbidden", http.StatusForbidden)
					return
				}
			}
		}
		// 5b. SQL injection check
		if s.cfg.SQLInject.Enabled {
			if matched, pattern := s.sqlInject.InspectWithBody(r, bodyBytes); matched {
				if s.cfg.SQLInject.Action == "block" {
					metrics.Get().IncBlockedRequests()
					w.Header().Set("X-Block-Reason", "sql_injection")
					s.logger.Warn("request_blocked_sqlinject", map[string]interface{}{"ip": ip, "pattern": pattern, "path": r.URL.Path, "attack_type": "sql_injection"})
					http.Error(w, "403 Forbidden", http.StatusForbidden)
					return
				}
			}
		}
		// 5c. XSS check
		if s.cfg.XSS.Enabled {
			if matched, pattern := s.xss.InspectRequestWithBody(r, bodyBytes); matched {
				if s.cfg.XSS.Action == "block" {
					metrics.Get().IncBlockedRequests()
					w.Header().Set("X-Block-Reason", "xss")
					s.logger.Warn("request_blocked_xss", map[string]interface{}{"ip": ip, "pattern": pattern, "path": r.URL.Path, "attack_type": "xss"})
					http.Error(w, "403 Forbidden", http.StatusForbidden)
					return
				}
			}
		}
	} else {
		// Original order for non-upload requests
		// 5. SQL injection check
		if s.cfg.SQLInject.Enabled {
			if matched, pattern := s.sqlInject.InspectWithBody(r, bodyBytes); matched {
				if s.cfg.SQLInject.Action == "block" {
					metrics.Get().IncBlockedRequests()
					w.Header().Set("X-Block-Reason", "sql_injection")
					s.logger.Warn("request_blocked_sqlinject", map[string]interface{}{"ip": ip, "pattern": pattern, "path": r.URL.Path, "attack_type": "sql_injection"})
					http.Error(w, "403 Forbidden", http.StatusForbidden)
					return
				}
			}
		}

		// 6. XSS check
		if s.cfg.XSS.Enabled {
			if matched, pattern := s.xss.InspectRequestWithBody(r, bodyBytes); matched {
				if s.cfg.XSS.Action == "block" {
					metrics.Get().IncBlockedRequests()
					w.Header().Set("X-Block-Reason", "xss")
					s.logger.Warn("request_blocked_xss", map[string]interface{}{"ip": ip, "pattern": pattern, "path": r.URL.Path, "attack_type": "xss"})
					http.Error(w, "403 Forbidden", http.StatusForbidden)
					return
				}
			}
		}

		// 7. Web shell upload check
		if s.cfg.Upload.Enabled {
			if matched, pattern := s.webShell.InspectRequestWithBody(r, bodyBytes); matched {
				if s.cfg.Upload.Action == "block" {
					metrics.Get().IncBlockedRequests()
					w.Header().Set("X-Block-Reason", "webshell_upload")
					s.logger.Warn("request_blocked_webshell", map[string]interface{}{"ip": ip, "pattern": pattern, "path": r.URL.Path, "attack_type": "webshell_upload"})
					http.Error(w, "403 Forbidden", http.StatusForbidden)
					return
				}
			}
		}
	}

	// Restore body for proxy forwarding
	r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	r.ContentLength = int64(len(bodyBytes))

	// Proxy to backend
	rec := newResponseRecorder(w)
	s.proxy.ServeHTTP(rec, r)

	// Record brute force failures based on backend response
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
func (s *Server) blockRequest(w http.ResponseWriter, reason string, statusCode int) {
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

// Run starts the shield server.
func Run(cfg *config.Config, log *logger.Logger, bl *blacklist.Manager, rl *rules.Engine) error {
	srv, err := NewServer(cfg, log, bl, rl)
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
