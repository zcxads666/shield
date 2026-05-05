package handler

import (
	"encoding/json"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/shield/shield/internal/storage/blacklist"
	"github.com/shield/shield/pkg/config"
	"github.com/shield/shield/pkg/metrics"
	"github.com/shield/shield/pkg/version"
)

// Server provides admin HTTP endpoints.
type AdminServer struct {
	cfg       *config.Config
	blacklist *blacklist.Manager
}

// NewServer creates an admin server.
func NewAdminServer(cfg *config.Config, bl *blacklist.Manager) *AdminServer {
	return &AdminServer{cfg: cfg, blacklist: bl}
}

// Handler returns the admin HTTP handler.
func (s *AdminServer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/stats", s.handleStats)
	mux.HandleFunc("/blacklist", s.handleBlacklist)
	mux.HandleFunc("/health", s.handleHealth)
	return mux
}

func (s *AdminServer) handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	m := metrics.Get().Snapshot()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]interface{}{
		"total_requests":     m.TotalRequests,
		"blocked_requests":   m.BlockedRequests,
		"allowed_requests":   m.AllowedRequests,
		"active_connections": m.ActiveConnections,
		"sql_injections":     m.SQLInjections,
		"xss_attempts":       m.XSSAttempts,
		"webshell_uploads":   m.WebShellUploads,
		"ddos_cc_blocks":     m.DDoSCCBlocks,
		"brute_force_blocks": m.BruteForceBlocks,
		"blacklisted_ips":    m.BlacklistedIPs,
		"timestamp":          time.Now().Format(time.RFC3339),
	}); err != nil {
		log.Printf("admin stats encode error: %v", err)
	}
}

func (s *AdminServer) handleBlacklist(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		list := s.blacklist.List()
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(list); err != nil {
			log.Printf("admin blacklist encode error: %v", err)
		}
	case http.MethodPost:
		var req struct {
			IP       string `json:"ip"`
			Reason   string `json:"reason"`
			Duration int    `json:"duration_sec"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if net.ParseIP(req.IP) == nil {
			http.Error(w, "invalid ip", http.StatusBadRequest)
			return
		}
		s.blacklist.Add(req.IP, req.Reason, time.Duration(req.Duration)*time.Second, req.Duration == 0)
		w.WriteHeader(http.StatusCreated)
		if err := json.NewEncoder(w).Encode(map[string]string{"status": "added"}); err != nil {
			log.Printf("admin blacklist add encode error: %v", err)
		}
	case http.MethodDelete:
		ip := r.URL.Query().Get("ip")
		if ip == "" {
			http.Error(w, "missing ip", http.StatusBadRequest)
			return
		}
		s.blacklist.Remove(ip)
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(map[string]string{"status": "removed"}); err != nil {
			log.Printf("admin blacklist remove encode error: %v", err)
		}
	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

func (s *AdminServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]string{
		"status":  "ok",
		"version": version.Version,
	}); err != nil {
		log.Printf("admin health encode error: %v", err)
	}
}
