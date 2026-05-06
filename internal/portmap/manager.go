package portmap

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/shield/shield/internal/handler"
	"github.com/shield/shield/internal/service/rules"
	"github.com/shield/shield/internal/storage/blacklist"
	"github.com/shield/shield/pkg/config"
	"github.com/shield/shield/pkg/logger"
)

type Manager struct {
	mu      sync.Mutex
	servers map[string]*http.Server
	logger  *logger.Logger
}

func NewManager(log *logger.Logger) *Manager {
	return &Manager{
		servers: make(map[string]*http.Server),
		logger:  log,
	}
}

func (m *Manager) Start(mappings []config.PortMappingItem, cfg *config.Config, lg *logger.Logger, bl *blacklist.Manager, re *rules.Engine) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, mapping := range mappings {
		if _, exists := m.servers[mapping.ID]; exists {
			lg.Warn("portmap_skip_duplicate", map[string]interface{}{
				"id":     mapping.ID,
				"listen": mapping.Listen,
			})
			continue
		}

		mapCfg := cloneConfigForMapping(cfg, mapping.Listen, mapping.Target)

		proxySrv, err := handler.NewProxyServer(mapCfg, lg, bl, re)
		if err != nil {
			lg.Error("portmap_create_failed", map[string]interface{}{
				"id":    mapping.ID,
				"error": err.Error(),
			})
			continue
		}

		srv := &http.Server{
			Addr:           mapping.Listen,
			Handler:        proxySrv.Handler(),
			ReadTimeout:    time.Duration(mapCfg.Server.ReadTimeoutMs) * time.Millisecond,
			WriteTimeout:   time.Duration(mapCfg.Server.WriteTimeoutMs) * time.Millisecond,
			MaxHeaderBytes: mapCfg.Server.MaxHeaderBytes,
		}

		m.servers[mapping.ID] = srv

		go func(id string, listen string, target string, server *http.Server) {
			lg.Info("portmap_starting", map[string]interface{}{
				"id":     id,
				"listen": listen,
				"target": target,
			})
			if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				lg.Error("portmap_listen_error", map[string]interface{}{
					"id":    id,
					"error": err.Error(),
				})
			}
		}(mapping.ID, mapping.Listen, mapping.Target, srv)
	}

	return nil
}

func (m *Manager) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	for id, srv := range m.servers {
		m.logger.Info("portmap_stopping", map[string]interface{}{"id": id})
		if err := srv.Shutdown(ctx); err != nil {
			m.logger.Error("portmap_shutdown_error", map[string]interface{}{
				"id":    id,
				"error": err.Error(),
			})
		}
	}

	m.servers = make(map[string]*http.Server)
}

func cloneConfigForMapping(cfg *config.Config, listen, target string) *config.Config {
	clone := *cfg

	if cfg.Proxy.SetHeaders != nil {
		clone.Proxy.SetHeaders = make(map[string]string, len(cfg.Proxy.SetHeaders))
		for k, v := range cfg.Proxy.SetHeaders {
			clone.Proxy.SetHeaders[k] = v
		}
	} else {
		clone.Proxy.SetHeaders = nil
	}

	if cfg.BruteForce.ProtectedPaths != nil {
		clone.BruteForce.ProtectedPaths = make([]string, len(cfg.BruteForce.ProtectedPaths))
		copy(clone.BruteForce.ProtectedPaths, cfg.BruteForce.ProtectedPaths)
	} else {
		clone.BruteForce.ProtectedPaths = nil
	}

	if cfg.BruteForce.StatusCodes != nil {
		clone.BruteForce.StatusCodes = make([]int, len(cfg.BruteForce.StatusCodes))
		copy(clone.BruteForce.StatusCodes, cfg.BruteForce.StatusCodes)
	} else {
		clone.BruteForce.StatusCodes = nil
	}

	if cfg.PortMappings != nil {
		clone.PortMappings = make([]config.PortMappingItem, len(cfg.PortMappings))
		copy(clone.PortMappings, cfg.PortMappings)
	} else {
		clone.PortMappings = nil
	}

	clone.Server.BindAddr = listen
	clone.Proxy.TargetURL = "http://" + target
	return &clone
}

func ValidateMappings(mappings []config.PortMappingItem) error {
	ids := make(map[string]bool)
	for _, m := range mappings {
		if m.ID == "" {
			return fmt.Errorf("port mapping missing id")
		}
		if ids[m.ID] {
			return fmt.Errorf("duplicate port mapping id: %s", m.ID)
		}
		ids[m.ID] = true

		if m.Listen == "" {
			return fmt.Errorf("port mapping %s: missing listen address", m.ID)
		}
		if m.Target == "" {
			return fmt.Errorf("port mapping %s: missing target", m.ID)
		}

		parts := strings.Split(m.Target, ":")
		if len(parts) != 2 || net.ParseIP(parts[0]) == nil {
			return fmt.Errorf("port mapping %s: invalid target %q (must be ip:port)", m.ID, m.Target)
		}
	}
	return nil
}
