package blacklist

import (
	"encoding/json"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// Entry represents a blacklisted IP record.
type Entry struct {
	IP         string    `json:"ip"`
	Reason     string    `json:"reason"`
	BlockedAt  time.Time `json:"blocked_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	Permanent  bool      `json:"permanent"`
}

// Manager manages IP blacklist with persistence.
type Manager struct {
	mu       sync.RWMutex
	entries  map[string]*Entry
	path     string
}

// NewManager creates a blacklist manager.
func NewManager(path string) *Manager {
	m := &Manager{
		entries: make(map[string]*Entry),
		path:    path,
	}
	if err := m.Load(); err != nil {
		log.Printf("blacklist load failed: %v", err)
	}
	return m
}

// Load reads blacklist from disk.
func (m *Manager) Load() error {
	if m.path == "" {
		return nil
	}
	data, err := os.ReadFile(m.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var list []Entry
	if err := json.Unmarshal(data, &list); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	for _, e := range list {
		if !e.Permanent && e.ExpiresAt.Before(now) {
			continue
		}
		m.entries[e.IP] = &e
	}
	return nil
}

// Save writes blacklist to disk. Caller must NOT hold the lock.
func (m *Manager) Save() error {
	if m.path == "" {
		return nil
	}
	m.mu.RLock()
	list := make([]Entry, 0, len(m.entries))
	for _, e := range m.entries {
		list = append(list, *e)
	}
	m.mu.RUnlock()

	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(m.path, data, 0644)
}

// saveUnsafe writes blacklist to disk assuming lock is already held.
func (m *Manager) saveUnsafe() error {
	if m.path == "" {
		return nil
	}
	list := make([]Entry, 0, len(m.entries))
	for _, e := range m.entries {
		list = append(list, *e)
	}
	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(m.path, data, 0644)
}

// Add adds an IP to the blacklist.
func (m *Manager) Add(ip, reason string, duration time.Duration, permanent bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries[ip] = &Entry{
		IP:        ip,
		Reason:    reason,
		BlockedAt: time.Now(),
		ExpiresAt: time.Now().Add(duration),
		Permanent: permanent,
	}
	if err := m.saveUnsafe(); err != nil {
		log.Printf("blacklist save failed: %v", err)
	}
}

// Remove removes an IP from the blacklist.
func (m *Manager) Remove(ip string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.entries, ip)
	if err := m.saveUnsafe(); err != nil {
		log.Printf("blacklist save failed: %v", err)
	}
}

// IsBlocked checks if an IP is currently blocked.
func (m *Manager) IsBlocked(ip string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	e, ok := m.entries[ip]
	if !ok {
		return false
	}
	if e.Permanent {
		return true
	}
	if time.Now().Before(e.ExpiresAt) {
		return true
	}
	return false
}

// List returns all active entries.
func (m *Manager) List() []Entry {
	m.mu.RLock()
	defer m.mu.RUnlock()
	now := time.Now()
	list := make([]Entry, 0, len(m.entries))
	for _, e := range m.entries {
		if e.Permanent || e.ExpiresAt.After(now) {
			list = append(list, *e)
		}
	}
	return list
}

// Cleanup removes expired entries.
func (m *Manager) Cleanup() {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	for ip, e := range m.entries {
		if !e.Permanent && e.ExpiresAt.Before(now) {
			delete(m.entries, ip)
		}
	}
}

// StartCleanupLoop runs periodic cleanup and persists changes to disk.
// Call this once on startup to prevent unbounded growth of expired entries.
func (m *Manager) StartCleanupLoop() {
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			m.Cleanup()
			if err := m.Save(); err != nil {
				log.Printf("blacklist cleanup save failed: %v", err)
			}
		}
	}()
}

// GetClientIP extracts client IP from request, respecting X-Forwarded-For.
func GetClientIP(remoteAddr string, headers map[string][]string, trustForwarded bool) string {
	if trustForwarded {
		if xff := headers["X-Forwarded-For"]; len(xff) > 0 && xff[0] != "" {
			ip, _, _ := strings.Cut(xff[0], ",")
			ip = strings.TrimSpace(ip)
			if ip != "" {
				return ip
			}
		}
		if xri := headers["X-Real-Ip"]; len(xri) > 0 && xri[0] != "" {
			ip := strings.TrimSpace(xri[0])
			if ip != "" {
				return ip
			}
		}
	}
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}
