package waitingroom

import (
	"crypto/hmac"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Config holds waiting room settings.
type Config struct {
	Enabled         bool    `yaml:"enabled"`
	MaxQueueSize    int     `yaml:"max_queue_size"`
	ReleasePerSec   float64 `yaml:"release_per_sec"`
	SessionTTLSec   int     `yaml:"session_ttl_sec"`
	QueueTimeoutSec int     `yaml:"queue_timeout_sec"`
	ActiveThreshold float64 `yaml:"active_threshold"`
}

// DefaultConfig returns sensible defaults.
func DefaultConfig() Config {
	return Config{
		Enabled:         false,
		MaxQueueSize:    5000,
		ReleasePerSec:   5.0,
		SessionTTLSec:   300,
		QueueTimeoutSec: 300,
		ActiveThreshold: 40.0,
	}
}

type entry struct {
	SessionID   string
	IP          string
	OriginalURL string
	JoinedAt    time.Time
	released    chan struct{}
}

// WaitingRoom manages a FIFO queue for peak traffic control.
type WaitingRoom struct {
	mu          sync.Mutex
	queue       []*entry
	entries     map[string]*entry
	cfg         Config
	secretKey   []byte
	active      int32
	releaseTick *time.Ticker
	stopCh      chan struct{}
}

// New creates a new WaitingRoom and starts the release goroutine.
func New(cfg Config, secretKey string) *WaitingRoom {
	wr := &WaitingRoom{
		queue:     make([]*entry, 0, cfg.MaxQueueSize),
		entries:   make(map[string]*entry),
		cfg:       cfg,
		secretKey: []byte(secretKey),
		stopCh:    make(chan struct{}),
	}
	if cfg.Enabled {
		interval := time.Duration(float64(time.Second) / cfg.ReleasePerSec)
		if interval < 50*time.Millisecond {
			interval = 50 * time.Millisecond
		}
		wr.releaseTick = time.NewTicker(interval)
		go wr.run()
	}
	return wr
}

func (wr *WaitingRoom) run() {
	for {
		select {
		case <-wr.releaseTick.C:
			wr.releaseOne()
		case <-wr.stopCh:
			return
		}
	}
}

func (wr *WaitingRoom) releaseOne() {
	wr.mu.Lock()
	if len(wr.queue) == 0 {
		wr.mu.Unlock()
		return
	}
	e := wr.queue[0]
	wr.queue = wr.queue[1:]
	delete(wr.entries, e.SessionID)
	wr.mu.Unlock()
	close(e.released)
}

// Join adds a user to the queue and returns their 1-indexed position.
func (wr *WaitingRoom) Join(sessionID, ip, originalURL string) (int, error) {
	wr.mu.Lock()
	defer wr.mu.Unlock()

	if e, ok := wr.entries[sessionID]; ok {
		return wr.positionLocked(e), nil
	}

	if len(wr.queue) >= wr.cfg.MaxQueueSize {
		return 0, fmt.Errorf("queue full")
	}

	e := &entry{
		SessionID:   sessionID,
		IP:          ip,
		OriginalURL: originalURL,
		JoinedAt:    time.Now(),
		released:    make(chan struct{}),
	}
	wr.queue = append(wr.queue, e)
	wr.entries[sessionID] = e
	return len(wr.queue), nil
}

// Leave removes a user from the queue.
func (wr *WaitingRoom) Leave(sessionID string) {
	wr.mu.Lock()
	defer wr.mu.Unlock()

	e, ok := wr.entries[sessionID]
	if !ok {
		return
	}
	delete(wr.entries, sessionID)
	for i, qe := range wr.queue {
		if qe == e {
			wr.queue = append(wr.queue[:i], wr.queue[i+1:]...)
			break
		}
	}
}

// Position returns the 1-indexed queue position, or 0 if released/not in queue.
func (wr *WaitingRoom) Position(sessionID string) int {
	wr.mu.Lock()
	defer wr.mu.Unlock()

	e, ok := wr.entries[sessionID]
	if !ok {
		return 0
	}
	return wr.positionLocked(e)
}

func (wr *WaitingRoom) positionLocked(e *entry) int {
	for i, qe := range wr.queue {
		if qe == e {
			return i + 1
		}
	}
	return 0
}

// WaitForRelease blocks until the entry is released or timeout expires.
func (wr *WaitingRoom) WaitForRelease(sessionID string, timeout time.Duration) error {
	wr.mu.Lock()
	e, ok := wr.entries[sessionID]
	wr.mu.Unlock()

	if !ok {
		return nil
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case <-e.released:
		return nil
	case <-timer.C:
		wr.Leave(sessionID)
		return fmt.Errorf("queue timeout")
	}
}

// SetActive toggles the waiting room on/off.
func (wr *WaitingRoom) SetActive(v bool) {
	var val int32
	if v {
		val = 1
	}
	atomic.StoreInt32(&wr.active, val)
}

// IsActive returns whether the waiting room is currently active.
func (wr *WaitingRoom) IsActive() bool {
	return wr.cfg.Enabled && atomic.LoadInt32(&wr.active) == 1
}

// QueueLength returns the current number of users in the queue.
func (wr *WaitingRoom) QueueLength() int {
	wr.mu.Lock()
	defer wr.mu.Unlock()
	return len(wr.queue)
}

// EstimatedWait returns the estimated wait duration for a given position.
func (wr *WaitingRoom) EstimatedWait(position int) time.Duration {
	if position <= 0 {
		return 0
	}
	secPerRelease := 1.0 / wr.cfg.ReleasePerSec
	return time.Duration(float64(position)*secPerRelease) * time.Second
}

// GenerateSessionCookie creates a signed session cookie for the waiting room.
func (wr *WaitingRoom) GenerateSessionCookie(ip string) string {
	b := make([]byte, 16)
	crand.Read(b)
	sessionID := hex.EncodeToString(b)

	mac := hmac.New(sha256.New, wr.secretKey)
	mac.Write([]byte("wr|" + sessionID + "|" + ip))
	sig := hex.EncodeToString(mac.Sum(nil))

	return sessionID + "." + sig
}

// VerifySessionCookie validates a waiting room cookie and returns the session ID.
func (wr *WaitingRoom) VerifySessionCookie(cookie, ip string) (string, bool) {
	parts := strings.SplitN(cookie, ".", 2)
	if len(parts) != 2 {
		return "", false
	}
	sessionID := parts[0]
	sig := parts[1]

	mac := hmac.New(sha256.New, wr.secretKey)
	mac.Write([]byte("wr|" + sessionID + "|" + ip))
	expected := hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(sig), []byte(expected)) {
		return "", false
	}
	return sessionID, true
}

// Stop gracefully shuts down the waiting room goroutines.
func (wr *WaitingRoom) Stop() {
	close(wr.stopCh)
	if wr.releaseTick != nil {
		wr.releaseTick.Stop()
	}
}

// GetGlobalRateFunc is a callback to fetch the current global request rate.
// Used to auto-activate the waiting room during peak traffic.
type GetGlobalRateFunc func() float64

// AutoActivate periodically checks the global rate and toggles the waiting room.
func (wr *WaitingRoom) AutoActivate(rateFn GetGlobalRateFunc) {
	if !wr.cfg.Enabled {
		return
	}
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			rate := rateFn()
			if rate > wr.cfg.ActiveThreshold && !wr.IsActive() {
				wr.SetActive(true)
			} else if rate <= wr.cfg.ActiveThreshold*0.7 && wr.IsActive() && wr.QueueLength() == 0 {
				wr.SetActive(false)
			}
		case <-wr.stopCh:
			return
		}
	}
}
