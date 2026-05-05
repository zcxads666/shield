package ddoscc

import (
	"math"
	"sync"
	"time"
)

// SuspicionEvent records a single suspicious event for an IP.
type SuspicionEvent struct {
	Time   time.Time
	Type   string
	Weight float64
}

// IPSuspicion tracks the suspicion score for a single IP with decay.
type IPSuspicion struct {
	IP            string
	Score         float64
	History       []SuspicionEvent
	BlockCount    int
	ChallengeFail int
	LastSeen      time.Time
	mu            sync.Mutex
}

// IPReputation manages suspicion scores across all tracked IPs.
type IPReputation struct {
	mu      sync.RWMutex
	entries map[string]*IPSuspicion
	maxSize int
}

// NewIPReputation creates an IP reputation tracker.
func NewIPReputation(maxSize int) *IPReputation {
	return &IPReputation{
		entries: make(map[string]*IPSuspicion),
		maxSize: maxSize,
	}
}

// GetOrCreate returns the IPSuspicion for an IP, creating one if needed.
func (r *IPReputation) GetOrCreate(ip string) *IPSuspicion {
	r.mu.RLock()
	s, ok := r.entries[ip]
	r.mu.RUnlock()
	if ok {
		return s
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if s, ok = r.entries[ip]; ok {
		return s
	}

	if len(r.entries) >= r.maxSize {
		r.evictOne()
	}

	s = &IPSuspicion{
		IP:       ip,
		History:  make([]SuspicionEvent, 0, 16),
		LastSeen: time.Now(),
	}
	r.entries[ip] = s
	return s
}

func (r *IPReputation) evictOne() {
	var oldestIP string
	var oldest time.Time
	for ip, s := range r.entries {
		if oldestIP == "" || s.LastSeen.Before(oldest) {
			oldestIP = ip
			oldest = s.LastSeen
		}
	}
	if oldestIP != "" {
		delete(r.entries, oldestIP)
	}
}

// CleanupStale removes entries whose lastSeen is before the cutoff time AND
// whose decayed score is below the given threshold. This prevents the
// reputation map from being permanently occupied by past attackers after
// an attack subsides.
func (r *IPReputation) CleanupStale(cutoff time.Time, minScore float64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for ip, s := range r.entries {
		s.mu.Lock()
		score := s.computeDecayedScore()
		last := s.LastSeen
		s.mu.Unlock()
		if last.Before(cutoff) && score < minScore {
			delete(r.entries, ip)
		}
	}
}

// AddEvent adds a suspicious event and updates the score.
func (s *IPSuspicion) AddEvent(event SuspicionEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.Score += event.Weight
	s.History = append(s.History, event)
	s.LastSeen = time.Now()

	if len(s.History) > 100 {
		s.History = s.History[len(s.History)-100:]
	}
}

// computeDecayedScore calculates the total score from history with time-based decay.
// Must be called under lock.
func (s *IPSuspicion) computeDecayedScore() float64 {
	now := time.Now()
	var total float64
	for _, e := range s.History {
		age := now.Sub(e.Time).Hours()
		decay := math.Exp(-age / 24)
		total += e.Weight * decay
	}
	return total
}

// Recalculate rebuilds the score from history with decay.
func (s *IPSuspicion) Recalculate() float64 {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.Score = s.computeDecayedScore()
	s.LastSeen = time.Now()
	return s.Score
}

// ShouldBlock returns true if the IP should be directly blocked.
func (s *IPSuspicion) ShouldBlock(blockThreshold float64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.Score = s.computeDecayedScore()
	return s.Score > blockThreshold
}

// ShouldChallenge returns true if the IP should be challenged.
func (s *IPSuspicion) ShouldChallenge(challengeThreshold float64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.Score = s.computeDecayedScore()
	return s.Score > challengeThreshold
}

// GetScore returns the current decayed score without modifying history.
func (s *IPSuspicion) GetScore() float64 {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.Score = s.computeDecayedScore()
	return s.Score
}

// OnBlock applies penalties when the IP is blocked.
func (s *IPSuspicion) OnBlock(acceleration float64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.BlockCount++
	multiplier := math.Pow(acceleration, float64(s.BlockCount))
	s.Score *= multiplier
	s.History = append(s.History, SuspicionEvent{
		Time:   time.Now(),
		Type:   "block_penalty",
		Weight: s.Score * (1 - 1/multiplier),
	})
	s.LastSeen = time.Now()
}

// OnChallengeFail records a challenge failure.
func (s *IPSuspicion) OnChallengeFail() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.ChallengeFail++
	s.Score += 10
	s.History = append(s.History, SuspicionEvent{
		Time:   time.Now(),
		Type:   "challenge_fail",
		Weight: 10,
	})
	s.LastSeen = time.Now()
}

// OnChallengePass records a successful challenge, reducing suspicion.
func (s *IPSuspicion) OnChallengePass() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.Score *= 0.5
	if len(s.History) > 0 {
		s.History = s.History[:len(s.History)-1]
	}
	s.LastSeen = time.Now()
}
