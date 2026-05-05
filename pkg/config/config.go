package config

import (
	"fmt"
	"os"
	"sync"

	"gopkg.in/yaml.v3"
)

// Config represents the entire shield configuration.
type Config struct {
	Server      ServerConfig      `yaml:"server"`
	Proxy       ProxyConfig       `yaml:"proxy"`
	RateLimit   RateLimitConfig   `yaml:"rate_limit"`
	DDoSCC      DDoSCCConfig      `yaml:"ddos_cc"`
	SQLInject   SQLInjectConfig   `yaml:"sql_inject"`
	XSS         XSSConfig         `yaml:"xss"`
	BruteForce  BruteForceConfig  `yaml:"brute_force"`
	Upload      UploadConfig      `yaml:"upload"`
	Blacklist   BlacklistConfig   `yaml:"blacklist"`
	Log         LogConfig         `yaml:"log"`
	Alert       AlertConfig       `yaml:"alert"`
	Rules       RulesConfig       `yaml:"rules"`
	WaitingRoom WaitingRoomConfig `yaml:"waiting_room"`
}

// ServerConfig defines the shield server settings.
type ServerConfig struct {
	BindAddr       string `yaml:"bind_addr"`
	ReadTimeoutMs  int    `yaml:"read_timeout_ms"`
	WriteTimeoutMs int    `yaml:"write_timeout_ms"`
	MaxHeaderBytes int    `yaml:"max_header_bytes"`
	AdminBindAddr  string `yaml:"admin_bind_addr"`
	// MaxBodySize limits the request body size in bytes read into memory (0 = default 10MB).
	MaxBodySize int `yaml:"max_body_size"`
	// MaxConcurrent limits total concurrent requests (0 = unlimited).
	MaxConcurrent int `yaml:"max_concurrent"`
	// QueueTimeoutMs is max time to wait for a slot (0 = no queue).
	QueueTimeoutMs int `yaml:"queue_timeout_ms"`
	// HighPriorityRatio is fraction of slots reserved for trusted IPs (0.0~1.0).
	HighPriorityRatio float64 `yaml:"high_priority_ratio"`
}

// ProxyConfig defines upstream backend settings.
type ProxyConfig struct {
	TargetURL      string            `yaml:"target_url"`
	SetHeaders     map[string]string `yaml:"set_headers"`
	TrustForwarded bool              `yaml:"trust_forwarded"`
}

// RateLimitConfig defines token bucket settings.
type RateLimitConfig struct {
	Enabled           bool `yaml:"enabled"`
	RequestsPerSecond int  `yaml:"requests_per_second"`
	BurstSize         int  `yaml:"burst_size"`
	BlockDurationSec  int  `yaml:"block_duration_sec"`
}

// DDoSCCConfig defines unified DDoS/CC defense settings.
type DDoSCCConfig struct {
	Enabled bool `yaml:"enabled"`

	// Token bucket rate limiting
	RequestsPerSecond int `yaml:"requests_per_second"` // default 25
	BurstSize         int `yaml:"burst_size"`          // default 30

	// Connection / slowloris
	MaxConnectionsPerIP int `yaml:"max_connections_per_ip"` // default 100
	SlowlorisTimeoutMs  int `yaml:"slowloris_timeout_ms"`   // default 30000

	// Global DDoS detection thresholds
	GlobalRateDangerThreshold      float64 `yaml:"global_rate_danger_threshold"`       // default 50
	GlobalRateDistributedThreshold float64 `yaml:"global_rate_distributed_threshold"`  // default 22
	GlobalDistributedPathThreshold int     `yaml:"global_distributed_path_threshold"`  // default 30
	GlobalConcentratedPathThreshold int    `yaml:"global_concentrated_path_threshold"` // default 3

	// Per-IP sliding window
	MaxRequests   int `yaml:"max_requests"`   // default 200
	BurstRequests int `yaml:"burst_requests"` // default 300
	WindowSec     int `yaml:"window_sec"`     // default 60

	// Behavior fingerprint thresholds
	BehaviorScoreThreshold float64 `yaml:"behavior_score_threshold"` // default 70
	BehaviorBlockThreshold  float64 `yaml:"behavior_block_threshold"` // default 30

	// Path concentration detection (cross-IP aggregation)
	PathIPThreshold     int     `yaml:"path_ip_threshold"`      // default 50
	PathAvgReqThreshold float64 `yaml:"path_avg_req_threshold"` // default 3
	PathTimeWindowSec   int     `yaml:"path_time_window_sec"`   // default 600

	// IP suspicion thresholds
	SuspicionBlockThreshold     float64 `yaml:"suspicion_block_threshold"`     // default 80
	SuspicionChallengeThreshold float64 `yaml:"suspicion_challenge_threshold"` // default 50

	// Block/ban configuration
	BlockDurationSec  int     `yaml:"block_duration_sec"`  // default 600
	BlockAcceleration float64 `yaml:"block_acceleration"`  // default 1.5
	MaxBlockCount     int     `yaml:"max_block_count"`     // default 3

	// Challenge system
	JSChallengeEnabled     bool `yaml:"js_challenge_enabled"`      // default true
	CaptchaChallengeEnabled bool `yaml:"captcha_challenge_enabled"` // default true
	EnvFingerprintEnabled   bool `yaml:"env_fingerprint_enabled"`   // default true
	PoWChallengeEnabled     bool `yaml:"pow_challenge_enabled"`     // default true
	PoWDifficulty           int  `yaml:"pow_difficulty"`            // default 4
}

// SQLInjectConfig defines SQL injection detection settings.
type SQLInjectConfig struct {
	Enabled       bool   `yaml:"enabled"`
	Action        string `yaml:"action"`
	SeverityLevel string `yaml:"severity_level"`
}

// XSSConfig defines XSS filtering settings.
type XSSConfig struct {
	Enabled        bool   `yaml:"enabled"`
	Action         string `yaml:"action"`
	FilterResponse bool   `yaml:"filter_response"`
}

// UploadConfig defines web shell upload detection settings.
type UploadConfig struct {
	Enabled       bool   `yaml:"enabled"`
	Action        string `yaml:"action"`
	MaxFileSizeMB int    `yaml:"max_file_size_mb"`
}

// BruteForceConfig defines brute force / scan protection.
type BruteForceConfig struct {
	Enabled          bool     `yaml:"enabled"`
	MaxFailures      int      `yaml:"max_failures"`
	WindowSec        int      `yaml:"window_sec"`
	BlockDurationSec int      `yaml:"block_duration_sec"`
	ProtectedPaths   []string `yaml:"protected_paths"`
	StatusCodes      []int    `yaml:"status_codes"`
}

// BlacklistConfig defines IP blacklist settings.
type BlacklistConfig struct {
	Enabled       bool   `yaml:"enabled"`
	PersistPath   string `yaml:"persist_path"`
	AutoBlacklist bool   `yaml:"auto_blacklist"`
}

// LogConfig defines logging settings.
type LogConfig struct {
	Level      string `yaml:"level"`
	Format     string `yaml:"format"`
	OutputPath string `yaml:"output_path"`
	MaxSizeMB  int    `yaml:"max_size_mb"`
	MaxBackups int    `yaml:"max_backups"`
	MaxAgeDays int    `yaml:"max_age_days"`
}

// AlertConfig defines alerting settings.
type AlertConfig struct {
	Enabled    bool   `yaml:"enabled"`
	Webhook    string `yaml:"webhook"`
	SyslogAddr string `yaml:"syslog_addr"`
	Threshold  int    `yaml:"threshold"`
}

// RulesConfig defines rule engine settings.
type RulesConfig struct {
	RulesPath         string `yaml:"rules_path"`
	HotReload         bool   `yaml:"hot_reload"`
	ReloadIntervalSec int    `yaml:"reload_interval_sec"`
}

// WaitingRoomConfig defines peak-traffic queuing settings.
type WaitingRoomConfig struct {
	Enabled         bool    `yaml:"enabled"`
	MaxQueueSize    int     `yaml:"max_queue_size"`
	ReleasePerSec   float64 `yaml:"release_per_sec"`
	SessionTTLSec   int     `yaml:"session_ttl_sec"`
	QueueTimeoutSec int     `yaml:"queue_timeout_sec"`
	ActiveThreshold float64 `yaml:"active_threshold"`
}

// Manager handles configuration loading and hot reload.
type Manager struct {
	mu       sync.RWMutex
	config   *Config
	path     string
	watchers []func(*Config)
}

// NewManager creates a new configuration manager.
func NewManager(path string) *Manager {
	return &Manager{path: path}
}

// Load reads configuration from the given path.
func (m *Manager) Load() error {
	data, err := os.ReadFile(m.path)
	if err != nil {
		return fmt.Errorf("read config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("parse config file: %w", err)
	}

	m.setDefault(&cfg)

	m.mu.Lock()
	m.config = &cfg
	m.mu.Unlock()

	for _, fn := range m.watchers {
		fn(&cfg)
	}

	return nil
}

// Get returns the current configuration safely.
func (m *Manager) Get() *Config {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.config
}

// OnChange registers a callback for configuration changes.
func (m *Manager) OnChange(fn func(*Config)) {
	m.watchers = append(m.watchers, fn)
}

// Path returns the configuration file path.
func (m *Manager) Path() string {
	return m.path
}

func (m *Manager) setDefault(cfg *Config) {
	if cfg.Server.BindAddr == "" {
		cfg.Server.BindAddr = ":8080"
	}
	if cfg.Server.ReadTimeoutMs == 0 {
		cfg.Server.ReadTimeoutMs = 30000
	}
	if cfg.Server.WriteTimeoutMs == 0 {
		cfg.Server.WriteTimeoutMs = 30000
	}
	if cfg.Server.MaxHeaderBytes == 0 {
		cfg.Server.MaxHeaderBytes = 1 << 20
	}
	if cfg.Server.AdminBindAddr == "" {
		cfg.Server.AdminBindAddr = ":9090"
	}
	if cfg.Server.MaxBodySize == 0 {
		cfg.Server.MaxBodySize = 10 << 20 // 10 MB
	}
	if cfg.Server.MaxConcurrent == 0 {
		cfg.Server.MaxConcurrent = 1000
	}
	if cfg.Server.QueueTimeoutMs == 0 {
		cfg.Server.QueueTimeoutMs = 5000
	}
	if cfg.Server.HighPriorityRatio == 0 {
		cfg.Server.HighPriorityRatio = 0.2
	}
	if cfg.Proxy.TargetURL == "" {
		cfg.Proxy.TargetURL = "http://127.0.0.1:80"
	}
	if cfg.RateLimit.RequestsPerSecond == 0 {
		cfg.RateLimit.RequestsPerSecond = 25
	}
	if cfg.RateLimit.BurstSize == 0 {
		cfg.RateLimit.BurstSize = 30
	}
	if cfg.RateLimit.BlockDurationSec == 0 {
		cfg.RateLimit.BlockDurationSec = 300
	}
	if cfg.DDoSCC.RequestsPerSecond == 0 {
		cfg.DDoSCC.RequestsPerSecond = 25
	}
	if cfg.DDoSCC.BurstSize == 0 {
		cfg.DDoSCC.BurstSize = 30
	}
	if cfg.DDoSCC.MaxConnectionsPerIP == 0 {
		cfg.DDoSCC.MaxConnectionsPerIP = 100
	}
	if cfg.DDoSCC.SlowlorisTimeoutMs == 0 {
		cfg.DDoSCC.SlowlorisTimeoutMs = 30000
	}
	if cfg.DDoSCC.GlobalRateDangerThreshold == 0 {
		cfg.DDoSCC.GlobalRateDangerThreshold = 50
	}
	if cfg.DDoSCC.GlobalRateDistributedThreshold == 0 {
		cfg.DDoSCC.GlobalRateDistributedThreshold = 22
	}
	if cfg.DDoSCC.GlobalDistributedPathThreshold == 0 {
		cfg.DDoSCC.GlobalDistributedPathThreshold = 30
	}
	if cfg.DDoSCC.GlobalConcentratedPathThreshold == 0 {
		cfg.DDoSCC.GlobalConcentratedPathThreshold = 3
	}
	if cfg.DDoSCC.MaxRequests == 0 {
		cfg.DDoSCC.MaxRequests = 200
	}
	if cfg.DDoSCC.BurstRequests == 0 {
		cfg.DDoSCC.BurstRequests = 300
	}
	if cfg.DDoSCC.WindowSec == 0 {
		cfg.DDoSCC.WindowSec = 60
	}
	if cfg.DDoSCC.BehaviorScoreThreshold == 0 {
		cfg.DDoSCC.BehaviorScoreThreshold = 70
	}
	if cfg.DDoSCC.BehaviorBlockThreshold == 0 {
		cfg.DDoSCC.BehaviorBlockThreshold = 30
	}
	if cfg.DDoSCC.PathIPThreshold == 0 {
		cfg.DDoSCC.PathIPThreshold = 50
	}
	if cfg.DDoSCC.PathAvgReqThreshold == 0 {
		cfg.DDoSCC.PathAvgReqThreshold = 3
	}
	if cfg.DDoSCC.PathTimeWindowSec == 0 {
		cfg.DDoSCC.PathTimeWindowSec = 600
	}
	if cfg.DDoSCC.SuspicionBlockThreshold == 0 {
		cfg.DDoSCC.SuspicionBlockThreshold = 80
	}
	if cfg.DDoSCC.SuspicionChallengeThreshold == 0 {
		cfg.DDoSCC.SuspicionChallengeThreshold = 50
	}
	if cfg.DDoSCC.BlockDurationSec == 0 {
		cfg.DDoSCC.BlockDurationSec = 600
	}
	if cfg.DDoSCC.BlockAcceleration == 0 {
		cfg.DDoSCC.BlockAcceleration = 1.5
	}
	if cfg.DDoSCC.MaxBlockCount == 0 {
		cfg.DDoSCC.MaxBlockCount = 3
	}
	if cfg.DDoSCC.PoWDifficulty == 0 {
		cfg.DDoSCC.PoWDifficulty = 5
	}
	if cfg.BruteForce.MaxFailures == 0 {
		cfg.BruteForce.MaxFailures = 3
	}
	if cfg.BruteForce.WindowSec == 0 {
		cfg.BruteForce.WindowSec = 60
	}
	if cfg.BruteForce.BlockDurationSec == 0 {
		cfg.BruteForce.BlockDurationSec = 600
	}
	if cfg.Log.Level == "" {
		cfg.Log.Level = "info"
	}
	if cfg.Log.Format == "" {
		cfg.Log.Format = "json"
	}
	if cfg.Log.OutputPath == "" {
		cfg.Log.OutputPath = "./logs/shield.log"
	}
	if cfg.Log.MaxSizeMB == 0 {
		cfg.Log.MaxSizeMB = 100
	}
	if cfg.Log.MaxBackups == 0 {
		cfg.Log.MaxBackups = 7
	}
	if cfg.Log.MaxAgeDays == 0 {
		cfg.Log.MaxAgeDays = 30
	}
	if cfg.Rules.ReloadIntervalSec == 0 {
		cfg.Rules.ReloadIntervalSec = 3
	}
	if cfg.Upload.Action == "" {
		cfg.Upload.Action = "block"
	}
	if cfg.Upload.MaxFileSizeMB == 0 {
		cfg.Upload.MaxFileSizeMB = 32
	}
	if cfg.WaitingRoom.MaxQueueSize == 0 {
		cfg.WaitingRoom.MaxQueueSize = 5000
	}
	if cfg.WaitingRoom.ReleasePerSec == 0 {
		cfg.WaitingRoom.ReleasePerSec = 5.0
	}
	if cfg.WaitingRoom.SessionTTLSec == 0 {
		cfg.WaitingRoom.SessionTTLSec = 300
	}
	if cfg.WaitingRoom.QueueTimeoutSec == 0 {
		cfg.WaitingRoom.QueueTimeoutSec = 300
	}
	if cfg.WaitingRoom.ActiveThreshold == 0 {
		cfg.WaitingRoom.ActiveThreshold = 40.0
	}
}
