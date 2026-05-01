package config

import (
	"fmt"
	"os"
	"sync"

	"gopkg.in/yaml.v3"
)

// Config represents the entire shield configuration.
type Config struct {
	Server     ServerConfig     `yaml:"server"`
	Proxy      ProxyConfig      `yaml:"proxy"`
	RateLimit  RateLimitConfig  `yaml:"rate_limit"`
	DDoS       DDoSConfig       `yaml:"ddos"`
	CC         CCConfig         `yaml:"cc"`
	SQLInject  SQLInjectConfig  `yaml:"sql_inject"`
	XSS        XSSConfig        `yaml:"xss"`
	BruteForce BruteForceConfig `yaml:"brute_force"`
	Upload     UploadConfig     `yaml:"upload"`
	Blacklist  BlacklistConfig  `yaml:"blacklist"`
	Log        LogConfig        `yaml:"log"`
	Alert      AlertConfig      `yaml:"alert"`
	Rules      RulesConfig      `yaml:"rules"`
}

// ServerConfig defines the shield server settings.
type ServerConfig struct {
	BindAddr       string `yaml:"bind_addr"`
	ReadTimeoutMs  int    `yaml:"read_timeout_ms"`
	WriteTimeoutMs int    `yaml:"write_timeout_ms"`
	MaxHeaderBytes int    `yaml:"max_header_bytes"`
	AdminBindAddr  string `yaml:"admin_bind_addr"`
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

// DDoSConfig defines DDoS defense settings.
type DDoSConfig struct {
	Enabled             bool `yaml:"enabled"`
	MaxConnectionsPerIP int  `yaml:"max_connections_per_ip"`
	SlowlorisTimeoutMs  int  `yaml:"slowloris_timeout_ms"`
	ChallengeThreshold  int  `yaml:"challenge_threshold"`
}

// CCConfig defines CC (Challenge Collapsar) attack detection settings.
type CCConfig struct {
	Enabled         bool `yaml:"enabled"`
	MaxRequests     int  `yaml:"max_requests"`
	WindowSec       int  `yaml:"window_sec"`
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
		cfg.RateLimit.RequestsPerSecond = 100
	}
	if cfg.RateLimit.BurstSize == 0 {
		cfg.RateLimit.BurstSize = 150
	}
	if cfg.RateLimit.BlockDurationSec == 0 {
		cfg.RateLimit.BlockDurationSec = 300
	}
	if cfg.DDoS.MaxConnectionsPerIP == 0 {
		cfg.DDoS.MaxConnectionsPerIP = 1000
	}
	if cfg.DDoS.SlowlorisTimeoutMs == 0 {
		cfg.DDoS.SlowlorisTimeoutMs = 30000
	}
	if cfg.CC.MaxRequests == 0 {
		cfg.CC.MaxRequests = 100
	}
	if cfg.CC.WindowSec == 0 {
		cfg.CC.WindowSec = 60
	}
	if cfg.BruteForce.MaxFailures == 0 {
		cfg.BruteForce.MaxFailures = 5
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
}
