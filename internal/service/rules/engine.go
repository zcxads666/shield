package rules

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// Rule represents a single WAF rule.
type Rule struct {
	ID          string   `yaml:"id"`
	Name        string   `yaml:"name"`
	Description string   `yaml:"description"`
	Phase       string   `yaml:"phase"` // request, response
	Pattern     string   `yaml:"pattern"`
	Action      string   `yaml:"action"` // block, log, allow
	Severity    string   `yaml:"severity"`
	Enabled     bool     `yaml:"enabled"`
	Targets     []string `yaml:"targets"` // url, headers, body, args
}

// RuleSet holds a collection of rules.
type RuleSet struct {
	Version string `yaml:"version"`
	Rules   []Rule `yaml:"rules"`
}

// compiledRule holds a compiled regexp.
type compiledRule struct {
	Rule
	re *regexp.Regexp
}

// Engine evaluates rules against requests/responses.
type Engine struct {
	mu        sync.RWMutex
	rules     []compiledRule
	path      string
	lastMod   time.Time
	hotReload bool
}

// NewEngine creates a rule engine.
func NewEngine(path string, hotReload bool) *Engine {
	return &Engine{
		path:      path,
		hotReload: hotReload,
	}
}

// Load reads rules from disk.
func (e *Engine) Load() error {
	info, err := os.Stat(e.path)
	if err != nil {
		if os.IsNotExist(err) {
			// create default rules file
			_ = e.writeDefault()
			return nil
		}
		return err
	}
	if !info.ModTime().After(e.lastMod) && len(e.rules) > 0 {
		return nil
	}
	data, err := os.ReadFile(e.path)
	if err != nil {
		return err
	}
	var rs RuleSet
	if err := yaml.Unmarshal(data, &rs); err != nil {
		return fmt.Errorf("parse rules: %w", err)
	}
	compiled := make([]compiledRule, 0, len(rs.Rules))
	for _, r := range rs.Rules {
		if !r.Enabled {
			continue
		}
		re, err := regexp.Compile(r.Pattern)
		if err != nil {
			continue
		}
		compiled = append(compiled, compiledRule{Rule: r, re: re})
	}
	e.mu.Lock()
	e.rules = compiled
	e.lastMod = info.ModTime()
	e.mu.Unlock()
	return nil
}

// MatchRequest evaluates rules against a request value.
func (e *Engine) MatchRequest(phase string, targets map[string]string) (matched bool, rule Rule) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	for _, cr := range e.rules {
		if !cr.Enabled || cr.Phase != phase {
			continue
		}
		for key, val := range targets {
			if len(cr.Targets) > 0 && !contains(cr.Targets, key) {
				continue
			}
			if cr.re.MatchString(val) {
				return true, cr.Rule
			}
		}
	}
	return false, Rule{}
}

// Count returns the number of loaded rules.
func (e *Engine) Count() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.rules)
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func (e *Engine) writeDefault() error {
	dir := filepath.Dir(e.path)
	_ = os.MkdirAll(dir, 0755)
	rs := RuleSet{
		Version: "1.0",
		Rules: []Rule{
			{ID: "R001", Name: "Path Traversal", Description: "Detect path traversal attempts", Phase: "request", Pattern: `\.\./|\.\.\\|%2e%2e`, Action: "block", Severity: "high", Enabled: true, Targets: []string{"url"}},
			{ID: "R002", Name: "Command Injection", Description: "Detect command injection", Phase: "request", Pattern: `;\s*\b(cat|ls|id|whoami|nc|bash|sh|cmd|powershell)\b`, Action: "block", Severity: "critical", Enabled: true, Targets: []string{"args", "body"}},
			{ID: "R003", Name: "Sensitive File Access", Description: "Access to sensitive files", Phase: "request", Pattern: `\b(\.env|\.git|\.htaccess|\.ssh|id_rsa|passwd|shadow)\b`, Action: "block", Severity: "high", Enabled: true, Targets: []string{"url"}},
		},
	}
	data, _ := yaml.Marshal(rs)
	return os.WriteFile(e.path, data, 0644)
}
