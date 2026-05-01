package sqlinject

import (
	"net/http"
	"regexp"
	"strings"
	"sync"

	"github.com/shield/shield/internal/defender/common"
	"github.com/shield/shield/pkg/logger"
	"github.com/shield/shield/pkg/metrics"
)

// SQLInjector detects SQL injection attempts.
type Detector struct {
	enabled bool
	action  string
	logger  *logger.Logger
	mu      sync.RWMutex
	patterns []*regexp.Regexp
}

// Default SQL injection patterns.
var defaultSQLPatterns = []string{
	// 1a: UNION SELECT ... FROM/INTO/TABLE/DATABASE (always suspicious in user input)
	`(?i)\bUNION\b.*\bSELECT\b.*\b(FROM|INTO|TABLE|DATABASE)\b`,
	// 1b: subquery inside parentheses
	`(?i)\(\s*(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE|MERGE)\b.*\b(FROM|INTO|TABLE|DATABASE)\b)`,
	// SQL comment detection: match -- when preceded by quote/semicolon/space/start
	// and followed by space/newline or end-of-string.
	// Note: standalone --$ check is done in code to avoid multipart boundary false positives.
	`(?i)(['";]|^)--[\n]`,`(?i)(['";]|^)--\s+[a-zA-Z]`,
	`(?i)/\*|\*/`,
	// 4: OR/AND numeric tautology (handles OR(1)=(1) no-space bypass)
	`(?i)(\bOR\b|\bAND\b)\s*\(?\s*\d+\s*\)?\s*=\s*\(?\s*\d+\s*\)?`,
	// 5: quote OR/AND quote tautology (replaces broken backreference pattern)
	`(?i)('|")\s*(OR|AND)\s*['"]?\s*=\s*['"]?`,
	`(?i)(\bOR\b|\bAND\b)\s+['"]\w+['"]\s*=\s*['"]\w+['"]`,
	`(?i);\s*(SELECT|INSERT|UPDATE|DELETE|DROP)`,
	`(?i)\bUNION\b.*\bSELECT\b`,
	`(?i)\bSLEEP\s*\(\s*\d+\s*\)`,
	`(?i)\bpg_sleep\s*\(\s*\d+\s*\)`,
	`(?i)\bBENCHMARK\s*\(\s*\d+\s*,`,
	`(?i)LOAD_FILE\s*\(`,
	`(?i)INFORMATION_SCHEMA`,
	`(?i)\bWAITFOR\b.*\bDELAY\b`,
	`(?i)xp_cmdshell`,
	`(?i)\bCALL\b.*\bshell\s*\(`,
	`(?i)(\|\||&&)\s*['"]\d+['"]\s*=\s*['"]\d+['"]`,
	`(?i)@@version`,
	`(?i)convert\s*\(\s*int\s*,`,
	// ORDER BY injection: digit after ORDER BY is suspicious in user input
	`(?i)\bORDER\s+BY\s+\d+`,
	// HAVING tautology
	`(?i)\bHAVING\s+\d+\s*=\s*\d+`,
	`(?i)(\bOR\b|\bAND\b)\s+['"][^'";=]+['"]?\s*=\s*['"]?[^'";=]+['"]?`,
	`(?i)(\|\||&&)\s+['"][^'";=]+['"]?\s*=\s*['"]?[^'";=]+['"]?`,
	// New patterns for no-space and pipe-based tautology bypasses
	`(?i)[a-zA-Z0-9_]'\s*(OR|AND|\|\||&&)\s*'\d['"]\s*=\s*['"]\d`,
	`(?i)\d'\s*(OR|AND|\|\||&&)\s*'[a-zA-Z0-9_]+['"]\s*=\s*['"][a-zA-Z0-9_]+`,
	`(?i)[a-zA-Z]'\s*(OR|AND|\|\||&&)\s*'\d['"]\s*=\s*['"]\d`,
	`(?i)(?:^|[^a-zA-Z0-9_])[a-zA-Z]{2,}'\s*(OR|AND|\|\||&&)\s*'[a-zA-Z0-9_]{1,3}'\s*=\s*'[a-zA-Z0-9_]{1,3}`,
	`(?i)(?:^|[^a-zA-Z0-9_])[a-zA-Z]'\s*(OR|AND|\|\||&&)\s*'[a-zA-Z0-9_]['"]\s*=\s*['"][a-zA-Z0-9_]`,
	// Pattern for function-call tautologies like 1' AND 1=eval(1)--
	`(?i)(\bOR\b|\bAND\b)\s+\d+\s*=\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\(`,
}

// NewDetector creates a SQL injection detector.
func NewDetector(enabled bool, action string, log *logger.Logger) *Detector {
	s := &Detector{
		enabled: enabled,
		action:  action,
		logger:  log,
	}
	s.ReloadPatterns(defaultSQLPatterns)
	return s
}

// ReloadPatterns updates detection patterns.
func (s *Detector) ReloadPatterns(patterns []string) {
	regs := make([]*regexp.Regexp, 0, len(patterns))
	for _, p := range patterns {
		if re, err := regexp.Compile(p); err == nil {
			regs = append(regs, re)
		}
	}
	s.mu.Lock()
	s.patterns = regs
	s.mu.Unlock()
}

// Inspect checks a request for SQL injection.
func (s *Detector) Inspect(r *http.Request) (bool, string) {
	return s.InspectWithBody(r, nil)
}

// InspectWithBody checks a request for SQL injection, using raw body bytes
// as fallback when ParseForm fails (e.g., invalid URL escapes like "<%=...%>").
func (s *Detector) InspectWithBody(r *http.Request, bodyBytes []byte) (bool, string) {
	if !s.enabled {
		return false, ""
	}

	targets := common.CollectParamsWithBody(r, bodyBytes)
	s.mu.RLock()
	patterns := s.patterns
	s.mu.RUnlock()

	for _, target := range targets {
		normalized := common.NormalizeInput(target)
		upperTarget := strings.ToUpper(target)
		upperNormalized := strings.ToUpper(normalized)
		checks := []string{upperTarget, target}
		if normalized != target {
			checks = append(checks, upperNormalized, normalized)
		}
		for _, check := range checks {
			for _, re := range patterns {
				if re.MatchString(check) {
					metrics.Get().IncSQLInjections()
					if s.logger != nil {
						s.logger.Warn("sql_injection_detected", map[string]interface{}{
							"pattern": re.String(),
							"target":  target,
							"path":    r.URL.Path,
						})
					}
					return true, re.String()
				}
			}
			// Additional check: -- at end of string, but skip multipart boundaries
			if strings.HasSuffix(check, "--") && !strings.Contains(check, "------") {
				// Ensure it's a real SQL comment, not just something ending in --
				// Check that -- is preceded by a quote, semicolon, space, or digit
				if len(check) > 2 {
					prev := check[len(check)-3]
					if prev == '\'' || prev == '"' || prev == ';' || prev == ' ' || prev == '\n' || prev == '\t' || (prev >= '0' && prev <= '9') {
						metrics.Get().IncSQLInjections()
						if s.logger != nil {
							s.logger.Warn("sql_injection_detected", map[string]interface{}{
								"pattern": "sql_comment_suffix",
								"target":  target,
								"path":    r.URL.Path,
							})
						}
						return true, "sql_comment_suffix"
					}
				}
			}
		}
	}
	return false, ""
}
