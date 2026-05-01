package defender

import (
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/shield/shield/internal/logger"
	"github.com/shield/shield/internal/metrics"
)

// SQLInjector detects SQL injection attempts.
type SQLInjector struct {
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

// NewSQLInjector creates a SQL injection detector.
func NewSQLInjector(enabled bool, action string, log *logger.Logger) *SQLInjector {
	s := &SQLInjector{
		enabled: enabled,
		action:  action,
		logger:  log,
	}
	s.ReloadPatterns(defaultSQLPatterns)
	return s
}

// ReloadPatterns updates detection patterns.
func (s *SQLInjector) ReloadPatterns(patterns []string) {
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
func (s *SQLInjector) Inspect(r *http.Request) (bool, string) {
	return s.InspectWithBody(r, nil)
}

// InspectWithBody checks a request for SQL injection, using raw body bytes
// as fallback when ParseForm fails (e.g., invalid URL escapes like "<%=...%>").
func (s *SQLInjector) InspectWithBody(r *http.Request, bodyBytes []byte) (bool, string) {
	if !s.enabled {
		return false, ""
	}

	targets := collectParamsWithBody(r, bodyBytes)
	s.mu.RLock()
	patterns := s.patterns
	s.mu.RUnlock()

	for _, target := range targets {
		normalized := normalizeInput(target)
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

func collectParams(r *http.Request) []string {
	return collectParamsWithBody(r, nil)
}

// collectParamsWithBody extracts all parameter values from the request,
// including URL query, POST form, and raw body bytes as fallback.
func collectParamsWithBody(r *http.Request, bodyBytes []byte) []string {
	var vals []string
	for k, v := range r.URL.Query() {
		vals = append(vals, k)
		vals = append(vals, v...)
	}
	// Also extract raw query values to handle semicolons that Go's ParseQuery splits on
	vals = append(vals, extractRawQueryValues(r.URL.RawQuery)...)
	if r.Method == http.MethodPost {
		// Try ParseForm first (consumes body)
		err := r.ParseForm()
		if err == nil {
			for k, v := range r.PostForm {
				vals = append(vals, k)
				vals = append(vals, v...)
			}
		}
		// Fallback: also scan raw body bytes for payloads that ParseForm
		// couldn't decode (e.g., invalid URL escapes like "<%=...%>").
		if len(bodyBytes) > 0 {
			bodyStr := string(bodyBytes)
			for _, part := range strings.Split(bodyStr, "&") {
				if idx := strings.Index(part, "="); idx >= 0 {
					vals = append(vals, part[idx+1:])
				}
			}
		}
	}
	return vals
}

var (
	entityStart   = regexp.MustCompile(`^#\d+;|^#x[0-9a-fA-F]+;`)
	normReHex     = regexp.MustCompile(`\\x([0-9a-fA-F]{2})`)
	normReUnicode = regexp.MustCompile(`\\u([0-9a-fA-F]{4})`)
	normReDec     = regexp.MustCompile(`&#(\d+);`)
	normReHexEnt  = regexp.MustCompile(`&#x([0-9a-fA-F]+);`)
	normReUXXXX   = regexp.MustCompile(`%u([0-9a-fA-F]{4})`)
)

func extractRawQueryValues(rawQuery string) []string {
	var vals []string
	if rawQuery == "" {
		return vals
	}
	// Split on & but preserve HTML entities like &#60; or &#x3C;
	pairs := smartAmpSplit(rawQuery)
	for _, pair := range pairs {
		if idx := strings.IndexByte(pair, '='); idx >= 0 {
			key, err := urlQueryUnescape(pair[:idx])
			if err != nil {
				key = pair[:idx]
			}
			val, err := urlQueryUnescape(pair[idx+1:])
			if err != nil {
				val = pair[idx+1:]
			}
			vals = append(vals, key, val)
		} else {
			key, err := urlQueryUnescape(pair)
			if err != nil {
				key = pair
			}
			vals = append(vals, key)
		}
	}
	return vals
}

func smartAmpSplit(rawQuery string) []string {
	parts := strings.Split(rawQuery, "&")
	var result []string
	var current string
	for _, part := range parts {
		if current != "" && entityStart.MatchString(part) {
			current += "&" + part
			continue
		}
		if current != "" {
			result = append(result, current)
		}
		current = part
	}
	if current != "" {
		result = append(result, current)
	}
	return result
}

func urlQueryUnescape(s string) (string, error) {
	return url.QueryUnescape(s)
}

// normalizeInput decodes common encoding bypasses for detection.
func normalizeInput(input string) string {
	s := input

	// Decode %uXXXX unicode escapes (ASP/IIS style) FIRST
	// before url.QueryUnescape, because %u0027 mixed with %20
	// causes url.QueryUnescape to fail on the %u sequence.
	s = normReUXXXX.ReplaceAllStringFunc(s, func(m string) string {
		r, _ := strconv.ParseUint(m[2:], 16, 32)
		return string(rune(r))
	})

	// Recursive URL decode (handles double encoding)
	for i := 0; i < 3; i++ {
		d, err := url.QueryUnescape(s)
		if err != nil || d == s {
			break
		}
		s = d
	}
	if s == "" {
		s = input
	}

	// Remove null bytes
	s = strings.ReplaceAll(s, "\x00", "")

	// Decode \xNN hex escapes
	s = normReHex.ReplaceAllStringFunc(s, func(m string) string {
		b, _ := strconv.ParseUint(m[2:], 16, 8)
		return string(byte(b))
	})

	// Decode \uNNNN unicode escapes
	s = normReUnicode.ReplaceAllStringFunc(s, func(m string) string {
		r, _ := strconv.ParseUint(m[2:], 16, 32)
		return string(rune(r))
	})

	// Decode HTML decimal entities &#NN;
	s = normReDec.ReplaceAllStringFunc(s, func(m string) string {
		matches := normReDec.FindStringSubmatch(m)
		if len(matches) > 1 {
			n, _ := strconv.Atoi(matches[1])
			if n > 0 && n <= 0x10FFFF {
				return string(rune(n))
			}
		}
		return m
	})

	// Decode HTML hex entities &#xNN;
	s = normReHexEnt.ReplaceAllStringFunc(s, func(m string) string {
		matches := normReHexEnt.FindStringSubmatch(m)
		if len(matches) > 1 {
			n, _ := strconv.ParseUint(matches[1], 16, 32)
			if n > 0 && n <= 0x10FFFF {
				return string(rune(n))
			}
		}
		return m
	})

	// Normalize whitespace: VT(0x0b), FF(0x0c), NBSP(0xa0) → space
	for _, c := range []string{"\x0b", "\x0c", "\xa0"} {
		s = strings.ReplaceAll(s, c, " ")
	}

	return s
}
