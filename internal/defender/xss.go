package defender

import (
	"net/http"
	"regexp"
	"strings"
	"sync"

	"github.com/shield/shield/internal/logger"
	"github.com/shield/shield/internal/metrics"
)

// XSSDetector detects XSS attempts.
type XSSDetector struct {
	enabled        bool
	action         string
	filterResponse bool
	logger         *logger.Logger
	mu             sync.RWMutex
	patterns       []*regexp.Regexp
}

// Default XSS patterns.
var defaultXSSPatterns = []string{
	`(?i)<script\b[^>]*>[\s\S]*?</script\s*>`,
	`(?i)<script\b`,
	`(?i)javascript:\s*`,
	`(?i)java[\x00\t\n\r]script:`,
	`(?i)vbscript:\s*`,
	`(?i)mocha:\s*`,
	`(?i)livescript:\s*`,
	`(?i)data:text/html[;\w,=]*;base64,`,
	`(?i)(?:^|[\s<])on\w+\s*=\s*["']?[^"'>]*`,
	`(?i)<\s*iframe`,
	`(?i)<\s*object`,
	`(?i)<\s*embed`,
	`(?i)eval\s*\(`,
	`(?i)expression\s*\(`,
	`(?i)document\.cookie`,
	`(?i)document\.location`,
	`(?i)window\.location`,
	`(?i)<\s*img[^>]+onerror`,
	`(?i)<\s*svg[^>]*>`,
	`(?i)@import\s+['"]javascript:`,
	`(?i)\{\{.*constructor.*\}\}`,
	`(?i)\{\{.*[\+\-\*/%].*\}\}`,
	`(?i)\{\{\{.*[\+\-\*/%].*\}\}\}`,
	`(?i)\$\{[^}]*alert`,
	`(?i)#\{[^}]*alert`,
	`(?i)<%=[^%]*alert`,
	`(?i)\\x3cscript`,
	`(?i)\\u003cscript`,
	`(?i)&#[xX]?3[cC];.*&#[xX]?73;`,
	`(?i)&#[xX]?3[cC];`,
	`(?i)script:alert`,
	`(?i)<script\b[^>]*>\s*(?:alert|eval|document|window)`,
	`(?i)%3Cscript\b[^%]*%3E[\s\S]*?%3C%2Fscript\s*%3E`,
}

// NewXSSDetector creates an XSS detector.
func NewXSSDetector(enabled bool, action string, filterResponse bool, log *logger.Logger) *XSSDetector {
	x := &XSSDetector{
		enabled:        enabled,
		action:         action,
		filterResponse: filterResponse,
		logger:         log,
	}
	x.ReloadPatterns(defaultXSSPatterns)
	return x
}

// ReloadPatterns updates detection patterns.
func (x *XSSDetector) ReloadPatterns(patterns []string) {
	regs := make([]*regexp.Regexp, 0, len(patterns))
	for _, p := range patterns {
		if re, err := regexp.Compile(p); err == nil {
			regs = append(regs, re)
		}
	}
	x.mu.Lock()
	x.patterns = regs
	x.mu.Unlock()
}

// InspectRequest checks request parameters for XSS payloads.
func (x *XSSDetector) InspectRequest(r *http.Request) (bool, string) {
	return x.InspectRequestWithBody(r, nil)
}

// InspectRequestWithBody checks request parameters for XSS payloads,
// using raw body bytes as fallback when ParseForm fails.
func (x *XSSDetector) InspectRequestWithBody(r *http.Request, bodyBytes []byte) (bool, string) {
	if !x.enabled {
		return false, ""
	}
	targets := collectParamsWithBody(r, bodyBytes)
	x.mu.RLock()
	patterns := x.patterns
	x.mu.RUnlock()

	for _, target := range targets {
		normalized := normalizeInput(target)
		targetsToCheck := []string{target, normalized}
		for _, check := range targetsToCheck {
			for _, re := range patterns {
				if re.MatchString(check) {
					metrics.Get().IncXSSAttempts()
					if x.logger != nil {
						x.logger.Warn("xss_detected", map[string]interface{}{
							"pattern": re.String(),
							"target":  target,
							"path":    r.URL.Path,
						})
					}
					return true, re.String()
				}
			}
		}
	}
	return false, ""
}

// Sanitize removes common XSS vectors from a string.
func Sanitize(input string) string {
	replacer := strings.NewReplacer(
		"<", "&lt;",
		">", "&gt;",
		"\"", "&quot;",
		"'", "&#x27;",
		"/", "&#x2F;",
	)
	return replacer.Replace(input)
}
