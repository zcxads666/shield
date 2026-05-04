package xss

import (
	"net/http"
	"regexp"
	"strings"
	"sync"

	"github.com/shield/shield/internal/defender/common"
	"github.com/shield/shield/pkg/logger"
	"github.com/shield/shield/pkg/metrics"
)

// Detector detects XSS attempts.
type Detector struct {
	enabled        bool
	action         string
	filterResponse bool
	logger         *logger.Logger
	mu             sync.RWMutex
	patterns       []*regexp.Regexp
}

// Default XSS patterns covering reflected, stored, DOM-based, and template injection.
var defaultXSSPatterns = []string{
	// === Basic script injection ===
	`(?i)<script\b[^>]*>[\s\S]*?</script\s*>`,
	`(?i)<script\b`,
	`(?i)</script\b`,

	// === JavaScript pseudo-protocols ===
	`(?i)javascript:\s*`,
	`(?i)java[\x00\t\n\r]script:`,
	`(?i)vbscript:\s*`,
	`(?i)mocha:\s*`,
	`(?i)livescript:\s*`,

	// === Data URI XSS ===
	`(?i)data:text/html[;\w,=]*;base64,`,
	`(?i)data:text/html[\s\S]*<script`,

	// === Event handlers ===
	`(?i)(?:^|[\s<"'/])on\w+\s*=\s*["']?[^"'>]*`,
	`(?i)(?:^|[\s<"'/;])on(?:load|error|click|focus|blur|mouseover|mouseout|keydown|keyup|keypress|submit|change|input|scroll|resize|select|abort|beforeunload|hashchange|message|storage|touchstart|touchend|animationstart|animationend|transitionend|wheel|copy|cut|paste|drag|drop)\s*=\s*`,

	// === DOM-based XSS sinks ===
	`(?i)\.innerHTML\s*=\s*`,
	`(?i)\.outerHTML\s*=\s*`,
	`(?i)\.insertAdjacentHTML\s*\(`,
	`(?i)document\.write\s*\(`,
	`(?i)document\.writeln\s*\(`,
	`(?i)eval\s*\(`,
	`(?i)setTimeout\s*\(\s*['"]`,
	`(?i)setInterval\s*\(\s*['"]`,
	`(?i)new\s+Function\s*\(`,
	`(?i)\.location\s*=\s*`,
	`(?i)\.location\.href\s*=\s*`,
	`(?i)\.location\.replace\s*\(`,
	`(?i)\.location\.assign\s*\(`,
	`(?i)\.src\b[\s\S]*?(?:javascript|data:)`,
	`(?i)\.srcdoc\s*=`,
	`(?i)postMessage\s*\(\s*['"]\s*\*`,

	// === HTML injection elements ===
	`(?i)<\s*iframe`,
	`(?i)<\s*object`,
	`(?i)<\s*embed`,
	`(?i)<\s*frame`,
	`(?i)<\s*form`,
	`(?i)<\s*link`,
	`(?i)<\s*meta`,
	`(?i)<\s*base\b`,
	`(?i)<\s*applet`,
	`(?i)<\s*marquee`,
	`(?i)<\s*math`,
	`(?i)<\s*body`,
	`(?i)<\s*video`,
	`(?i)<\s*audio`,
	`(?i)<\s*source`,
	`(?i)<\s*details`,
	`(?i)<\s*keygen`,
	`(?i)<\s*isindex`,

	// === CSS-based XSS ===
	`(?i)expression\s*\(`,
	`(?i)@import\s+['"]javascript:`,
	`(?i)-moz-binding\s*:\s*url`,
	`(?i)behavior\s*:\s*url`,
	`(?i)-o-link\s*:\s*`,
	`(?i)-o-link-source\s*:\s*`,

	// === SVG-based XSS ===
	`(?i)<\s*svg[^>]*(?:onload|onclick|onmouseover|onfocus)\s*=`,
	`(?i)<\s*svg[^>]*>\s*<script`,
	`(?i)<\s*svg[^>]*>\s*<foreignObject`,
	`(?i)<\s*img[^>]+onerror`,
	`(?i)<\s*img[^>]+onload`,
	`(?i)<\s*image[^>]+onerror`,

	// === Cookie and DOM access ===
	`(?i)document\.cookie`,
	`(?i)document\.location`,
	`(?i)window\.location`,
	`(?i)document\.referrer`,
	`(?i)document\.domain`,
	`(?i)window\.name`,
	`(?i)localStorage\.`,
	`(?i)sessionStorage\.`,

	// === Template injection (SSTI) ===
	`(?i)\{\{.*constructor.*\}\}`,
	`(?i)\{\{.*[\+\-\*/%].*\}\}`,
	`(?i)\{\{\{.*[\+\-\*/%].*\}\}\}`,
	`(?i)\$\{[^}]*alert`,
	`(?i)\$\{[^}]*<script`,
	`(?i)#\{[^}]*alert`,
	`(?i)<%=[^%]*alert`,
	`(?i)\{\{.*__proto__.*\}\}`,
	`(?i)\{\{.*prototype.*\}\}`,
	`(?i)\{\{.*self\b.*\}\}`,
	`(?i)\{\{.*globals\b.*\}\}`,
	`(?i)\$\{.*constructor.*\}`,
	`(?i)\$\{.*__proto__.*\}`,

	// === Encoding bypass detection ===
	`(?i)\\x3cscript`,
	`(?i)\\u003cscript`,
	`(?i)&#[xX]?3[cC];.*&#[xX]?73;`,
	`(?i)&#[xX]?3[cC];`,
	`(?i)script:alert`,
	`(?i)<script\b[^>]*>\s*(?:alert|eval|document|window)`,
	`(?i)%3Cscript\b[^%]*%3E[\s\S]*?%3C%2Fscript\s*%3E`,
	`(?i)%3C(?:iframe|object|embed|svg|img)`,
	`(?i)\\074script`,
	`(?i)<[^>]+style\s*=\s*["'][^"'>]*expression\s*\(`,
	`(?i)<[^>]+style\s*=\s*["'][^"'>]*-moz-binding`,
	`(?i)<[^>]+style\s*=\s*["'][^"'>]*url\s*\(\s*["']?\s*javascript:`,
	`(?i)<[^>]+style\s*=\s*["'][^"'>]*@import`,

	// === DOM clobbering ===
	`(?i)<(?:form|img|a|embed|object|applet)[^>]*id\s*=\s*["']?(?:submit|action|method|element|forms|all|self|top|parent|opener)`,
	`(?i)<(?:form|img|a)[^>]*name\s*=\s*["']?(?:submit|action|method|element|forms|all|self|top|parent|opener)`,

	// === Prototype pollution ===
	`(?i)__proto__\s*[\[\.]`,
	`(?i)constructor\s*\[\s*['"]?prototype`,
	`(?i)\.constructor\.constructor\s*\(`,
}

// NewDetector creates an XSS detector.
func NewDetector(enabled bool, action string, filterResponse bool, log *logger.Logger) *Detector {
	x := &Detector{
		enabled:        enabled,
		action:         action,
		filterResponse: filterResponse,
		logger:         log,
	}
	x.ReloadPatterns(defaultXSSPatterns)
	return x
}

// ReloadPatterns updates detection patterns.
func (x *Detector) ReloadPatterns(patterns []string) {
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
func (x *Detector) InspectRequest(r *http.Request) (bool, string) {
	return x.InspectRequestWithBody(r, nil)
}

// InspectRequestWithBody checks request parameters, HTTP headers, and cookies
// for XSS payloads.
func (x *Detector) InspectRequestWithBody(r *http.Request, bodyBytes []byte) (bool, string) {
	if !x.enabled {
		return false, ""
	}

	// Combine all targets from query params, body, headers, and cookies
	targets := common.CollectParamsWithBody(r, bodyBytes)
	targets = append(targets, common.CollectHeaders(r)...)
	targets = append(targets, common.CollectCookies(r)...)

	return x.checkTargets(targets, r)
}

// checkTargets runs all patterns against a list of target strings.
func (x *Detector) checkTargets(targets []string, r *http.Request) (bool, string) {
	x.mu.RLock()
	patterns := x.patterns
	x.mu.RUnlock()

	for _, target := range targets {
		normalized := common.NormalizeInput(target)
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
