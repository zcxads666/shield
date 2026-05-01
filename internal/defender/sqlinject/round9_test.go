package sqlinject

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/shield/shield/internal/defender/xss"
	"github.com/shield/shield/pkg/logger"
)

func TestRound9Payloads(t *testing.T) {
	log, _ := logger.New("warn", "json", "")
	sqlInj := NewDetector(true, "block", log)
	xssDet := xss.NewDetector(true, "block", false, log)

	cases := []struct {
		name      string
		input     string
		expectSQL bool
		expectXSS bool
	}{
		{"sql_eval_tautology", "1' AND 1=eval(1)--", true, true},
		{"ssti_double_brace", "{{7*7}}", false, true},
		{"ssti_triple_brace", "{{{7*7}}}", false, true},
		{"ssti_addition", "{{7+7}}", false, true},
		{"ssti_subtraction", "{{7-7}}", false, true},
		{"ssti_division", "{{7/7}}", false, true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			u, _ := url.Parse("http://example.com/?q=" + url.QueryEscape(c.input))
			r := &http.Request{URL: u, Method: "GET"}

			sqlMatched, sqlPattern := sqlInj.Inspect(r)
			xssMatched, xssPattern := xssDet.InspectRequest(r)

			if c.expectSQL && !sqlMatched {
				t.Errorf("expected SQL match for %s, got none", c.input)
			}
			if c.expectXSS && !xssMatched {
				t.Errorf("expected XSS match for %s, got none (SQL pattern: %s, XSS pattern: %s)", c.input, sqlPattern, xssPattern)
			}
		})
	}
}
