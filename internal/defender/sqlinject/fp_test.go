package sqlinject

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/shield/shield/pkg/logger"
)

func TestFalsePositives(t *testing.T) {
	log, _ := logger.New("warn", "json", "")
	inj := NewDetector(true, "block", log)

	cases := []struct {
		input       string
		shouldBlock bool
		desc        string
	}{
		// Benign - should NOT block
		{"------WebKitFormBoundary", false, "multipart boundary"},
		{"------WebKitFormBoundary--", false, "multipart boundary with --"},
		{"------Boundary--", false, "generic boundary"},
		{"----boundary--", false, "short boundary"},
		{"In SQL, you can use UNION to combine results from multiple queries.", false, "SQL tutorial text"},
		{"To prevent SQL injection, always use parameterized queries like: SELECT * FROM users WHERE id = ?", false, "SQL tutorial with SELECT FROM"},
		{"SELECT * FROM candidates WHERE name = 'Alice' AND status = 'active'", false, "SQL in text"},
		{"UPDATE users SET last_login = NOW() WHERE id = 42", false, "UPDATE in text"},
		{"DROP TABLE IF EXISTS temp_table", false, "DROP in text"},
		{"1 < 2 && 3 > 1", false, "math expression"},
		{"a <= b || c >= d", false, "math expression 2"},

		// Malicious - SHOULD block
		{"1' UNION SELECT username, password FROM users--", true, "union select"},
		{"1' OR '1'='1", true, "classic tautology"},
		{"1'||'1'='1", true, "pipe tautology"},
		{"1'OR'1'='1", true, "no-space OR"},
		{"admin'--", true, "comment bypass"},
		{"1'; DROP TABLE users--", true, "stacked query"},
		{"1' AND 1=1--", true, "AND tautology"},
		{"1' UNION ALL SELECT null, version()--", true, "union all"},
	}

	for _, c := range cases {
		t.Run(c.desc, func(t *testing.T) {
			u, _ := url.Parse("http://example.com/?q=" + url.QueryEscape(c.input))
			r := &http.Request{URL: u, Method: "GET"}
			matched, pattern := inj.Inspect(r)
			if matched != c.shouldBlock {
				if c.shouldBlock {
					t.Errorf("FN: expected BLOCK, got PASS (pattern=%s)", pattern)
				} else {
					t.Errorf("FP: expected PASS, got BLOCK (pattern=%s)", pattern)
				}
			}
		})
	}
}
