package defender

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/shield/shield/internal/logger"
)

func TestSQLInjector(t *testing.T) {
	log, _ := logger.New("warn", "json", "")
	inj := NewSQLInjector(true, "block", log)

	cases := []struct {
		name    string
		query   string
		blocked bool
	}{
		{"union select", "?id=1 UNION SELECT * FROM users", true},
		{"or 1=1", "?user=admin OR 1=1", true},
		{"normal", "?id=123", false},
		{"comment", "?id=1--", true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			u, _ := url.Parse("http://example.com/" + c.query)
			r := &http.Request{URL: u, Method: "GET"}
			matched, _ := inj.Inspect(r)
			if matched != c.blocked {
				t.Fatalf("expected blocked=%v, got=%v", c.blocked, matched)
			}
		})
	}
}
