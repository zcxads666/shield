package defender

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/shield/shield/internal/logger"
)

func TestSQLInjectorUnicodeURLMixed(t *testing.T) {
	log, _ := logger.New("warn", "json", "")
	inj := NewSQLInjector(true, "block", log)

	mustBlock := []struct {
		name  string
		query string
	}{
		{"unicode_url_or_tautology", "1%u0027%20OR%20%271%27=%271"},
		{"unicode_url_union_select", "1%u0027%20UNION%20SELECT%20*%20FROM%20users--"},
	}

	for _, c := range mustBlock {
		t.Run(c.name, func(t *testing.T) {
			u, _ := url.Parse("http://example.com/api/test?q=" + c.query)
			r := &http.Request{URL: u, Method: "GET"}
			matched, pattern := inj.Inspect(r)
			if !matched {
				t.Fatalf("expected blocked=true for %q, got=false (pattern=%s)", c.query, pattern)
			}
		})
	}

	mustNotBlock := []struct {
		name  string
		query string
	}{
		{"normal_id", "123"},
		{"url_encoded_space_name", "John%20Doe"},
		{"url_encoded_search", "hello%20world"},
	}

	for _, c := range mustNotBlock {
		t.Run(c.name, func(t *testing.T) {
			u, _ := url.Parse("http://example.com/api/test?q=" + c.query)
			r := &http.Request{URL: u, Method: "GET"}
			matched, pattern := inj.Inspect(r)
			if matched {
				t.Fatalf("expected blocked=false for %q, got=true (pattern=%s)", c.query, pattern)
			}
		})
	}
}
