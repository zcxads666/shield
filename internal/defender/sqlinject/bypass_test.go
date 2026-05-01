package sqlinject

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/shield/shield/pkg/logger"
)

func TestBypassPayloads(t *testing.T) {
	log, _ := logger.New("warn", "json", "")
	inj := NewDetector(true, "block", log)

	cases := []struct {
		input string
		desc  string
	}{
		{"1'%0bOR%0b'1'='1", "VT whitespace bypass"},
		{"1%2527%2520UNION%2520SELECT%2520*%2520FROM%2520users--", "double encoding"},
		{"%u0027%u0020UNION%u0020SELECT%u0020*%u0020FROM%u0020users--", "unicode bypass"},
		{"1'OR'1'='1", "no-space OR"},
		{"1'||'1'='1", "pipe OR"},
	}

	for _, c := range cases {
		t.Run(c.desc, func(t *testing.T) {
			u, _ := url.Parse("http://example.com/?q=" + c.input)
			r := &http.Request{URL: u, Method: "GET"}
			matched, pattern := inj.Inspect(r)
			if !matched {
				t.Errorf("Expected BLOCK for %s, got PASS", c.desc)
			} else {
				t.Logf("BLOCKED %s with pattern: %s", c.desc, pattern)
			}
		})
	}
}
