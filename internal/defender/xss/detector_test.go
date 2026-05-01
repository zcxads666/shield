package xss

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/shield/shield/pkg/logger"
)

func TestXSSDetector(t *testing.T) {
	log, _ := logger.New("warn", "json", "")
	x := NewDetector(true, "block", false, log)

	cases := []struct {
		name    string
		query   string
		blocked bool
	}{
		{"script tag", "?input=<script>alert(1)</script>", true},
		{"javascript", "?url=javascript:alert(1)", true},
		{"onerror", "?img=<img src=x onerror=alert(1)>", true},
		{"normal", "?name=hello", false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			u, _ := url.Parse("http://example.com/" + c.query)
			r := &http.Request{URL: u, Method: "GET"}
			matched, _ := x.InspectRequest(r)
			if matched != c.blocked {
				t.Fatalf("expected blocked=%v, got=%v", c.blocked, matched)
			}
		})
	}
}

func TestSanitize(t *testing.T) {
	input := `<script>alert("xss")</script>`
	out := Sanitize(input)
	if out == input {
		t.Fatal("sanitize did not transform input")
	}
}
