package defender

import (
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"github.com/shield/shield/internal/logger"
)

func TestBypassPayloads(t *testing.T) {
	log, _ := logger.New("warn", "json", "")
	inj := NewSQLInjector(true, "block", log)

	cases := []struct {
		name  string
		value string
	}{
		{"VT bypass", "1'%0bOR%0b'1'='1"},
		{"double encode", "%2527%2520OR%2520%25271%2527%3D%25271"},
		{"unicode bypass", "%u0027%u0020OR%u0020%u00271%u0027%u003D%u00271"},
		{"nospace OR", "1'OR'1'='1"},
		{"pipe OR", "1'||'1'='1"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			u, _ := url.Parse("http://example.com/?q=" + url.QueryEscape(c.value))
			r := &http.Request{URL: u, Method: "GET"}
			matched, pattern := inj.Inspect(r)
			fmt.Printf("%-20s matched=%v  pattern=%s\n", c.name, matched, pattern)

			u2, _ := url.Parse("http://example.com/?q=" + c.value)
			r2 := &http.Request{URL: u2, Method: "GET"}
			matched2, pattern2 := inj.Inspect(r2)
			fmt.Printf("  raw %-14s matched=%v  pattern=%s\n", c.name, matched2, pattern2)
		})
	}
}
