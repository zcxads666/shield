package defender

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/shield/shield/internal/logger"
)

func TestDebugXSSMissed(t *testing.T) {
	log, _ := logger.New("warn", "json", "stderr")
	x := NewXSSDetector(true, "block", false, log)

	tests := []string{
		`<%= alert(1) %>`,
	}

	for _, s := range tests {
		escaped := url.QueryEscape(s)
		req, _ := http.NewRequest("GET", "http://localhost/?content="+escaped, nil)
		
		t.Logf("RawQuery: %s", req.URL.RawQuery)
		t.Logf("Query content: %v", req.URL.Query()["content"])
		
		matched, pattern := x.InspectRequest(req)
		t.Logf("matched=%v pattern=%q input=%q escaped=%q", matched, pattern, s, escaped)
		if !matched {
			t.Errorf("Expected match for %q", s)
		}
	}
}
