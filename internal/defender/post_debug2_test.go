package defender

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/shield/shield/internal/logger"
)

func TestPostDebug2(t *testing.T) {
	log, _ := logger.New("warn", "json", "stderr")
	injector := NewSQLInjector(true, "block", log)

	payloads := []string{
		"1' AND pg_sleep(5)--",
		"1 ORDER BY 1--",
		"1' HAVING 1=1--",
	}

	for _, p := range payloads {
		body := url.QueryEscape("q") + "=" + url.QueryEscape(p)
		req, _ := http.NewRequest("POST", "http://localhost/", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.ContentLength = int64(len(body))

		matched, pattern := injector.Inspect(req)
		fmt.Printf("POST payload=%q matched=%v pattern=%s\n", p, matched, pattern)

		// Also test GET
		u, _ := url.Parse("http://localhost/?q=" + url.QueryEscape(p))
		req2, _ := http.NewRequest("GET", "http://localhost/", nil)
		req2.URL = u
		matched2, pattern2 := injector.Inspect(req2)
		fmt.Printf("GET  payload=%q matched=%v pattern=%s\n", p, matched2, pattern2)
		fmt.Println()
	}
}
