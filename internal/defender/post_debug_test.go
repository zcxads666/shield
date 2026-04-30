package defender

import (
	"bufio"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/shield/shield/internal/logger"
)

func TestPostDebug(t *testing.T) {
	log, _ := logger.New("warn", "json", "stderr")
	injector := NewSQLInjector(true, "block", log)

	f, _ := os.Open("../../testdata/payloads/sql_injection.txt")
	defer f.Close()

	var payloads []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		payloads = append(payloads, line)
	}

	blocked := 0
	for _, p := range payloads {
		req, _ := http.NewRequest("POST", "http://localhost/", strings.NewReader(url.QueryEscape("q")+"="+url.QueryEscape(p)))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if matched, _ := injector.Inspect(req); matched {
			blocked++
		} else {
			fmt.Printf("BYPASSED POST: %s\n", p)
		}
	}
	fmt.Printf("POST: total=%d, blocked=%d, rate=%.2f%%\n", len(payloads), blocked, float64(blocked)/float64(len(payloads))*100)
}
