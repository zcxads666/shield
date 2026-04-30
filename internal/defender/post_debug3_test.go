package defender

import (
	"fmt"
	"testing"

	"github.com/shield/shield/internal/logger"
)

func TestPayloadFileDebug(t *testing.T) {
	log, _ := logger.New("warn", "json", "stderr")
	injector := NewSQLInjector(true, "block", log)

	payloads := []string{
		"1' AND pg_sleep(5)--",
		"1 ORDER BY 1--",
		"1 ORDER BY 10--",
		"1' HAVING 1=1--",
		"1' GROUP BY users.id HAVING 1=1--",
	}

	for _, p := range payloads {
		req := makeRequestWithParam(t, "q", p)
		matched, pattern := injector.Inspect(req)
		fmt.Printf("GET payload=%q matched=%v pattern=%s\n", p, matched, pattern)
	}
}
