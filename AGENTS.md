# AGENTS.md — Shield WAF

## Commands

```bash
# Build
go build -o bin/shield ./cmd/shield

# Run (starts proxy on :8080, validates config first)
go run ./cmd/shield -c configs/config.yaml start

# CLI commands (status, stats, blacklist, mapping management)
go run ./cmd/shield -c configs/config.yaml status
go run ./cmd/shield -c configs/config.yaml stats
go run ./cmd/shield -c configs/config.yaml bl
go run ./cmd/shield -c configs/config.yaml mp

# Test (CI uses -race; run vet before test)
go vet ./...
go test -v -race -coverprofile=coverage.out -covermode=atomic ./...

# Lint (CI: golangci-lint v1.50, default config, 5m timeout)
golangci-lint run --timeout=5m

# Run a single package's tests
go test -v -race ./internal/defender/sqlinject/...
```

## Architecture

- **One Go module**: `github.com/shield/shield` (Go 1.18+). Only external dep: `gopkg.in/yaml.v3`.
- **No web frameworks, no ORM** — pure `net/http`, `encoding/json`, `sync/atomic`.
- **Dependency injection** via constructors (`New*` functions). No global vars except the `metrics` singleton (`pkg/metrics`). All I/O uses `context.Context`.
- **10-layer defense pipeline** in `internal/handler/proxy.go:RunProxy`:
  1. Priority semaphore → 2. Blacklist → 3. DDoS/CC early → 4. Content detection (SQLi/XSS/WebShell) → 5. Custom rules → 6. DDoS/CC late → 7. Brute force → 8. Waiting room → 9. Reverse proxy → 10. Response analysis
- **Block reason** is set via `X-Block-Reason` header: `blacklist`, `ddos/cc:block`, `ddos/cc:challenge_failed`, `brute_force`, `rule_matched`, `sql_injection`, `xss`, `webshell_upload`, `server_overloaded`, `body_too_large`, `waiting_room_full`.

## Directory layout

| Path | Purpose |
|------|---------|
| `cmd/shield/` | Main binary (`main.go`) |
| `cmd/mock_backend/` | Mock HTTP backend for integration tests |
| `internal/handler/` | Core proxy handler |
| `internal/portmap/` | Port mapping proxy manager |
| `internal/defender/` | Attack detectors (sqlinject, xss, webshell, ddoscc, bruteforce) |
| `internal/service/rules/` | YAML rule engine (hot-reload) |
| `internal/storage/blacklist/` | IP blacklist (JSON persistence) |
| `pkg/config/` | YAML config manager (hot-reload) |
| `pkg/waitingroom/` | FIFO queue + SSE waiting room |
| `pkg/semaphore/` | Priority semaphore (concurrency control) |
| `configs/` | Configuration files |
| `data/rules.yaml` | Custom WAF rules (3 default rules) |
| `scripts/` | Shell/Python test + benchmark scripts |

## Conventions

- **Internal package**: code in `internal/` is private to this module. Shared libraries go in `pkg/`.
- **Logging**: structured JSON via `pkg/logger` — use `lg.Info("event", map[string]interface{}{...})`, not `log.Printf`.
- **Metrics**: per-request counters via `metrics.Get().Increment*()`.
- **Config**: access via `cfg.Server.BindAddr`, etc. Never read os.Getenv() or flag directly inside packages — wire config through constructors.
- **Tests**: standard `testing` package. No external test frameworks. Integration tests use `cmd/mock_backend`.
- **Python scripts** in root and `testdata/` are for load/attack testing against a running instance — not unit tests.

## CI gate order

`lint` → `vet` → `test` (Go 1.18 + 1.19, with `-race`) → `build`

Run `go vet ./...` before pushing — it runs in CI as a separate job from golangci-lint.
