<p align="center">
  <b>English</b> |
  <a href="README_zh.md">中文</a>
</p>

# Shield — Web Application Firewall

A high-performance, lightweight WAF written in Go. Provides DDoS/CC mitigation, SQL injection detection, XSS filtering, WebShell upload blocking, brute force protection, and more — all in a single static binary with zero framework dependencies.

## Quick Install

```bash
curl -fsSL https://raw.githubusercontent.com/zcxads666/shield/main/scripts/install.sh | sudo bash
```

Install a specific version:

```bash
sudo bash install.sh --version v1.14.8
```

After install: proxy on `:8080`, admin API on `:9090`, systemd service auto-started.

## Features

- **DDoS/CC Mitigation** — 8-layer progressive detection: global rate → token bucket → connection/slowloris → DDoS pattern → sliding window → UA rotation → behavior fingerprint + IP reputation + path concentration
- **4-Level Challenge System** — JS challenge → environment fingerprint → PoW → math captcha
- **SQL Injection Defense** — 50+ regex patterns, URL encoding / Unicode / comment obfuscation / hex bypass detection
- **XSS Filtering** — 70+ patterns covering script injection, SSTI, event handlers, DOM-based, prototype pollution
- **WebShell Upload Blocking** — Detects PHP / JSP / ASP webshells, double-extension bypass, image horses
- **Brute Force Protection** — Request frequency + backend response dual detection, distributed attack awareness
- **Waiting Room** — FIFO queue with SSE real-time position updates, auto-activation during peak traffic
- **IP Blacklist** — Auto/manual blocking, JSON persistence
- **Rule Engine** — YAML custom rules, hot-reload
- **Admin API** — Health check, real-time stats, blacklist management
- **Structured Logging** — JSON format with request tracing

## Request Pipeline

Each request passes through a **10-layer defense pipeline**:

```
Client Request
  │
  ├─ 1. Priority Semaphore ── high-priority slots for verified users
  ├─ 2. Blacklist Check ────── blocked IPs → 403
  ├─ 3. DDoS/CC Early ──────── cookie bypass → global rate → token bucket → connection/slowloris
  │     └─ Challenge → JS / fingerprint / PoW → fail → block
  ├─ 4. Content Detection ──── WebShell → SQLi → XSS
  ├─ 5. Custom Rules ───────── YAML regex rules
  ├─ 6. DDoS/CC Late ───────── DDoS pattern → sliding window → UA rotation → behavior + reputation
  │     └─ Challenge → JS / fingerprint / PoW → fail → block
  ├─ 7. Brute Force ────────── frequency + backend response
  ├─ 8. Waiting Room ───────── peak queuing, SSE updates
  │
  ▼
Backend Proxy → response status → brute force auxiliary detection
```

**X-Block-Reason**: `blacklist` | `ddos/cc:block` | `ddos/cc:challenge_failed` | `brute_force` | `rule_matched` | `sql_injection` | `xss` | `webshell_upload` | `server_overloaded` | `body_too_large` | `waiting_room_full`

## Build from Source

```bash
make build
go run ./cmd/shield -config configs/config.yaml
```

```bash
# Tests (CI uses -race)
go vet ./...
go test -v -race -coverprofile=coverage.out -covermode=atomic ./...

# Lint
golangci-lint run --timeout=10m
```

## Admin API

Default: `:9090`

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health + version |
| `/stats` | GET | Real-time counters |
| `/blacklist` | GET | List blocked IPs |
| `/blacklist` | POST | Add `{"ip":"...","reason":"...","duration_sec":0}` |
| `/blacklist?ip=1.2.3.4` | DELETE | Remove IP |

## Directory Structure

```
.
├── cmd/
│   ├── shield/         # Main binary
│   └── mock_backend/   # Test mock backend
├── internal/
│   ├── handler/        # Proxy + admin API
│   ├── defender/       # Attack detectors (ddoscc, sqlinject, xss, webshell, bruteforce)
│   ├── service/        # Rules engine, alerts
│   └── storage/        # Blacklist persistence
├── pkg/                # Shared libraries (config, logger, metrics, ratelimit, semaphore, waitingroom)
├── configs/            # Configuration files
├── scripts/            # Install + test scripts
├── testdata/           # Test datasets + test scripts
├── deployments/        # Docker, docker-compose, systemd
└── docs/               # Documentation
```

## Docker

```bash
cd deployments/docker-compose
docker-compose up -d
```

## Architecture

```
cmd/shield (App: assembly + lifecycle)
    │
    ▼
internal/handler (HTTP entry + pipeline orchestration)
    │
    ├──▶ internal/defender/* (Detection engines)
    ├──▶ internal/service/*  (Rules / alerts)
    └──▶ internal/storage/*  (Blacklist persistence)
```

- Pure `net/http`, zero web frameworks
- Dependency injection via constructors
- All I/O uses `context.Context`
- `sync/atomic` for lock-free metrics

## Requirements

- Linux x86_64 / arm64, macOS (Apple Silicon / Intel)
- Memory: ≥ 128 MB
- CPU: ≥ 1 core

## License

MIT
