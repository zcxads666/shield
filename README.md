<p align="center">
  <b>English</b> | <a href="README_zh.md">中文</a>
</p>

<br>

<p align="center">
  <a href="https://github.com/zcxads666/shield/actions/workflows/ci.yml">
    <img src="https://img.shields.io/github/actions/workflow/status/zcxads666/shield/ci.yml?branch=main&style=flat-square&label=CI" alt="CI">
  </a>
  <a href="https://github.com/zcxads666/shield/releases">
    <img src="https://img.shields.io/github/v/release/zcxads666/shield?style=flat-square&label=Release" alt="Release">
  </a>
  <img src="https://img.shields.io/badge/Go-1.18%2B-00ADD8?logo=go&style=flat-square" alt="Go">
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square" alt="License">
  <img src="https://img.shields.io/badge/Deps-1%20(yaml)-lightgrey?style=flat-square" alt="Dependencies">
</p>

<h1 align="center">Shield</h1>

<p align="center"><b>Lightweight Web Application Firewall</b></p>

<p align="center">Zero framework dependencies. Single static binary. Full DDoS/CC mitigation, SQLi / XSS / WebShell detection, brute force protection, and more.</p>

---

## Quick Install

```bash
curl -fsSL https://raw.githubusercontent.com/zcxads666/shield/main/scripts/install.sh | sudo bash
```

```bash
# Specific version
sudo bash install.sh --version v1.14.8
```

After install the proxy listens on `:8080`. Manage via CLI commands.

---

## Features

| Category | Details |
|----------|---------|
| **DDoS/CC** | 8-layer progressive pipeline: global rate limit, token bucket, connection cap & slowloris detection, DDoS pattern, sliding window, UA rotation, behavior fingerprinting with IP reputation and path concentration |
| **Challenge System** | 4 escalating levels: JS challenge, environment fingerprint, proof-of-work, math captcha |
| **SQL Injection** | 50+ regex patterns covering URL encoding, Unicode, comment obfuscation, and hex encoding bypasses |
| **XSS** | 70+ patterns detecting script injection, SSTI, event handlers, DOM-based, and prototype pollution |
| **WebShell** | Blocks PHP/JSP/ASP webshell uploads, double-extension bypasses, and image horses |
| **Brute Force** | Dual detection via request frequency and backend response status; distributed attack awareness |
| **Waiting Room** | FIFO queue with SSE real-time position updates; auto-activates under peak load |
| **IP Blacklist** | Auto/manual blocking with JSON persistence |
| **Rule Engine** | YAML-defined custom rules with hot-reload |
| **CLI Management** | Health check, real-time metrics, blacklist, port mapping CRUD |
| **Logging** | Structured JSON with request tracing |

---

## Request Pipeline

Each request passes through a **10-layer defense pipeline**:

```
Client Request
  │
  ├─ 1.  Priority Semaphore ── high-priority slots for verified users
  ├─ 2.  Blacklist ─────────── blocked IPs receive 403 Forbidden
  ├─ 3.  DDoS/CC Early ─────── cookie bypass, global rate, token bucket, connection/slowloris
  │      └─ Challenge → JS / fingerprint / PoW → fail → block
  ├─ 4.  Content Detection ─── WebShell → SQLi → XSS (regex matching)
  ├─ 5.  Custom Rules ──────── YAML-defined regex rules
  ├─ 6.  DDoS/CC Late ──────── DDoS pattern, sliding window, UA rotation, behavior + reputation
  │      └─ Challenge → JS / fingerprint / PoW → fail → block
  ├─ 7.  Brute Force ───────── request frequency + backend response dual check
  ├─ 8.  Waiting Room ──────── FIFO queuing with SSE position updates
  │
  ▼
Backend Proxy → record response status → brute force auxiliary detection
```

**Block reason** is set via the `X-Block-Reason` response header:

`blacklist` | `ddos/cc:block` | `ddos/cc:challenge_failed` | `brute_force` | `rule_matched` | `sql_injection` | `xss` | `webshell_upload` | `server_overloaded` | `body_too_large` | `waiting_room_full`

---

## Build from Source

```bash
make build
go run ./cmd/shield -config configs/config.yaml start
```

```bash
go vet ./...
go test -v -race -coverprofile=coverage.out -covermode=atomic ./...
golangci-lint run --timeout=10m
```

---

## CLI Commands

```bash
# Start server (validates config first)
shield
shield start

# View status and metrics
shield status              # or: shield st
shield stats               # or: shield ss

# View recent logs
shield logs                # last 50 lines
shield logs -n 100         # last 100 lines

# Blacklist (alias: bl)
shield bl                  # list all
shield bl add 1.2.3.4              # add (permanent)
shield bl add 1.2.3.4 spam         # add with reason
shield bl add 1.2.3.4 spam 3600    # add with 3600s duration
shield bl rm 1.2.3.4               # remove

# Port mapping (alias: mp) — independent WAF per port
shield mp                               # list all
shield mp add :9090 192.168.1.100:8080  # add (auto id)
shield mp add app1 :9090 192.168.1.100:8080  # add with named id
shield mp rm app1                        # remove
shield mp set app1 :9090 10.0.0.5:3000  # update
```

---

## Configuration

| Section | Key Fields | Purpose |
|---------|-----------|---------|
| `server` | `bind_addr`, `max_concurrent` | Listen address, max concurrent requests |
| `proxy` | `target_url`, `trust_forwarded` | Backend origin, X-Forwarded-For handling |
| `ddos_cc` | `token_bucket_rate`, `pow_challenge_enabled` | Detection thresholds and challenge toggles |
| `sql_inject` | `enabled`, `action` | SQL injection detection |
| `xss` | `enabled`, `action` | XSS detection |
| `upload` | `enabled`, `action` | WebShell detection |
| `brute_force` | `max_failures`, `window_sec` | Brute force thresholds |
| `blacklist` | `enabled`, `persist_path` | Blacklist persistence |
| `rules` | `rules_path`, `hot_reload` | Custom rule engine |
| `waiting_room` | `enabled`, `max_queue_size` | Queue and release configuration |

Full example: `configs/config.yaml`

---

## Directory Layout

```
.
├── cmd/shield/         Main binary
├── cmd/mock_backend/   HTTP mock for integration tests
├── internal/
│   ├── handler/        Reverse proxy
│   ├── portmap/        Port mapping proxy manager
│   ├── defender/       Detectors (ddoscc, sqlinject, xss, webshell, bruteforce)
│   ├── service/        Rules engine, alert notifier
│   └── storage/        Blacklist JSON persistence
├── pkg/                Shared: config, logger, metrics, ratelimit, semaphore, waitingroom
├── configs/            YAML configuration files
├── scripts/            Install, test, and benchmark scripts
├── testdata/           Test datasets and Python test scripts
├── deployments/        Docker, docker-compose, systemd units
└── docs/               API and architecture documentation
```

---

## Docker

```bash
cd deployments/docker-compose
docker-compose up -d
```

---

## Architecture

```
cmd/shield (assembly + lifecycle)
    │
    ▼
internal/handler (HTTP entry + pipeline orchestration)
    │
    ├──▶ internal/portmap (port-level WAF instances)
    ├──▶ internal/defender/* (detection engines)
    ├──▶ internal/service/*  (rules, alerts)
    └──▶ internal/storage/*  (blacklist persistence)
```

- Pure `net/http` — zero web frameworks
- Dependency injection via constructors
- No global state except the `metrics` singleton
- All I/O uses `context.Context`
- Lock-free counters via `sync/atomic`

---

## Requirements

- Linux x86_64 / arm64, macOS (Apple Silicon / Intel)
- 128 MB memory, 1 CPU core

---

## License

[MIT](LICENSE)
