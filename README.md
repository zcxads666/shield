<p align="center">
  <a href="#-shield---web-application-firewall">English</a> |
  <a href="#shield---%E8%BD%BB%E9%87%8F%E7%BA%A7-web-%E5%BA%94%E7%94%A8%E9%98%B2%E7%81%AB%E5%A2%99">中文</a>
</p>

---

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

---

# Shield — 轻量级 Web 应用防火墙

基于 Go 语言的高性能轻量级 Web 应用防火墙。单二进制文件，零框架依赖，提供 DDoS/CC 防护、SQL 注入检测、XSS 过滤、WebShell 上传拦截、暴力破解防护等全方位安全能力。

## 一键安装

```bash
curl -fsSL https://raw.githubusercontent.com/zcxads666/shield/main/scripts/install.sh | sudo bash
```

安装指定版本：

```bash
sudo bash install.sh --version v1.14.8
```

安装完成后：代理监听 `:8080`，管理 API 监听 `:9090`，systemd 服务自动启动。

## 功能特性

- **DDoS/CC 防护** — 8层渐进式检测流水线：全局限流 → 令牌桶 → 连接数/Slowloris → DDoS模式 → 滑动窗口 → UA轮换 → 行为指纹+IP信誉+路径集中度
- **四级挑战系统** — JS挑战 → 环境指纹 → PoW工作量证明 → 数学验证码
- **SQL 注入防护** — 50+ 正则模式，支持 URL编码/Unicode/注释混淆/十六进制等多重编码绕过检测
- **XSS 攻击过滤** — 70+ 模式覆盖 script注入/SSTI模板注入/事件处理器/DOM型/原型污染
- **WebShell 上传拦截** — 检测 PHP/JSP/ASP 木马、双后缀绕过、图片马
- **暴力破解防护** — 请求频次+后端响应双重检测，分布式攻击感知
- **等待室** — 峰值流量排队，SSE实时推送位置更新，自动启停
- **IP 黑名单** — 自动/手动拉黑，JSON持久化
- **规则引擎** — YAML自定义规则，热加载
- **管理 API** — 健康检查、实时统计、黑名单管理
- **结构化日志** — JSON格式带请求追踪

## 请求处理流水线

每个请求经过以下**10层防御流水线**，按序执行：

```
客户端请求
  │
  ├─ 1. 优先级信号量 ──── 高优先级预留给已验证用户
  ├─ 2. 黑名单检查 ────── 已拉黑IP直接返回403
  ├─ 3. DDoS/CC前期检测 ── Cookie旁路 → 全局速率 → 令牌桶 → 连接数/Slowloris
  │     └─ 触发挑战 → JS/环境指纹/PoW → 失败直接拦截
  ├─ 4. 内容检测 ──────── WebShell → SQL注入 → XSS
  ├─ 5. 规则引擎 ──────── 自定义YAML规则匹配
  ├─ 6. DDoS/CC后期检测 ── DDoS模式 → 滑动窗口 → UA轮换 → 行为+信誉+路径集中度
  │     └─ 触发挑战 → JS/环境指纹/PoW → 失败直接拦截
  ├─ 7. 暴力破解 ──────── 请求频次+后端响应失败双重检测
  ├─ 8. 等待室检查 ────── 峰值排队，SSE实时位置推送
  │
  ▼
后端代理 → 记录响应状态 → 暴力破解辅助检测
```

**X-Block-Reason 响应头**：`blacklist` | `ddos/cc:block` | `ddos/cc:challenge_failed` | `brute_force` | `rule_matched` | `sql_injection` | `xss` | `webshell_upload` | `server_overloaded` | `body_too_large` | `waiting_room_full`

## 从源码构建

```bash
make build
go run ./cmd/shield -config configs/config.yaml
```

```bash
# 测试
go vet ./...
go test -v -race -coverprofile=coverage.out -covermode=atomic ./...

# 代码检查
golangci-lint run --timeout=10m
```

## 管理 API

| 接口 | 方法 | 说明 |
|------|------|------|
| `GET /health` | HTTP | 健康检查，返回版本号 |
| `GET /stats` | HTTP | 实时统计 |
| `GET /blacklist` | HTTP | 查看黑名单列表 |
| `POST /blacklist` | HTTP | 手动添加黑名单 |
| `DELETE /blacklist?ip=1.2.3.4` | HTTP | 移除黑名单IP |

```bash
curl http://127.0.0.1:9090/health
curl http://127.0.0.1:9090/stats
```

## 配置说明

| 配置段 | 关键字段 | 说明 |
|--------|----------|------|
| `server` | `bind_addr`, `max_concurrent` | 代理绑定地址、最大并发 |
| `proxy` | `target_url`, `trust_forwarded` | 后端地址、X-Forwarded-For |
| `ddos_cc` | `token_bucket_rate`, `pow_challenge_enabled` 等 | DDoS/CC 阈值与挑战开关 |
| `sql_inject` | `enabled`, `action` | SQL注入检测 |
| `xss` | `enabled`, `action` | XSS检测 |
| `upload` | `enabled`, `action` | WebShell检测 |
| `brute_force` | `max_failures`, `window_sec` | 暴力破解阈值 |
| `blacklist` | `enabled`, `persist_path` | 黑名单持久化 |
| `rules` | `rules_path`, `hot_reload` | 规则引擎 |
| `waiting_room` | `enabled`, `max_queue_size` | 等待室配置 |

## 架构设计

```
cmd/shield (App层: 组装+生命周期)
    │
    ▼
internal/handler (Handler层: HTTP入口+流水线编排)
    │
    ├──▶ internal/defender/* (引擎层: 攻击检测)
    ├──▶ internal/service/*  (服务层: 规则/告警)
    └──▶ internal/storage/*  (仓储层: 黑名单持久化)
```

- 纯 `net/http`，零 Web 框架
- 依赖注入，禁止全局变量（metrics 除外）
- 所有 I/O 使用 `context.Context`
- `sync/atomic` 无锁计数器

## 系统要求

- Linux x86_64 / arm64, macOS (Apple Silicon / Intel)
- 内存：≥ 128MB
- CPU：≥ 1 核

## License

MIT
