<p align="center">
  <a href="README.md">English</a> | <b>中文</b>
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

<p align="center"><b>轻量级 Web 应用防火墙</b></p>

<p align="center">零框架依赖，单静态二进制。提供 DDoS/CC 防护、SQLi / XSS / WebShell 检测、暴力破解防护等全方位安全能力。</p>

---

## 一键安装

```bash
curl -fsSL https://raw.githubusercontent.com/zcxads666/shield/main/scripts/install.sh | sudo bash
```

```bash
# 指定版本
sudo bash install.sh --version v1.14.8
```

安装完成后代理监听 `:8080`。通过 CLI 命令进行管理。

---

## 功能特性

| 类别 | 详情 |
|------|------|
| **DDoS/CC** | 8 层渐进式检测流水线：全局限流、令牌桶、连接数/Slowloris、DDoS 模式、滑动窗口、UA 轮换、行为指纹+IP 信誉+路径集中度 |
| **挑战系统** | 4 级升级：JS 挑战、环境指纹、PoW 工作量证明、数学验证码 |
| **SQL 注入** | 50+ 正则模式，覆盖 URL 编码、Unicode、注释混淆、十六进制等绕过手法 |
| **XSS** | 70+ 模式检测脚本注入、SSTI 模板注入、事件处理器、DOM 型、原型污染 |
| **WebShell** | 拦截 PHP/JSP/ASP 木马、双后缀绕过、图片马 |
| **暴力破解** | 请求频次+后端响应双重检测，分布式攻击感知 |
| **等待室** | FIFO 队列 + SSE 实时位置推送，峰值自动激活 |
| **IP 黑名单** | 自动/手动拉黑，JSON 持久化 |
| **规则引擎** | YAML 自定义规则，热加载 |
| **CLI 管理** | 状态检查、实时指标、黑名单、端口映射增删改查 |
| **日志** | 结构化 JSON，含请求追踪 |

---

## 请求处理流水线

每个请求经过 **10 层防御流水线**：

```
客户端请求
  │
  ├─ 1.  优先级信号量 ──── 高优先级预留给已验证用户
  ├─ 2.  黑名单检查 ────── 已拉黑 IP 返回 403
  ├─ 3.  DDoS/CC 前期 ──── Cookie 旁路、全局速率、令牌桶、连接数/Slowloris
  │      └─ 触发挑战 → JS / 环境指纹 / PoW → 失败 → 拦截
  ├─ 4.  内容检测 ──────── WebShell → SQLi → XSS（正则匹配）
  ├─ 5.  自定义规则 ────── YAML 正则规则
  ├─ 6.  DDoS/CC 后期 ──── DDoS 模式、滑动窗口、UA 轮换、行为+信誉
  │      └─ 触发挑战 → JS / 环境指纹 / PoW → 失败 → 拦截
  ├─ 7.  暴力破解 ──────── 请求频次 + 后端响应双重检测
  ├─ 8.  等待室 ────────── FIFO 排队 + SSE 位置推送
  │
  ▼
后端代理 → 记录响应状态 → 暴力破解辅助检测
```

**拦截原因**通过 `X-Block-Reason` 响应头标识：

`blacklist` | `ddos/cc:block` | `ddos/cc:challenge_failed` | `brute_force` | `rule_matched` | `sql_injection` | `xss` | `webshell_upload` | `server_overloaded` | `body_too_large` | `waiting_room_full`

---

## 从源码构建

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

## CLI 命令

```bash
# 启动服务（自动校验配置）
shield --config configs/config.yaml start

# 查看服务状态
shield --config configs/config.yaml status

# 查看实时指标
shield --config configs/config.yaml stats

# 查看最近日志
shield --config configs/config.yaml logs --lines 50

# 黑名单管理
shield --config configs/config.yaml blacklist list
shield --config configs/config.yaml blacklist add --ip 1.2.3.4 --reason "spam" --duration 3600
shield --config configs/config.yaml blacklist remove --ip 1.2.3.4

# 端口映射 CRUD（独立 WAF 实例）
shield --config configs/config.yaml mapping list
shield --config configs/config.yaml mapping add --id app1 --listen :9090 --target 192.168.1.100:8080
shield --config configs/config.yaml mapping remove --id app1
shield --config configs/config.yaml mapping update --id app1 --target 10.0.0.5:3000
```

---

## 配置说明

| 配置段 | 关键字段 | 用途 |
|--------|----------|------|
| `server` | `bind_addr`, `max_concurrent` | 监听地址、最大并发 |
| `proxy` | `target_url`, `trust_forwarded` | 后端地址、X-Forwarded-For |
| `ddos_cc` | `token_bucket_rate`, `pow_challenge_enabled` | 检测阈值与挑战开关 |
| `sql_inject` | `enabled`, `action` | SQL 注入检测 |
| `xss` | `enabled`, `action` | XSS 检测 |
| `upload` | `enabled`, `action` | WebShell 检测 |
| `brute_force` | `max_failures`, `window_sec` | 暴力破解阈值 |
| `blacklist` | `enabled`, `persist_path` | 黑名单持久化 |
| `rules` | `rules_path`, `hot_reload` | 规则引擎 |
| `waiting_room` | `enabled`, `max_queue_size` | 队列与释放配置 |

完整示例：`configs/config.yaml`

---

## 目录结构

```
.
├── cmd/shield/         主程序入口
├── cmd/mock_backend/   集成测试用模拟后端
├── internal/
│   ├── handler/        反向代理
│   ├── portmap/        端口映射代理管理
│   ├── defender/       检测引擎（ddoscc、sqlinject、xss、webshell、bruteforce）
│   ├── service/        规则引擎、告警通知
│   └── storage/        黑名单 JSON 持久化
├── pkg/                共享库（config、logger、metrics、ratelimit、semaphore、waitingroom）
├── configs/            YAML 配置文件
├── scripts/            安装、测试、压测脚本
├── testdata/           测试数据集与 Python 测试脚本
├── deployments/        Docker、docker-compose、systemd
└── docs/               文档
```

---

## Docker

```bash
cd deployments/docker-compose
docker-compose up -d
```

---

## 架构设计

```
cmd/shield（组装 + 生命周期）
    │
    ▼
internal/handler（HTTP 入口 + 流水线编排）
    │
    ├──▶ internal/portmap（端口级 WAF 实例）
    ├──▶ internal/defender/*（检测引擎）
    ├──▶ internal/service/* （规则、告警）
    └──▶ internal/storage/* （黑名单持久化）
```

- 纯 `net/http`，零 Web 框架
- 构造函数依赖注入
- 除 `metrics` 外无全局变量
- 所有 I/O 使用 `context.Context`
- `sync/atomic` 无锁计数器

---

## 系统要求

- Linux x86_64 / arm64, macOS（Apple Silicon / Intel）
- 128 MB 内存，1 核 CPU

---

## License

[MIT](LICENSE)
