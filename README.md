# Shield — 轻量级 Web 应用防火墙（WAF）

Shield 是一个采用 Go 语言编写的高性能轻量级 Web 应用防火墙，提供 DDoS/CC 防护、SQL 注入检测、XSS 过滤、WebShell 上传拦截、暴力破解防护等全方位安全能力。

## 一键安装

```bash
curl -fsSL https://raw.githubusercontent.com/zcxads666/shield/main/scripts/install.sh | sudo bash
```

安装指定版本：

```bash
curl -fsSL https://raw.githubusercontent.com/zcxads666/shield/main/scripts/install.sh -o install.sh
sudo bash install.sh --version v1.14.8
```

卸载：

```bash
sudo bash install.sh uninstall
```

安装完成后：
- 代理服务监听 `:8080`（可通过配置修改）
- 管理 API 监听 `:9090`
- systemd 服务自动启动

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

## 从源码构建

```bash
make build
go run ./cmd/shield -config configs/config.yaml
```

服务启动后：
- 代理服务监听 `:8081`（通过 `server.bind_addr` 配置）
- 管理 API 监听 `:9090`（通过 `server.admin_bind_addr` 配置）

## 请求处理流水线

每个请求经过以下**10层防御流水线**，按序执行：

```
客户端请求
  │
  ├─ 0. 信号量限流 ───────── 优先级信号量，高优先级预留给已验证用户和非可疑IP
  ├─ 1. 黑名单检查 ───────── 已拉黑IP直接返回403
  ├─ 2. DDoS/CC前期检测 ──── 轻量检查（Cookie旁路 → 全局速率 → 令牌桶 → 连接数/Slowloris）
  │     └─ 触发挑战 → JS/环境指纹/PoW → 挑战失败直接拦截
  ├─ 3. 内容检测 ─────────── WebShell(上传文件时优先) → SQL注入 → XSS（正则匹配）
  ├─ 4. 规则引擎 ─────────── 自定义YAML规则匹配
  ├─ 5. DDoS/CC后期检测 ──── 重量检查（DDoS模式 → 滑动窗口 → UA轮换 → 行为+信誉+路径集中度）
  │     └─ 触发挑战 → JS/环境指纹/PoW → 挑战失败直接拦截
  ├─ 6. 暴力破解 ─────────── 请求频次+后端响应失败双重检测
  ├─ 7. 等待室检查 ───────── 峰值排队，SSE实时位置推送
  │
  ▼
后端代理 → 记录响应状态 → 暴力破解辅助检测
```

**X-Block-Reason 响应头**：`blacklist` | `ddos/cc:block` | `ddos/cc:challenge_failed` | `brute_force` | `rule_matched` | `sql_injection` | `xss` | `webshell_upload`

## 目录结构

```
.
├── cmd/
│   ├── shield/                    # 主程序入口
│   ├── mock_backend/              # 测试用模拟后端
│   ├── test_100ips/               # 100 IP并发测试工具
│   ├── test_diagnostic/           # 诊断测试工具
│   ├── test_final/                # 综合测试工具
│   └── test_multipath/            # 多路径测试工具
├── internal/
│   ├── handler/                   # HTTP 请求处理
│   │   ├── proxy.go               # 代理服务 + 10层防御流水线编排
│   │   └── admin.go               # 管理 API
│   ├── defender/                  # 攻击检测引擎
│   │   ├── ddoscc/                # 统一 DDoS/CC 防护（8层检测+挑战系统）
│   │   ├── bruteforce/            # 暴力破解防护
│   │   ├── sqlinject/             # SQL 注入检测（50+模式）
│   │   ├── xss/                   # XSS 攻击检测（70+模式）
│   │   ├── webshell/              # WebShell 上传检测
│   │   └── common/                # 共享解码/归一化工具
│   ├── service/                   # 业务服务
│   │   ├── rules/                 # 规则引擎（YAML+正则+热加载）
│   │   ├── ipreputation/          # 轻量IP频率追踪
│   │   └── alert/                 # 告警通知
│   └── storage/
│       └── blacklist/             # 黑名单持久化管理
├── pkg/                           # 可复用公共库
│   ├── config/                    # YAML配置管理（热加载）
│   ├── logger/                    # 结构化日志
│   ├── metrics/                   # 原子计数器
│   ├── ratelimit/                 # 令牌桶+自适应限流
│   ├── semaphore/                 # 优先级信号量（并发控制）
│   ├── waitingroom/               # 等待室（FIFO队列+SSE推送）
│   └── version/                   # 版本号
├── configs/                       # 配置文件
├── scripts/                       # 安装/测试/回归脚本
├── testdata/                      # 测试数据集
├── deployments/                   # 部署配置（Docker/systemd）
├── docs/                          # 文档
└── Makefile
```

## 构建与测试

```bash
# 编译
make build

# 单元测试（带 race 检测）
go test -v -race -coverprofile=coverage.out -covermode=atomic ./...

# 代码检查
go vet ./...
golangci-lint run --timeout=10m

# 运行安全测试脚本
bash scripts/security_test.sh

# 性能压测
bash scripts/benchmark.sh
```

## 管理 API

默认监听 `:9090`：

| 接口 | 方法 | 说明 |
|------|------|------|
| `GET /health` | HTTP | 健康检查，返回版本号 |
| `GET /stats` | HTTP | 实时统计（请求数、拦截数、各类型攻击数、活跃连接等）|
| `GET /blacklist` | HTTP | 查看黑名单列表 |
| `POST /blacklist` | HTTP | 手动添加黑名单 `{"ip":"...", "reason":"...", "duration_sec":0}` |
| `DELETE /blacklist?ip=1.2.3.4` | HTTP | 移除黑名单IP |

示例：

```bash
curl http://127.0.0.1:9090/health
curl http://127.0.0.1:9090/stats
curl http://127.0.0.1:9090/blacklist
```

## 配置说明

关键配置项（完整配置见 `configs/config.yaml`）：

| 配置段 | 关键字段 | 说明 |
|--------|----------|------|
| `server` | `bind_addr`, `max_concurrent`, `queue_timeout_ms` | 代理服务绑定地址、最大并发、队列超时 |
| `proxy` | `target_url`, `trust_forwarded` | 后端地址、是否信任 X-Forwarded-For |
| `ddos_cc` | `token_bucket_rate`, `js_challenge_enabled`, `pow_challenge_enabled` 等 | DDoS/CC 检测阈值与挑战开关 |
| `sql_inject` | `enabled`, `action` | SQL注入检测开关 |
| `xss` | `enabled`, `action` | XSS检测开关 |
| `upload` | `enabled`, `action` | WebShell检测开关 |
| `brute_force` | `max_failures`, `window_sec`, `protected_paths` | 暴力破解阈值与保护路径 |
| `blacklist` | `enabled`, `persist_path`, `auto_blacklist` | 黑名单持久化 |
| `rules` | `rules_path`, `hot_reload`, `reload_interval_sec` | 规则引擎 |
| `waiting_room` | `enabled`, `max_queue_size`, `release_per_sec`, `active_threshold` | 等待室配置 |

## Docker 部署

```bash
cd deployments/docker-compose
docker-compose up -d
```

## 架构设计

Shield 采用**分层架构**，各层通过构造函数注入依赖：

```
cmd/shield (App层: 组装+生命周期)
    │
    ▼
internal/handler (Handler层: HTTP入口+流水线编排)
    │
    ├──▶ internal/defender/* (Engine层: 攻击检测引擎)
    ├──▶ internal/service/*  (Service层: 规则/信誉/告警)
    └──▶ internal/storage/*  (Repository层: 黑名单持久化)
```

**设计原则**：
- 依赖注入，禁止全局变量（metrics 除外）
- 检测结果通过返回值传递，不抛 panic
- 所有 I/O 操作尽可能非阻塞
- 关键路径配套单元测试

## 安全部署建议

- **HTTPS/TLS**: 建议在 Shield 前方部署 TLS 终止代理（如 Nginx、Caddy），确保客户端到 Shield 之间的通信加密
- **管理 API 访问控制**: 管理 API 端口（默认 :9090）应仅允许内网访问，不要暴露在公网上
- **密钥管理**: 配置文件中的 HMAC 密钥（当前硬编码）在生产环境应替换为独立密钥文件或环境变量注入
- **日志脱敏**: 日志中记录客户端 IP，确保符合数据保护法规要求
- **Cookie Secure 标志**: 若部署在 HTTPS 环境，建议配置 Cookie 的 Secure 标志以防止中间人攻击

## 系统要求

- Linux x86_64 / arm64, macOS (Apple Silicon / Intel)
- 内存：≥ 128MB
- CPU：≥ 1 核

## License

MIT
