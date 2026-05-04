# Shield — 轻量级 Web 应用防火墙（WAF）

Shield 是一个采用 Go 语言编写的高性能轻量级 Web 应用防火墙，提供 DDoS/CC 防护、SQL 注入检测、XSS 过滤、WebShell 上传拦截、暴力破解防护等全方位安全能力。

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

## 快速开始

### 1. 编译

```bash
make build
```

### 2. 配置

编辑 `configs/config.yaml`，修改 `proxy.target_url` 指向你的后端服务：

```yaml
proxy:
  target_url: "http://127.0.0.1:8082"
```

### 3. 启动

```bash
./bin/shield -config configs/config.yaml
```

服务启动后：
- 代理服务监听 `:8081`（通过 `server.bind_addr` 配置）
- 管理 API 监听 `:9090`（通过 `server.admin_bind_addr` 配置）

## 请求处理流水线

每个请求经过以下**10层防御流水线**，按序执行：

```
客户端请求
  │
  ├─ 0. 信号量限流 ──────── 优先级信号量，高优先级预留给非可疑IP
  ├─ 0.5 等待室旁路路径 ──── SSE/状态/释放回调绕过所有检测
  ├─ 0.6 等待室检测 ──────── 峰值排队，SSE实时位置推送
  ├─ 1. 黑名单检查 ───────── 已拉黑IP直接返回403
  ├─ 2. DDoS/CC检测 ─────── 8层渐进式检测流水线
  │     ├─ 2a. Cookie旁路 ─── 已认证用户跳过全局速率检查
  │     ├─ 2b. 全局速率 ───── 整体RPS超过阈值→新用户进入挑战
  │     ├─ 2c. 令牌桶 ────── 每IP令牌桶，违规→渐进式升级
  │     ├─ 2d. 连接/Slowloris 每IP连接上限+慢速攻击检测
  │     ├─ 2e. DDoS模式 ───── GoldenEye/HTTP Flood/SYN Flood
  │     ├─ 2f. 滑动窗口 ───── CC传统检测
  │     ├─ 2g. UA轮换 ────── 单个IP≥4个User-Agent即拦截
  │     └─ 2h. 行为+IP信誉+路径集中度 → 四级挑战或拦截
  ├─ 3. 等待室检查 ───────── DDoS/CC通过后，等待室队列控制放行速率
  ├─ 4. 暴力破解 ─────────── 请求频次+后端响应失败双重检测
  ├─ 5. 规则引擎 ─────────── 自定义YAML规则匹配
  ├─ 6. 内容检测 ─────────── SQL注入 → XSS → WebShell（正则匹配）
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
│   └── version/                   # 版本号（v1.14.5）
├── configs/                       # 配置文件
│   ├── config.yaml                # 主配置
│   └── data/rules.yaml            # 自定义规则
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

# 清理
make clean

# 单元测试
go test ./internal/... ./pkg/...

# 带覆盖率
go test ./internal/... ./pkg/... -cover

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
| `ddos_cc` | `requests_per_second`, `js_challenge_enabled`, `pow_challenge_enabled` 等 | DDoS/CC 检测阈值与挑战开关 |
| `sql_inject` | `enabled`, `action` | SQL注入检测开关 |
| `xss` | `enabled`, `action` | XSS检测开关 |
| `upload` | `enabled`, `action` | WebShell检测开关 |
| `brute_force` | `max_failures`, `window_sec`, `protected_paths` | 暴力破解阈值与保护路径 |
| `blacklist` | `enabled`, `persist_path`, `auto_blacklist` | 黑名单持久化 |
| `rules` | `rules_path`, `hot_reload`, `reload_interval_sec` | 规则引擎 |
| `waiting_room` | `enabled`, `max_queue_size`, `release_per_sec`, `active_threshold` | 等待室配置 |

## 部署

### Docker

```bash
cd deployments/docker-compose
docker-compose up -d
```

### systemd

```bash
sudo bash scripts/install.sh
# 或手动：
sudo cp deployments/systemd/shield.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now shield
```

查看状态：

```bash
sudo systemctl status shield
sudo journalctl -u shield -f
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

## 系统要求

- Linux x86_64
- Go 1.18+（从源码编译）
- 内存：≥ 128MB
- CPU：≥ 1 核

## License

MIT
