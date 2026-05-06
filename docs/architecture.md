# Shield WAF 架构设计

## 项目概述

Shield 是一个轻量级 Web 应用防火墙（WAF），采用 Go 语言编写，遵循标准 Go 项目布局。

## 分层架构

### 1. Handler 层（HTTP 入口）
- **职责**：解析 HTTP 请求、编排10层防御流水线、格式化响应
- **位置**：`internal/handler/`
- **文件**：
  - `proxy.go` — 代理请求入口，10层防御流水线编排

### 1.1 PortMap 层（端口级 WAF 实例）
- **职责**：管理独立的端口映射代理，每个映射拥有完整的10层防御流水线
- **位置**：`internal/portmap/`
- **文件**：
  - `manager.go` — 端口映射代理管理器（启动/停止/校验）

### 2. Service 层（业务逻辑）
- **职责**：业务编排、规则匹配、告警、IP频率追踪
- **位置**：`internal/service/`
- **子模块**：
  - `rules/` — YAML规则引擎（正则匹配+热加载）
  - `alert/` — 告警通知（webhook+阈值控制）
  - `ipreputation/` — 轻量IP请求频率追踪

### 3. Engine 层（检测引擎）
- **职责**：攻击检测、规则匹配、挑战响应
- **位置**：`internal/defender/`
- **子模块**：
  - `ddoscc/` — 统一 DDoS/CC 防护（8层渐进式检测+4级挑战系统）
  - `sqlinject/` — SQL 注入检测（50+正则模式）
  - `xss/` — XSS 攻击检测（70+正则模式）
  - `webshell/` — WebShell/木马上传检测
  - `bruteforce/` — 暴力破解防护（请求频次+响应状态双重检测）
  - `common/` — 共享工具函数（解码、归一化等）

### 4. Storage 层（数据访问）
- **职责**：数据持久化/查询
- **位置**：`internal/storage/`
- **文件**：
  - `blacklist/manager.go` — 黑名单的内存+JSON持久化管理

### 5. App 层（组装层）
- **职责**：依赖注入、生命周期管理
- **位置**：`cmd/shield/main.go`
- **说明**：通过构造函数在 `main()` 中完成所有依赖的初始化与组装，包括 Config、Logger、Blacklist、Rules Engine、Handler 等。

## 请求处理流水线

```
客户端请求
  │
  ├─ 0. 优先级信号量限流 ──── 高优先级预留给非可疑IP，低优先级排队
  ├─ 0.6 等待室旁路 ────────── SSE流/状态查询/释放回调 绕过所有检查
  ├─ 1. 黑名单检查 ─────────── 已封禁IP直接返回403
  ├─ 2. DDoS/CC 8层检测 ────── 
  │     Cookie旁路 → 全局速率 → 令牌桶(每IP) → 连接数/Slowloris
  │     → DDoS模式(GoldenEye/HTTP Flood/SYN Flood)
  │     → 滑动窗口(CC) → UA轮换(≥4) → 行为指纹+IP信誉+路径集中度
  │     └─ 四级挑战: JS → 环境指纹 → PoW → 验证码
  ├─ 3. 等待室排队 ────────── 峰值流量控制，SSE实时位置推送
  ├─ 4. 暴力破解检测 ──────── 请求频次+后端响应状态双重检测
  ├─ 5. 规则引擎 ───────────── YAML自定义规则匹配
  └─ 6. 内容检测 ──────────── SQL注入 → XSS → WebShell
       │                         (上传路径: WebShell先于SQL/XSS)
       ▼
   转发到后端 ──────────────── 记录响应状态用于暴力破解辅助检测
```

**阻断响应头**：`X-Block-Reason` 标识阻断原因（blacklist | ddos/cc:block | ddos/cc:challenge_failed | brute_force | rule_matched | sql_injection | xss | webshell_upload）

## DDoS/CC 8层检测流水线

| 层 | 名称 | 检测对象 | 动作 |
|----|------|---------|------|
| 0 | Cookie旁路 | 持有有效 `__shield_cc` 的用户 | 提升限流阈值4x |
| 1 | 全局速率 | 所有IP聚合RPS | 新用户进入挑战 |
| 2 | 令牌桶 | 每IP请求频率 | 违规1次=挑战，2次=PoW，3次=封禁 |
| 3 | 连接/Slowloris | 每IP连接数+慢速请求 | 直接封禁 |
| 4 | DDoS模式 | GoldenEye/HTTPFlood/SYNFlood | 直接封禁 |
| 5 | 滑动窗口 | 每IP+路径请求历史 | 触发挑战系统 |
| 6 | UA轮换 | 每IP+路径User-Agent数 | ≥4个=封禁 |
| 7 | 行为+信誉+路径集中 | 指纹评分+IP信誉+路径IP集中度 | 四级挑战或封禁 |

## 模块依赖关系

```
        ┌─────────┐
        │   App   │
        └────┬────┘
             │
        ┌────▼────┐
        │ Handler │ (proxy.go: 10层流水线编排)
        └────┬────┘
             │
     ┌───────┼───────┐
     ▼       ▼       ▼
┌─────────┐ ┌──────┐ ┌─────────┐
│ Engine  │ │Service│ │ Storage │
│(defender)│ │      │ │         │
└─────────┘ └──────┘ └─────────┘
```

- **Handler** 依赖 Engine + Service + Storage
- **Engine** 不依赖其他层（纯检测逻辑）
- **Service** 不依赖 Engine/Storage
- **Storage** 不依赖其他层
- **App** 依赖所有层，负责组装

## 目录结构

```
.
├── cmd/
│   ├── shield/                    # 主程序入口
│   ├── mock_backend/              # 测试用模拟后端
│   ├── test_100ips/               # 100 IP并发测试
│   ├── test_diagnostic/           # 诊断测试
│   ├── test_final/                # 综合测试
│   └── test_multipath/            # 多路径测试
├── internal/
│   ├── handler/
│   │   ├── proxy.go               # 代理服务+防御流水线
│   │   ├── proxy_test.go
│   │   └── proxy_integration_test.go
│   ├── portmap/
│   │   ├── manager.go             # 端口映射代理管理
│   │   └── manager_test.go
│   ├── defender/
│   │   ├── ddoscc/                # 统一DDoS/CC防护
│   │   │   ├── defender.go        # 8层检测编排
│   │   │   ├── detection.go       # 各层检测实现
│   │   │   ├── challenge.go       # 4级挑战系统
│   │   │   ├── behavior.go        # 行为指纹
│   │   │   ├── global.go          # 全局速率统计
│   │   │   ├── ipstats.go         # 每IP统计
│   │   │   ├── reputation.go      # IP信誉评分
│   │   │   ├── types.go           # 类型+常量
│   │   │   └── defender_test.go
│   │   ├── bruteforce/
│   │   │   ├── defender.go
│   │   │   └── defender_test.go
│   │   ├── sqlinject/
│   │   │   ├── detector.go
│   │   │   └── *_test.go
│   │   ├── xss/
│   │   │   ├── detector.go
│   │   │   └── detector_test.go
│   │   ├── webshell/
│   │   │   └── detector.go
│   │   └── common/
│   │       └── helpers.go
│   ├── service/
│   │   ├── alert/
│   │   │   ├── notifier.go
│   │   │   └── notifier_test.go
│   │   ├── ipreputation/
│   │   │   ├── reputation.go
│   │   │   └── reputation_test.go
│   │   └── rules/
│   │       ├── engine.go
│   │       ├── engine_test.go
│   │       └── engine_extra_test.go
│   └── storage/
│       └── blacklist/
│           ├── manager.go
│           ├── manager_test.go
│           └── manager_extra_test.go
├── pkg/
│   ├── config/                    # 配置管理（YAML+热加载）
│   ├── logger/                    # 结构化日志
│   ├── metrics/                   # 原子计数器
│   ├── ratelimit/                 # 令牌桶+自适应限流
│   ├── semaphore/                 # 优先级信号量
│   ├── waitingroom/               # 等待室（FIFO+SSE）
│   └── version/                   # 版本号
├── configs/
│   ├── config.yaml
│   └── data/rules.yaml
├── scripts/                       # 安装/测试/回归脚本
├── testdata/                      # 测试数据集
├── deployments/                   # 部署配置（Docker/systemd）
├── docs/                          # 文档
│   ├── api.md
│   ├── architecture.md
│   └── deployment.md
├── runtime/                       # 运行时数据
├── Makefile
├── go.mod
├── go.sum
├── README.md
└── .gitignore
```

## 设计原则

1. **依赖注入**：通过构造函数注入，禁止全局变量（metrics除外）
2. **检测结果通过返回值传递**：不抛 panic，所有错误通过返回值传递
3. **Context 传递**：所有 I/O 操作通过 `context.Context` 传递
4. **测试驱动**：每个模块配套单元测试，核心模块覆盖率 ≥ 90%
5. **渐进式响应**：攻击检测采用渐进升级（允许→挑战→PoW→封禁），避免误杀
6. **普通用户优先**：有验证过的 cookie 用户享受更高限流阈值，等待室保护正常用户访问
