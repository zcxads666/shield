# Shield WAF 架构设计

## 项目概述

Shield 是一个轻量级 Web 应用防火墙（WAF），采用 Go 语言编写，遵循标准 Go 项目布局。

## 分层架构

### 1. Handler 层（HTTP 入口）
- **职责**：解析 HTTP 请求、调用 Service、格式化响应
- **位置**：`internal/handler/`
- **对应 Java**：Controller
- **文件**：
  - `proxy.go` — 代理请求入口，转发到后端服务
  - `admin.go` — 管理面板 API（健康检查、统计、黑名单）

### 2. Service 层（业务逻辑）
- **职责**：业务编排、调用 Repository、触发 Engine
- **位置**：`internal/service/`
- **对应 Java**：Service
- **子模块**：
  - `rules/` — 规则引擎编排
  - `alert/` — 告警通知逻辑
  - `ipreputation/` — IP 信誉评分

### 3. Domain 层（领域模型）
- **职责**：定义核心数据结构
- **位置**：`internal/domain/`（当前由各领域模块内联定义，后续可统一提取）
- **对应 Java**：Entity/Model
- **说明**：核心结构体包括 Request、Rule、Alert、BlacklistEntry、Metrics 等，当前分散在各模块中，保持领域模型纯净、不依赖外部框架。

### 4. Repository 层（数据访问）
- **职责**：数据持久化/查询
- **位置**：`internal/storage/`
- **对应 Java**：Mapper/DAO
- **文件**：
  - `blacklist/manager.go` — 黑名单的内存+文件持久化管理

### 5. Engine 层（检测引擎）
- **职责**：攻击检测、规则匹配、响应生成
- **位置**：`internal/defender/`
- **子模块**：
  - `sqlinject/` — SQL 注入检测
  - `xss/` — XSS 攻击检测
  - `webshell/` — WebShell/木马上传检测
  - `ddos/` — DDoS 防护
  - `cc/` — CC 攻击检测
  - `bruteforce/` — 暴力破解防护
  - `common/` — 共享工具函数（解码、归一化等）

### 6. App 层（组装层）
- **职责**：依赖注入、生命周期管理
- **位置**：`cmd/shield/main.go`
- **说明**：通过构造函数在 `main()` 中完成所有依赖的初始化与组装，包括 Config、Logger、Blacklist、Rules Engine、Handler 等。

## 数据流

```
[请求] → Handler → Service → [Engine 检测] → Repository
                          ↓
                    [响应/阻断]
```

1. 客户端请求到达 `Handler` 层（`proxy.go`）
2. `Handler` 调用 `Service` 层进行业务处理
3. `Service` 调用 `Engine` 层（`internal/defender/`）进行攻击检测
4. 若检测到攻击，`Engine` 返回阻断结果，`Handler` 直接返回 403/429 等响应
5. 若检测通过，请求继续转发到后端服务
6. `Repository` 层负责黑名单、规则等数据的持久化与查询

## 模块依赖关系

- **Handler** 依赖 Service
- **Service** 依赖 Repository + Engine
- **Engine** 不依赖其他层（纯逻辑）
- **Domain** 不依赖任何层
- **App** 依赖所有层，负责组装

```
        ┌─────────┐
        │   App   │
        └────┬────┘
             │
        ┌────▼────┐
        │ Handler │
        └────┬────┘
             │
        ┌────▼────┐
        │ Service │
        └────┬────┘
       ┌─────┴─────┐
       ▼           ▼
  ┌────────┐  ┌────────┐
  │ Engine │  │ Storage│
  └────────┘  └────────┘
```

## 目录结构

```
.
├── cmd/shield/                    # 应用程序入口（App 层）
│   └── main.go
├── internal/                      # 私有应用代码
│   ├── handler/                   # Handler 层（HTTP 入口）
│   │   ├── admin.go               # 管理面板 API
│   │   ├── admin_test.go
│   │   ├── proxy.go               # 代理请求处理
│   │   ├── proxy_test.go
│   │   └── proxy_integration_test.go
│   ├── service/                   # Service 层（业务逻辑）
│   │   ├── alert/                 # 告警通知
│   │   │   ├── notifier.go
│   │   │   └── notifier_test.go
│   │   ├── ipreputation/          # IP 信誉评分
│   │   │   ├── reputation.go
│   │   │   └── reputation_test.go
│   │   └── rules/                 # 规则引擎
│   │       ├── engine.go
│   │       ├── engine_test.go
│   │       └── engine_extra_test.go
│   ├── storage/                   # Repository 层（数据访问）
│   │   └── blacklist/             # 黑名单管理
│   │       ├── manager.go
│   │       ├── manager_test.go
│   │       └── manager_extra_test.go
│   └── defender/                  # Engine 层（检测引擎）
│       ├── bruteforce/            # 暴力破解防护
│       │   ├── defender.go
│       │   └── defender_test.go
│       ├── cc/                    # CC 攻击检测
│       │   ├── detector.go
│       │   └── detector_test.go
│       ├── common/                # 共享工具函数
│       │   └── helpers.go
│       ├── ddos/                  # DDoS 防护
│       │   ├── defender.go
│       │   ├── defender_test.go
│       │   ├── round9_test.go
│       │   └── stress_test.go
│       ├── sqlinject/             # SQL 注入检测
│       │   ├── bypass_test.go
│       │   ├── detector.go
│       │   ├── detector_test.go
│       │   ├── fp_test.go
│       │   ├── payload_test.go
│       │   ├── round9_test.go
│       │   └── unicode_test.go
│       ├── webshell/              # WebShell 上传检测
│       │   └── detector.go
│       └── xss/                   # XSS 攻击检测
│           ├── detector.go
│           └── detector_test.go
├── pkg/                           # 可复用公共库
│   ├── config/                    # 配置管理
│   │   ├── config.go
│   │   ├── config_test.go
│   │   └── config_extra_test.go
│   ├── logger/                    # 结构化日志
│   │   ├── logger.go
│   │   └── logger_test.go
│   ├── metrics/                   # 指标统计
│   │   ├── metrics.go
│   │   └── metrics_test.go
│   ├── ratelimit/                 # 令牌桶限流
│   │   ├── adaptive.go
│   │   ├── bucket.go
│   │   └── bucket_test.go
│   └── semaphore/                 # 优先级信号量
│       └── semaphore.go
├── scripts/                       # 脚本（安装、测试、运行）
│   ├── install.sh
│   ├── run.sh
│   ├── uninstall.sh
│   ├── benchmark.sh
│   ├── security_test.sh
│   └── ...
├── testdata/                      # 测试数据集
│   ├── benign/
│   │   ├── edge_cases.txt
│   │   └── normal_requests.txt
│   └── payloads/
│       ├── command_injection.txt
│       ├── path_traversal.txt
│       ├── sql_injection.txt
│       └── xss.txt
├── configs/                       # 配置文件模板
│   ├── config.yaml
│   ├── config.yaml.docker
│   └── config.yaml.example
├── deployments/                   # 部署配置
│   ├── docker/
│   │   ├── Dockerfile
│   │   └── .dockerignore
│   ├── docker-compose/
│   │   └── docker-compose.yml
│   ├── kubernetes/                # 预留
│   └── systemd/
│       └── shield.service
├── docs/                          # 文档
│   ├── api.md
│   ├── architecture.md            # 本文档
│   └── deployment.md
├── runtime/                       # 运行时数据
│   ├── data/
│   │   ├── blacklist.json
│   │   └── rules.yaml
│   └── logs/
├── Makefile
├── go.mod
├── go.sum
├── README.md
└── .gitignore
```

## 设计原则

1. **依赖注入**：通过构造函数注入，禁止全局变量
2. **接口隔离**：每层通过接口交互
3. **领域模型纯净**：不依赖框架/库
4. **Error 传播**：底层错误包装后向上传递
5. **Context 传递**：所有 I/O 操作通过 `context.Context` 传递
6. **测试驱动**：每个模块配套单元测试，核心模块覆盖率 ≥ 90%
