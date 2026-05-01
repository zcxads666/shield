# Shield — 轻量级 Web 应用防火墙（WAF）

Shield 是一个采用 Go 语言编写的高性能轻量级 Web 应用防火墙，提供 SQL 注入检测、XSS 过滤、WebShell 上传拦截、DDoS/CC 防护、暴力破解防护等功能。

## 功能特性

- **SQL 注入防护** — 支持多种编码绕过检测（URL 编码、Unicode、注释混淆等）
- **XSS 攻击过滤** — 反射型、存储型、SSTI 模板注入检测
- **WebShell 上传拦截** — 检测 PHP/JSP 木马、图片马、双后缀绕过
- **DDoS/CC 防护** — 基于令牌桶限流 + 连接数控制，区分正常并发与恶意攻击
- **暴力破解防护** — 登录接口失败次数统计与自动拉黑
- **IP 黑名单** — 自动/手动拉黑，支持持久化
- **规则热加载** — 规则文件变更后自动生效
- **管理 API** — 内置健康检查、实时统计、黑名单查询接口

## 快速开始

### 1. 安装

```bash
git clone https://github.com/your-org/shield.git
cd shield
make build
```

### 2. 配置

复制示例配置并按需修改：

```bash
cp configs/config.yaml.example configs/config.yaml
# 编辑 configs/config.yaml，修改 proxy.target_url 指向你的后端服务
```

最小可用配置：

```yaml
server:
  bind_addr: ":8080"
  admin_bind_addr: ":9090"

proxy:
  target_url: "http://127.0.0.1:8082"
  trust_forwarded: true
```

### 3. 启动

```bash
make run
# 或
./bin/shield -config configs/config.yaml
```

服务启动后：
- 代理服务监听 `http://localhost:8080`
- 管理 API 监听 `http://localhost:9090`

## 目录结构

```
.
├── cmd/shield/              # 应用程序入口（App 层）
├── internal/                # 私有应用代码
│   ├── handler/             # Handler 层 — HTTP 请求入口
│   ├── service/             # Service 层 — 业务逻辑编排
│   ├── storage/             # Repository 层 — 数据持久化
│   └── defender/            # Engine 层 — 攻击检测引擎
├── pkg/                     # 可复用公共库
│   ├── config/              # 配置管理
│   ├── logger/              # 结构化日志
│   ├── metrics/             # 指标统计
│   ├── ratelimit/           # 令牌桶限流
│   └── semaphore/           # 优先级信号量
├── scripts/                 # 安装、测试、运行脚本
├── testdata/                # 测试数据集
├── configs/                 # 配置文件模板
├── deployments/             # 部署配置（Docker、systemd）
├── docs/                    # 文档
├── runtime/                 # 运行时数据与日志
└── Makefile
```

详细架构说明见 [docs/architecture.md](docs/architecture.md)。

## 构建

```bash
# 编译二进制到 bin/shield
make build

# 清理编译产物
make clean
```

## 测试

```bash
# 运行全部单元测试
make test

# 或直接使用 go test
go test ./...

# 带覆盖率报告
go test ./... -cover

# 带竞态检测
go test ./... -race

# 运行安全测试脚本
bash scripts/security_test.sh

# 运行性能压测
bash scripts/benchmark.sh
```

## 部署

### Docker 部署

```bash
cd deployments/docker-compose
docker-compose up -d
```

服务将暴露：
- `8080` — 代理端口
- `9090` — 管理 API 端口

### systemd 部署

```bash
sudo cp deployments/systemd/shield.service /etc/systemd/system/
sudo useradd -r -s /bin/false shield
sudo mkdir -p /opt/shield/{configs,logs,data}
sudo cp configs/config.yaml /opt/shield/configs/
sudo cp bin/shield /opt/shield/
sudo systemctl daemon-reload
sudo systemctl enable --now shield
```

查看状态：

```bash
sudo systemctl status shield
sudo journalctl -u shield -f
```

## API 文档

管理 API 默认监听 `admin_bind_addr`（默认 `:9090`）：

| 接口 | 方法 | 说明 |
|------|------|------|
| `GET /health` | HTTP | 健康检查 |
| `GET /stats` | HTTP | 实时统计（请求数、拦截数、活跃连接等）|
| `GET /blacklist` | HTTP | 查看当前黑名单 |

示例：

```bash
curl http://127.0.0.1:9090/health
curl http://127.0.0.1:9090/stats
curl http://127.0.0.1:9090/blacklist
```

详细 API 文档见 [docs/api.md](docs/api.md)。

## 架构设计

Shield 采用标准分层架构：

```
Handler → Service → Engine / Storage
```

- **Handler 层** — HTTP 入口，解析请求、调用 Service、格式化响应
- **Service 层** — 业务编排，调用 Repository 和 Engine
- **Engine 层** — 攻击检测引擎（SQL 注入、XSS、DDoS 等）
- **Storage 层** — 数据持久化（黑名单、规则等）

详细架构设计见 [docs/architecture.md](docs/architecture.md)。

## 系统要求

- Linux x86_64
- Go 1.18+（从源码编译）
- 内存：≥ 128MB
- CPU：≥ 1 核

## License

MIT
