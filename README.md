# Shield — Go WAF / Defense Tool

高性能 Go 语言 Web 应用防火墙（WAF），提供 DDoS/CC 防护、SQL 注入检测、XSS 过滤、暴力破解防护等功能。

## 快速开始（无需编译，直接运行）

```bash
# 1. 解压后进入目录
cd /opt/shield

# 2. 一键安装为系统服务
sudo bash scripts/install.sh

# 3. 启动服务
sudo systemctl start shield

# 4. 查看状态
sudo systemctl status shield
```

## 代理配置说明

Shield 作为反向代理运行，所有流量先经过 Shield 检测，再转发到后端服务。

### 基础代理配置（80 → 8080）

编辑 `configs/config.yaml`：

```yaml
server:
  bind_addr: ":80"          # Shield 监听端口（对外暴露）
  admin_bind_addr: ":9090"   # Admin API 端口

proxy:
  target_url: "http://127.0.0.1:8080"  # 后端服务地址
  trust_forwarded: true               # 信任 X-Forwarded-For 头
```

**效果：** 用户访问 `http://your-server:80` → Shield 检测 → 转发到本机 8080 端口的后端服务。

### 常见代理场景

#### 场景 1：Shield 占 80，后端占 8080（推荐）
```yaml
server:
  bind_addr: ":80"
proxy:
  target_url: "http://127.0.0.1:8080"
```

#### 场景 2：Shield 占 8080，后端占 80（测试环境）
```yaml
server:
  bind_addr: ":8080"
proxy:
  target_url: "http://127.0.0.1:80"
```

#### 场景 3：HTTPS 后端（内网 HTTPS）
```yaml
server:
  bind_addr: ":443"
proxy:
  target_url: "https://127.0.0.1:8443"
  trust_forwarded: true
```

#### 场景 4：反向代理到远程服务器
```yaml
server:
  bind_addr: ":80"
proxy:
  target_url: "http://192.168.1.100:8080"
  trust_forwarded: false
```

### 有反向代理时的配置（Nginx / CDN 前置）

如果 Nginx 或 CDN 在 Shield 前面，必须开启 `trust_forwarded`：

```yaml
proxy:
  target_url: "http://127.0.0.1:8080"
  trust_forwarded: true   # 必须开启，否则 DDoS 限流失效
```

**请求链路：**
```
用户 → Nginx/CDN → Shield(:80) → 后端(:8080)
         ↑
    X-Forwarded-For: 真实用户IP
```

## 完整配置参数说明

### server 段

| 参数 | 说明 | 示例 |
|------|------|------|
| bind_addr | Shield 监听地址 | `:80` |
| read_timeout_ms | 读取超时（毫秒） | `30000` |
| write_timeout_ms | 写入超时（毫秒） | `30000` |
| max_header_bytes | 请求头最大字节 | `1048576` |
| admin_bind_addr | Admin API 监听地址 | `:9090` |
| max_concurrent | 全局最大并发数 | `1000` |
| queue_timeout_ms | 排队等待超时（毫秒） | `5000` |
| high_priority_ratio | 高优先级槽位比例 | `0.2` |

### proxy 段

| 参数 | 说明 | 示例 |
|------|------|------|
| target_url | 后端服务地址 | `http://127.0.0.1:8080` |
| trust_forwarded | 是否信任 X-Forwarded-For | `true` / `false` |

### rate_limit 段（CC 防护）

| 参数 | 说明 | 示例 |
|------|------|------|
| enabled | 是否启用 | `true` |
| requests_per_second | 每秒请求数限制 | `100` |
| burst_size | 突发流量桶大小 | `150` |
| block_duration_sec | 阻断时长（秒） | `300` |

### ddos 段（DDoS 防护）

| 参数 | 说明 | 示例 |
|------|------|------|
| enabled | 是否启用 | `true` |
| max_connections_per_ip | 单 IP 最大连接数 | `1000` |
| slowloris_timeout_ms | 慢连接超时（毫秒） | `30000` |

### sql_inject / xss 段（攻击检测）

| 参数 | 说明 | 示例 |
|------|------|------|
| enabled | 是否启用检测 | `true` |
| action | 命中后动作 | `block` / `log` |

### brute_force 段（暴力破解防护）

| 参数 | 说明 | 示例 |
|------|------|------|
| max_failures | 最大失败次数 | `5` |
| window_sec | 统计窗口（秒） | `60` |
| block_duration_sec | 阻断时长（秒） | `600` |
| protected_paths | 受保护路径 | `["/login", "/api/auth"]` |
| status_codes | 计入失败的状态码 | `[401, 403]` |

### blacklist 段（黑名单）

| 参数 | 说明 | 示例 |
|------|------|------|
| enabled | 是否启用 | `true` |
| persist_path | 黑名单持久化文件 | `./data/blacklist.json` |
| auto_blacklist | 自动拉黑 | `true` |

### log 段（日志）

| 参数 | 说明 | 示例 |
|------|------|------|
| level | 日志级别 | `info` / `warn` / `error` |
| format | 格式 | `json` / `text` |
| output_path | 输出路径 | `./logs/shield.log` |

## Admin API

Shield 内置管理接口，默认监听 `admin_bind_addr`：

| 接口 | 方法 | 说明 |
|------|------|------|
| `GET /health` | HTTP | 健康检查 |
| `GET /stats` | HTTP | 实时统计（请求数、拦截数、活跃连接等）|
| `GET /blacklist` | HTTP | 查看当前黑名单 |

示例：
```bash
curl http://127.0.0.1:9090/health
curl http://127.0.0.1:9090/stats
```

## CLI 命令

```bash
# 启动服务（前台运行）
./bin/shield -config configs/config.yaml

# 查看统计
./bin/shield -cmd stats

# 查看黑名单
./bin/shield -cmd blacklist
```

## 项目结构

```
.
├── cmd/shield              # 应用程序入口
├── internal/               # 私有应用代码
│   ├── handler/            # HTTP 处理器层（Controller）
│   │   ├── admin.go        # 管理面板 API
│   │   └── proxy.go        # 代理请求处理
│   ├── service/            # 业务逻辑层
│   │   ├── alert/          # 告警通知
│   │   ├── ipreputation/   # IP 信誉评分
│   │   └── rules/          # 规则引擎
│   ├── storage/            # 数据持久化层
│   │   └── blacklist/      # IP 黑名单管理
│   └── defender/           # 安全防御模块
│       ├── bruteforce/     # 暴力破解防护
│       ├── cc/             # CC 攻击检测
│       ├── common/         # 共享工具函数
│       ├── ddos/           # DDoS 防护
│       ├── sqlinject/      # SQL 注入检测
│       ├── webshell/       # WebShell 上传检测
│       └── xss/            # XSS 攻击检测
├── pkg/                    # 可复用公共库
│   ├── config/             # 配置管理
│   ├── logger/             # 结构化日志
│   ├── metrics/            # 指标统计
│   ├── ratelimit/          # 令牌桶限流
│   └── semaphore/          # 优先级信号量
├── scripts/                # 脚本（安装、测试、运行）
├── testdata/               # 测试数据集
├── configs/                # 配置文件示例
├── deployments/            # 部署配置（Docker、Systemd）
├── docs/                   # 文档
└── README.md               # 本文件
```

## 测试

```bash
# 运行全部单元测试
go test ./...

# 运行安全测试脚本
bash scripts/security_test.sh

# 运行性能压测
bash scripts/benchmark.sh
```

## 系统要求

- Linux x86_64
- 无需 Go 环境（已提供编译好的二进制文件）
- 如需从源码编译：Go 1.21+

## License

MIT
