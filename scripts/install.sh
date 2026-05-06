#!/bin/bash
#
# Shield WAF 在线安装脚本
# 从 GitHub Releases 下载最新版本并自动安装
#
# 一键安装:
#   curl -fsSL https://raw.githubusercontent.com/zcxads666/shield/main/scripts/install.sh | sudo bash
#
# 安装指定版本:
#   sudo bash install.sh --version v1.14.8
#
# 卸载:
#   sudo bash install.sh uninstall
#

set -e

REPO="zcxads666/shield"
SHIELD_DIR="/opt/shield"
SERVICE_NAME="shield"
USER_NAME="shield"
GITHUB_API="https://api.github.com/repos/${REPO}"
GITHUB_DL="https://github.com/${REPO}/releases/download"

# 颜色
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "请使用 root 权限运行: sudo bash install.sh"
        exit 1
    fi
}

detect_arch() {
    local arch
    case "$(uname -m)" in
        x86_64|amd64)    arch="amd64" ;;
        aarch64|arm64)   arch="arm64" ;;
        *)               log_error "不支持的架构: $(uname -m)"; exit 1 ;;
    esac
    echo "$arch"
}

detect_os() {
    local os
    case "$(uname -s | tr '[:upper:]' '[:lower:]')" in
        linux)   os="linux" ;;
        darwin)  os="darwin" ;;
        *)       log_error "不支持的系统: $(uname -s)"; exit 1 ;;
    esac
    echo "$os"
}

get_latest_version() {
    local tag
    tag=$(curl -fsSL "${GITHUB_API}/releases/latest" 2>/dev/null | grep -oP '"tag_name":\s*"\K[^"]+' || true)
    if [ -z "$tag" ]; then
        log_error "无法获取最新版本，请检查网络或使用 --version 指定版本"
        exit 1
    fi
    echo "$tag"
}

download_binary() {
    local version="$1"
    local os="$2"
    local arch="$3"
    local fname="shield-${os}-${arch}"
    local url="${GITHUB_DL}/${version}/${fname}"

    log_info "下载 Shield ${version} (${os}/${arch})..."
    log_info "URL: ${url}"

    mkdir -p "$SHIELD_DIR/bin"

    if command -v wget &>/dev/null; then
        wget -q --show-progress -O "$SHIELD_DIR/bin/shield" "$url" || {
            log_error "下载失败，请检查版本是否存在: ${version}"
            exit 1
        }
    elif command -v curl &>/dev/null; then
        curl -fSL --progress-bar -o "$SHIELD_DIR/bin/shield" "$url" || {
            log_error "下载失败，请检查版本是否存在: ${version}"
            exit 1
        }
    else
        log_error "未找到 wget 或 curl"
        exit 1
    fi

    chmod 755 "$SHIELD_DIR/bin/shield"
    log_info "二进制文件已安装: $SHIELD_DIR/bin/shield"
}

create_user() {
    if ! id "$USER_NAME" &>/dev/null; then
        log_info "创建用户: $USER_NAME"
        useradd -r -s /bin/false -d "$SHIELD_DIR" "$USER_NAME" 2>/dev/null || true
    else
        log_info "用户 $USER_NAME 已存在"
    fi
}

create_dirs() {
    mkdir -p "$SHIELD_DIR"
    mkdir -p "$SHIELD_DIR/data"
    mkdir -p "$SHIELD_DIR/logs"
}

create_config() {
    if [ -f "$SHIELD_DIR/config.yaml" ] && [ "${FORCE:-0}" != "1" ]; then
        log_info "配置文件已存在，跳过创建"
        return
    fi

    log_info "创建默认配置文件"
    cat > "$SHIELD_DIR/config.yaml" << 'CONFIGEOF'
server:
  bind_addr: ":8080"
  read_timeout_ms: 30000
  write_timeout_ms: 30000
  max_header_bytes: 1048576
  max_body_size: 104857600
  max_concurrent: 1000
  queue_timeout_ms: 5000
  high_priority_ratio: 0.2
  pid_file: "./data/shield.pid"
  status_file: "./data/status.json"

proxy:
  target_url: "http://127.0.0.1:8082"
  set_headers: {}
  trust_forwarded: true

rate_limit:
  enabled: true
  requests_per_second: 100
  burst_size: 150
  block_duration_sec: 300

ddos_cc:
  enabled: true
  requests_per_second: 50
  burst_size: 80
  max_connections_per_ip: 1000
  slowloris_timeout_ms: 30000
  global_rate_danger_threshold: 5000
  global_rate_distributed_threshold: 22
  global_distributed_path_threshold: 30
  global_concentrated_path_threshold: 3
  max_requests: 500
  burst_requests: 800
  window_sec: 60
  behavior_score_threshold: 70
  behavior_block_threshold: 30
  path_ip_threshold: 50
  path_avg_req_threshold: 3
  path_time_window_sec: 600
  suspicion_challenge_threshold: 50
  suspicion_block_threshold: 80
  block_duration_sec: 600
  js_challenge_enabled: true
  captcha_challenge_enabled: true
  pow_challenge_enabled: true
  pow_difficulty: 3
  env_fingerprint_enabled: true

sql_inject:
  enabled: true
  action: block
  severity_level: high

xss:
  enabled: true
  action: block
  filter_response: false

upload:
  enabled: true
  action: block
  max_file_size_mb: 100

brute_force:
  enabled: true
  max_failures: 5
  window_sec: 60
  block_duration_sec: 600
  protected_paths:
    - /login
    - /api/auth
    - /admin
  status_codes:
    - 401
    - 403

blacklist:
  enabled: true
  persist_path: "./data/blacklist.json"
  auto_blacklist: true

log:
  level: info
  format: json
  output_path: "./logs/shield.log"
  max_size_mb: 100
  max_backups: 7
  max_age_days: 30

alert:
  enabled: false
  webhook: ""
  syslog_addr: ""
  threshold: 10

rules:
  rules_path: "./data/rules.yaml"
  hot_reload: true
  reload_interval_sec: 3

waiting_room:
  enabled: true
  max_queue_size: 5000
  release_per_sec: 5.0
  session_ttl_sec: 300
  queue_timeout_sec: 300
  active_threshold: 40

# port_mappings:
#   - id: "example-80"
#     listen: ":9090"
#     target: "192.168.1.100:80"
CONFIGEOF
    chown "$USER_NAME:$USER_NAME" "$SHIELD_DIR/config.yaml" 2>/dev/null || true
}

create_rules() {
    if [ -f "$SHIELD_DIR/data/rules.yaml" ] && [ "${FORCE:-0}" != "1" ]; then
        log_info "规则文件已存在，跳过创建"
        return
    fi

    log_info "创建默认规则文件"
    cat > "$SHIELD_DIR/data/rules.yaml" << 'RULESEOF'
rules:
  - id: R001
    name: Path Traversal Detection
    condition: request
    targets:
      uri: "(\.\./|\.\.\\|%2e%2e)"
    action: block
    severity: high

  - id: R002
    name: Command Injection Detection
    condition: request
    targets:
      body: "(;\s*\b(cat|ls|id|whoami|nc|bash|sh|cmd|powershell)\b)"
    action: block
    severity: critical

  - id: R003
    name: Sensitive File Access Detection
    condition: request
    targets:
      uri: "(\b(\.env|\.git|\.htaccess|\.ssh|id_rsa|passwd|shadow)\b)"
    action: block
    severity: high
RULESEOF
    chown "$USER_NAME:$USER_NAME" "$SHIELD_DIR/data/rules.yaml" 2>/dev/null || true
}

create_service() {
    if [ "$(uname -s)" != "Linux" ]; then
        log_warn "非 Linux 系统，跳过 systemd 服务创建"
        return
    fi

    log_info "创建 systemd 服务: $SERVICE_NAME"

    cat > /etc/systemd/system/${SERVICE_NAME}.service << SERVICEEOF
[Unit]
Description=Shield WAF - Web Application Firewall
Documentation=https://github.com/zcxads666/shield
After=network.target
Wants=network.target

[Service]
Type=simple
User=shield
Group=shield
WorkingDirectory=/opt/shield
ExecStart=/opt/shield/bin/shield -config /opt/shield/config.yaml start
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=shield
LimitNOFILE=65535
LimitNPROC=4096
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/shield

[Install]
WantedBy=multi-user.target
SERVICEEOF

    systemctl daemon-reload
    log_info "systemd 服务创建完成"
}

configure_firewall() {
    if [ "$(uname -s)" != "Linux" ]; then
        return
    fi

    log_info "配置防火墙..."
    if command -v ufw &>/dev/null; then
        ufw allow 8080/tcp 2>/dev/null || true
        log_info "ufw 规则已添加"
    elif command -v firewall-cmd &>/dev/null; then
        firewall-cmd --permanent --add-port=8080/tcp 2>/dev/null || true
        firewall-cmd --reload 2>/dev/null || true
        log_info "firewalld 规则已添加"
    else
        log_warn "未检测到防火墙，请手动开放所需端口"
    fi
}

set_permissions() {
    chown -R "$USER_NAME:$USER_NAME" "$SHIELD_DIR" 2>/dev/null || true
    chmod 755 "$SHIELD_DIR"
    chmod 755 "$SHIELD_DIR/bin/shield"
}

start_service() {
    if [ "$(uname -s)" != "Linux" ]; then
        log_info "macOS 手动启动: sudo $SHIELD_DIR/bin/shield -config $SHIELD_DIR/config.yaml"
        return
    fi

    log_info "启动 Shield 服务..."
    systemctl enable "$SERVICE_NAME" 2>/dev/null || true
    systemctl start "$SERVICE_NAME" 2>/dev/null || true
    sleep 2

    if systemctl is-active --quiet "$SERVICE_NAME"; then
        log_info "Shield 服务启动成功"
    else
        log_error "服务启动失败，查看日志: journalctl -u shield -n 50"
    fi
}

print_status() {
    echo ""
    echo "========================================"
    echo "  Shield WAF 安装完成"
    echo "========================================"
    echo ""
    echo "  安装目录: $SHIELD_DIR"
    echo "  配置文件: $SHIELD_DIR/config.yaml"
    echo "  日志文件: $SHIELD_DIR/logs/shield.log"
    echo "  服务名称: $SERVICE_NAME"
    echo "  版本:     $VERSION"
    echo ""

    if [ "$(uname -s)" = "Linux" ]; then
        echo "  常用命令:"
        echo "    systemctl start shield     # 启动"
        echo "    systemctl stop shield      # 停止"
        echo "    systemctl restart shield   # 重启"
        echo "    systemctl status shield    # 状态"
        echo "    journalctl -u shield -f    # 查看日志"
        echo ""
    fi

    echo "  CLI 管理:"
    echo "    shield -config /opt/shield/config.yaml status"
    echo "    shield -config /opt/shield/config.yaml stats"
    echo "    shield -config /opt/shield/config.yaml logs --lines 50"
    echo "    shield -config /opt/shield/config.yaml blacklist list"
    echo "    shield -config /opt/shield/config.yaml mapping list"
    echo ""
    echo "========================================"

    if [ "$(uname -s)" = "Linux" ]; then
        systemctl status "$SERVICE_NAME" --no-pager 2>/dev/null || true
    fi
}

uninstall() {
    log_warn "开始卸载 Shield..."

    if [ "$(uname -s)" = "Linux" ]; then
        systemctl stop "$SERVICE_NAME" 2>/dev/null || true
        systemctl disable "$SERVICE_NAME" 2>/dev/null || true
        rm -f /etc/systemd/system/${SERVICE_NAME}.service
        systemctl daemon-reload
    fi

    rm -rf "$SHIELD_DIR"
    userdel "$USER_NAME" 2>/dev/null || true
    log_info "Shield 已卸载"
}

main() {
    VERSION=""

    # 解析参数
    case "${1:-}" in
        uninstall|remove)
            check_root
            uninstall
            exit 0
            ;;
        --version)
            VERSION="$2"
            if [ -z "$VERSION" ]; then
                log_error "请指定版本号，例如: --version v1.14.8"
                exit 1
            fi
            shift 2
            ;;
    esac

    # 检测系统信息
    ARCH=$(detect_arch)
    OS=$(detect_os)

    # 获取版本
    if [ -z "$VERSION" ]; then
        VERSION=$(get_latest_version)
    fi

    log_info "Shield WAF 安装脚本"
    log_info "系统: ${OS}/${ARCH}, 版本: ${VERSION}"

    check_root
    create_user
    create_dirs
    download_binary "$VERSION" "$OS" "$ARCH"
    create_config
    create_rules
    create_service
    configure_firewall
    set_permissions
    start_service
    print_status
}

main "$@"
