#!/bin/bash
#
# Shield WAF Linux 一键安装脚本
# 支持: Ubuntu / Debian / CentOS / RHEL / Fedora / Arch
#

set -e

SHIELD_DIR="/opt/shield"
SERVICE_NAME="shield"
USER_NAME="shield"

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# 检查 root 权限
check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "请使用 root 权限运行: sudo bash install.sh"
        exit 1
    fi
}

# 检测系统类型
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        VER=$VERSION_ID
    elif [ -f /etc/redhat-release ]; then
        OS="centos"
    elif [ -f /etc/arch-release ]; then
        OS="arch"
    else
        OS="unknown"
    fi
    log_info "检测到系统: $OS"
}

# 创建用户
create_user() {
    if ! id "$USER_NAME" &>/dev/null; then
        log_info "创建用户: $USER_NAME"
        useradd -r -s /bin/false -d "$SHIELD_DIR" "$USER_NAME" 2>/dev/null || true
    else
        log_info "用户 $USER_NAME 已存在"
    fi
}

# 安装目录
install_files() {
    log_info "安装 Shield 到 $SHIELD_DIR"
    
    # 创建目录
    mkdir -p "$SHIELD_DIR"
    mkdir -p "$SHIELD_DIR/data"
    mkdir -p "$SHIELD_DIR/logs"
    
    # 获取脚本所在目录
    SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
    
    # 复制文件
    if [ -f "$SCRIPT_DIR/bin/shield" ]; then
        cp "$SCRIPT_DIR/bin/shield" "$SHIELD_DIR/bin/shield"
        chmod +x "$SHIELD_DIR/bin/shield"
    else
        log_error "未找到 bin/shield，请确保在解压后的 Shield 目录中运行本脚本"
        exit 1
    fi
    
    # 复制配置文件
    if [ -f "$SCRIPT_DIR/config.yaml" ]; then
        cp "$SCRIPT_DIR/config.yaml" "$SHIELD_DIR/config.yaml"
    fi
    
    # 复制数据文件
    if [ -d "$SCRIPT_DIR/data" ]; then
        cp -r "$SCRIPT_DIR/data"/* "$SHIELD_DIR/data/" 2>/dev/null || true
    fi
    
    # 复制规则文件
    if [ -f "$SCRIPT_DIR/data/rules.yaml" ]; then
        cp "$SCRIPT_DIR/data/rules.yaml" "$SHIELD_DIR/data/rules.yaml"
    fi
    
    # 设置权限
    chown -R "$USER_NAME:$USER_NAME" "$SHIELD_DIR"
    chmod 755 "$SHIELD_DIR"
    chmod 755 "$SHIELD_DIR/bin/shield"
    
    log_info "文件安装完成"
}

# 创建 systemd 服务
create_service() {
    log_info "创建 systemd 服务: $SERVICE_NAME"
    
    cat > /etc/systemd/system/${SERVICE_NAME}.service << 'SERVICEEOF'
[Unit]
Description=Shield WAF - Web Application Firewall
Documentation=https://github.com/shield/shield
After=network.target
Wants=network.target

[Service]
Type=simple
User=shield
Group=shield
WorkingDirectory=/opt/shield
ExecStart=/opt/shield/bin/shield -config /opt/shield/config.yaml
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=shield

# 资源限制
LimitNOFILE=65535
LimitNPROC=4096

[Install]
WantedBy=multi-user.target
SERVICEEOF

    systemctl daemon-reload
    log_info "systemd 服务创建完成"
}

# 创建默认配置
create_default_config() {
    if [ ! -f "$SHIELD_DIR/config.yaml" ]; then
        log_info "创建默认配置文件"
        cat > "$SHIELD_DIR/config.yaml" << 'CONFIGEOF'
server:
  bind_addr: ":80"
  read_timeout_ms: 30000
  write_timeout_ms: 30000
  max_header_bytes: 1048576
  admin_bind_addr: ":9090"
  max_concurrent: 1000
  queue_timeout_ms: 5000
  high_priority_ratio: 0.2

proxy:
  target_url: "http://127.0.0.1:8080"
  trust_forwarded: true

rate_limit:
  enabled: true
  requests_per_second: 100
  burst_size: 150
  block_duration_sec: 300

ddos:
  enabled: true
  max_connections_per_ip: 1000
  slowloris_timeout_ms: 30000
  challenge_threshold: 500

sql_inject:
  enabled: true
  action: block
  severity_level: high

xss:
  enabled: true
  action: block
  filter_response: false

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
CONFIGEOF
        chown "$USER_NAME:$USER_NAME" "$SHIELD_DIR/config.yaml"
    fi
}

# 创建默认规则文件
create_default_rules() {
    if [ ! -f "$SHIELD_DIR/data/rules.yaml" ]; then
        log_info "创建默认规则文件"
        cat > "$SHIELD_DIR/data/rules.yaml" << 'RULESEOF'
rules:
  - id: block_scanner
    name: Block Common Scanner User-Agents
    condition: request
    targets:
      header_User-Agent: "(sqlmap|nikto|nmap|masscan|zgrab|gobuster|dirbuster)"
    action: block

  - id: block_bad_referer
    name: Block Suspicious Referers
    condition: request
    targets:
      header_Referer: "(xxx|porn|casino|spam)"
    action: block
RULESEOF
        chown "$USER_NAME:$USER_NAME" "$SHIELD_DIR/data/rules.yaml"
    fi
}

# 防火墙配置（可选）
configure_firewall() {
    log_info "配置防火墙..."
    
    # 检查是否有防火墙
    if command -v ufw &>/dev/null; then
        ufw allow 80/tcp 2>/dev/null || true
        ufw allow 443/tcp 2>/dev/null || true
        ufw allow 9090/tcp 2>/dev/null || true
        log_info "ufw 规则已添加"
    elif command -v firewall-cmd &>/dev/null; then
        firewall-cmd --permanent --add-port=80/tcp 2>/dev/null || true
        firewall-cmd --permanent --add-port=443/tcp 2>/dev/null || true
        firewall-cmd --permanent --add-port=9090/tcp 2>/dev/null || true
        firewall-cmd --reload 2>/dev/null || true
        log_info "firewalld 规则已添加"
    else
        log_warn "未检测到支持的防火墙，请手动开放 80/443/9090 端口"
    fi
}

# 启动服务
start_service() {
    log_info "启动 Shield 服务..."
    systemctl enable "$SERVICE_NAME"
    systemctl start "$SERVICE_NAME"
    sleep 2
    
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        log_info "Shield 服务启动成功"
    else
        log_error "Shield 服务启动失败，请检查日志: journalctl -u shield -n 50"
        exit 1
    fi
}

# 打印状态
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
    echo ""
    echo "  常用命令:"
    echo "    systemctl start shield     # 启动"
    echo "    systemctl stop shield      # 停止"
    echo "    systemctl restart shield   # 重启"
    echo "    systemctl status shield    # 状态"
    echo "    journalctl -u shield -f    # 查看日志"
    echo ""
    echo "  Admin API:"
    echo "    curl http://127.0.0.1:9090/health"
    echo "    curl http://127.0.0.1:9090/stats"
    echo ""
    echo "  当前代理配置:"
    grep -A2 "^proxy:" "$SHIELD_DIR/config.yaml" | sed 's/^/    /'
    echo ""
    echo "========================================"
    echo ""
    
    # 显示服务状态
    systemctl status "$SERVICE_NAME" --no-pager 2>/dev/null || true
}

# 卸载函数
uninstall() {
    log_warn "开始卸载 Shield..."
    systemctl stop "$SERVICE_NAME" 2>/dev/null || true
    systemctl disable "$SERVICE_NAME" 2>/dev/null || true
    rm -f /etc/systemd/system/${SERVICE_NAME}.service
    systemctl daemon-reload
    rm -rf "$SHIELD_DIR"
    userdel "$USER_NAME" 2>/dev/null || true
    log_info "Shield 已卸载"
}

# 主逻辑
main() {
    case "${1:-}" in
        uninstall|remove)
            check_root
            uninstall
            exit 0
            ;;
        *)
            check_root
            detect_os
            create_user
            install_files
            create_default_config
            create_default_rules
            create_service
            configure_firewall
            start_service
            print_status
            ;;
    esac
}

main "$@"
