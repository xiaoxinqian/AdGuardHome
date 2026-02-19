#!/bin/bash

# AdGuardHome 私人定制安全版 - 一键安装脚本
# 版本: 1.0.0

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# 默认配置
VERSION="1.0.0"
INSTALL_DIR="/opt/adguard-home"
DATA_DIR="/var/lib/adguard-home"
SERVICE_NAME="adguard-home"
REPO_URL="https://github.com/xiaoxinqian/AdGuardHome"

# 打印函数
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# 检测系统架构
detect_arch() {
    case $(uname -m) in
        x86_64|amd64)
            echo "amd64"
            ;;
        aarch64|arm64)
            echo "arm64"
            ;;
        armv7l|armhf)
            echo "armv7"
            ;;
        *)
            print_error "不支持的架构: $(uname -m)"
            exit 1
            ;;
    esac
}

# 检测操作系统
detect_os() {
    if [ -f /etc/debian_version ]; then
        echo "debian"
    elif [ -f /etc/redhat-release ]; then
        echo "redhat"
    elif [ -f /etc/arch-release ]; then
        echo "arch"
    else
        echo "unknown"
    fi
}

# 检查 root 权限
check_root() {
    if [ "$EUID" -ne 0 ]; then
        print_error "请使用 root 权限运行此脚本"
        exit 1
    fi
}

# 安装依赖
install_dependencies() {
    print_info "安装依赖..."
    
    local os=$(detect_os)
    
    case $os in
        debian)
            apt-get update -qq
            apt-get install -y -qq curl wget ca-certificates openssl
            ;;
        redhat)
            yum install -y -q curl wget ca-certificates openssl
            ;;
        arch)
            pacman -Sy --noconfirm curl wget ca-certificates openssl
            ;;
        *)
            print_warning "未知系统，跳过依赖安装"
            ;;
    esac
}

# 生成随机管理路径
generate_custom_path() {
    openssl rand -hex 8
}

# 生成 TOTP 密钥
generate_totp_secret() {
    openssl rand -base32 20 | tr -d '='
}

# 验证密码强度
validate_password() {
    local password=$1
    
    if [ ${#password} -lt 12 ]; then
        return 1
    fi
    
    if ! echo "$password" | grep -q '[A-Z]'; then
        return 1
    fi
    
    if ! echo "$password" | grep -q '[a-z]'; then
        return 1
    fi
    
    if ! echo "$password" | grep -q '[0-9]'; then
        return 1
    fi
    
    if ! echo "$password" | grep -q '[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]'; then
        return 1
    fi
    
    return 0
}

# 设置管理员密码
set_admin_password() {
    print_info "设置管理员密码"
    echo ""
    echo "密码策略要求:"
    echo "  - 最少 12 位字符"
    echo "  - 包含大写字母"
    echo "  - 包含小写字母"
    echo "  - 包含数字"
    echo "  - 包含特殊字符 (!@#$%^&* 等)"
    echo ""
    
    while true; do
        read -s -p "请输入管理员密码: " PASSWORD < /dev/tty
        echo ""
        
        if ! validate_password "$PASSWORD"; then
            print_error "密码不符合策略要求，请重新输入"
            continue
        fi
        
        read -s -p "请再次输入密码: " PASSWORD_CONFIRM < /dev/tty
        echo ""
        
        if [ "$PASSWORD" != "$PASSWORD_CONFIRM" ]; then
            print_error "两次输入的密码不一致"
            continue
        fi
        
        break
    done
    
    print_success "密码设置成功"
}

# 下载二进制文件
download_binary() {
    local arch=$(detect_arch)
    local download_url="${REPO_URL}/releases/download/v${VERSION}/AdGuardHome_linux_${arch}.tar.gz"
    local tmp_dir=$(mktemp -d)
    
    print_info "下载 AdGuardHome (架构: ${arch})..."
    
    cd "$tmp_dir"
    
    if ! wget -q "$download_url" -O AdGuardHome.tar.gz 2>/dev/null; then
        print_warning "无法从 GitHub 下载，使用本地编译版本..."
        if [ -f "/workspace/bin/AdGuardHome" ]; then
            cp /workspace/bin/AdGuardHome "${INSTALL_DIR}/"
        else
            print_error "请先编译项目或手动下载二进制文件"
            exit 1
        fi
    else
        tar xzf AdGuardHome.tar.gz
        mv AdGuardHome/AdGuardHome "${INSTALL_DIR}/"
    fi
    
    cd - > /dev/null
    rm -rf "$tmp_dir"
    
    chmod +x "${INSTALL_DIR}/AdGuardHome"
    
    print_success "二进制文件准备完成"
}

# 生成初始配置文件
generate_config() {
    local custom_path=$(generate_custom_path)
    local totp_secret=$(generate_totp_secret)
    
    print_info "生成配置文件..."
    
    mkdir -p "$DATA_DIR"
    
    cat > "${DATA_DIR}/AdGuardHome.yaml" << EOF
http:
  address: 0.0.0.0:80
  session_ttl: 30m

users:
  - name: admin
    password: ""

security:
  single_user_mode: true
  custom_path: "${custom_path}"
  password_policy:
    min_length: 12
    require_upper: true
    require_lower: true
    require_digit: true
    require_special: true
  totp:
    enabled: true
    secret: "${totp_secret}"
  session:
    single_device: true
    timeout: 30m
  login:
    max_attempts: 5
    lockout_period: 30m

audit:
  enabled: true
  retention_days: 90
  log_file: ${DATA_DIR}/audit.log

dns:
  bind_hosts:
    - 0.0.0.0
  port: 53
  bootstrap_dns:
    - 223.5.5.5
    - 119.29.29.29
  upstream_dns:
    - https://dns.alidns.com/dns-query
    - https://doh.pub/dns-query

filtering:
  protection_enabled: true
  filtering_enabled: true

querylog:
  enabled: true
  interval: 168h

statistics:
  enabled: true
  interval: 168h
EOF
    
    echo "$custom_path" > "${DATA_DIR}/.custom_path"
    echo "$totp_secret" > "${DATA_DIR}/.totp_secret"
    
    print_success "配置文件生成完成"
}

# 创建 systemd 服务
create_service() {
    print_info "创建 systemd 服务..."
    
    cat > /etc/systemd/system/${SERVICE_NAME}.service << EOF
[Unit]
Description=AdGuard Home Private Security Edition
Documentation=https://github.com/xiaoxinqian/AdGuardHome
After=network.target
Wants=network.target

[Service]
Type=simple
User=root
WorkingDirectory=${DATA_DIR}
ExecStart=${INSTALL_DIR}/AdGuardHome -c ${DATA_DIR}/AdGuardHome.yaml -w ${DATA_DIR}
Restart=on-failure
RestartSec=5s
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable ${SERVICE_NAME}
    
    print_success "服务创建完成"
}

# 配置防火墙
configure_firewall() {
    print_info "配置防火墙..."
    
    if command -v ufw &> /dev/null; then
        ufw allow 80/tcp
        ufw allow 53/tcp
        ufw allow 53/udp
        print_success "UFW 防火墙规则已添加"
    elif command -v firewall-cmd &> /dev/null; then
        firewall-cmd --permanent --add-port=80/tcp
        firewall-cmd --permanent --add-port=53/tcp
        firewall-cmd --permanent --add-port=53/udp
        firewall-cmd --reload
        print_success "Firewalld 防火墙规则已添加"
    else
        print_warning "未检测到防火墙，请手动配置"
    fi
}

# 设置密码
set_password() {
    print_info "设置管理员密码..."
    
    cd "$DATA_DIR"
    
    HASHED_PASSWORD=$(openssl passwd -6 "$PASSWORD")
    
    sed -i "s/password: \"\"/password: \"${HASHED_PASSWORD}\"/" "${DATA_DIR}/AdGuardHome.yaml"
    
    print_success "密码已设置"
}

# 启动服务
start_service() {
    print_info "启动服务..."
    
    systemctl start ${SERVICE_NAME}
    
    sleep 2
    
    if systemctl is-active --quiet ${SERVICE_NAME}; then
        print_success "服务启动成功"
    else
        print_error "服务启动失败"
        journalctl -u ${SERVICE_NAME} --no-pager -n 20
        exit 1
    fi
}

# 安装 agh 命令
install_agh() {
    print_info "安装 agh 命令行工具..."
    
    if [ -f "${INSTALL_DIR}/agh" ]; then
        ln -sf "${INSTALL_DIR}/agh" /usr/local/bin/agh
    else
        cat > /usr/local/bin/agh << 'AGHEOF'
#!/bin/bash
cd /var/lib/adguard-home
/opt/adguard-home/agh "$@"
AGHEOF
        chmod +x /usr/local/bin/agh
    fi
    
    print_success "agh 命令已安装"
}

# 显示完成信息
show_completion() {
    local custom_path=$(cat "${DATA_DIR}/.custom_path" 2>/dev/null || echo "unknown")
    local totp_secret=$(cat "${DATA_DIR}/.totp_secret" 2>/dev/null || echo "unknown")
    local server_ip=$(curl -s ifconfig.me 2>/dev/null || echo "YOUR_SERVER_IP")
    
    echo ""
    echo "=========================================="
    echo -e "${GREEN}安装完成!${NC}"
    echo "=========================================="
    echo ""
    echo -e "${YELLOW}重要信息:${NC}"
    echo ""
    echo "管理后台地址:"
    echo -e "  ${GREEN}http://${server_ip}/${custom_path}/${NC}"
    echo ""
    echo "用户名: admin"
    echo "密码: (您设置的密码)"
    echo ""
    echo -e "${YELLOW}TOTP 二步验证:${NC}"
    echo "  密钥: ${totp_secret}"
    echo "  请使用 Google Authenticator 或其他验证器添加此密钥"
    echo ""
    echo -e "${YELLOW}命令行工具:${NC}"
    echo "  agh status        - 查看系统状态"
    echo "  agh security-check - 安全检查"
    echo "  agh help          - 查看所有命令"
    echo ""
    echo -e "${YELLOW}安全建议:${NC}"
    echo "  1. 请妥善保管管理路径和 TOTP 密钥"
    echo "  2. 建议配置 HTTPS (运行 agh security-wizard)"
    echo "  3. 建议配置邮件告警 (编辑配置文件)"
    echo ""
    echo "日志文件: ${DATA_DIR}/audit.log"
    echo "配置文件: ${DATA_DIR}/AdGuardHome.yaml"
    echo ""
    echo "=========================================="
}

# 主函数
main() {
    echo ""
    echo "=========================================="
    echo " AdGuardHome 私人定制安全版 安装脚本"
    echo " 版本: ${VERSION}"
    echo "=========================================="
    echo ""
    
    check_root
    install_dependencies
    
    mkdir -p "$INSTALL_DIR"
    mkdir -p "$DATA_DIR"
    
    set_admin_password
    download_binary
    generate_config
    create_service
    configure_firewall
    set_password
    start_service
    install_agh
    show_completion
}

# 运行安装
main "$@"
