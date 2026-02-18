&nbsp;
<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="doc/adguard_home_darkmode.svg">
    <img alt="AdGuard Home 私人定制安全版" src="doc/adguard_home_lightmode.svg" width="300px">
  </picture>
</p>
<h3 align="center">私人定制安全版 - 专为公网暴露环境设计</h3>
<p align="center">
  基于 AdGuard Home 官方版本二次开发，专注于单人使用、动态 IP、移动网络场景下的极致安全加固
</p>
<p align="center">
  <a href="https://github.com/xiaoxinqian/AdGuardHome/releases">
    <img src="https://img.shields.io/github/release/xiaoxinqian/AdGuardHome/all.svg" alt="Latest release"/>
  </a>
  <a href="https://github.com/xiaoxinqian/AdGuardHome/issues">
    <img src="https://img.shields.io/github/issues/xiaoxinqian/AdGuardHome.svg" alt="Issues"/>
  </a>
</p>
<br/>
<hr/>

## 特性概览

### 安全功能

| 功能 | 说明 |
|------|------|
| TOTP 二步验证 | 支持 Google Authenticator 等验证器 |
| 强密码策略 | 12位以上，包含大小写字母、数字、特殊字符 |
| 登录审计日志 | 记录所有登录、操作、异常事件 |
| 单用户模式 | 禁止添加其他用户，仅保留管理员 |
| 单设备登录 | 新设备登录自动注销其他设备 |
| 自定义管理路径 | 隐藏默认登录入口，防止扫描 |
| 登录失败锁定 | 5次失败锁定30分钟 |
| DNS 访问控制 | 仅授权设备可使用 DNS 解析 |
| 邮件告警 | SMTP 通知登录、异常事件 |
| 安全响应头 | CSP、X-Frame-Options 等防护 |
| 扫描器检测 | 自动拦截 nikto、sqlmap 等扫描工具 |

### 命令行工具 (agh)

```bash
agh status           # 查看系统状态
agh reset-password   # 重置管理员密码
agh disable-2fa      # 禁用二步验证
agh reset-2fa        # 重置二步验证密钥
agh sessions         # 查看活跃会话
agh logout <ID>      # 注销指定会话
agh logs             # 查看审计日志
agh whitelist        # 管理 DNS 白名单
agh security-check   # 安全检查
agh security-wizard  # 安全配置向导
agh notify           # 邮件告警配置
```

## 快速安装

### 一键安装脚本

```bash
curl -sSL https://raw.githubusercontent.com/xiaoxinqian/AdGuardHome/master/scripts/install-security.sh | bash
```

安装完成后会显示：
- 自定义管理路径
- TOTP 密钥
- 管理员账号信息

### 手动安装

1. 下载最新版本：[Releases](https://github.com/xiaoxinqian/AdGuardHome/releases)
2. 解压并运行：
   ```bash
   tar xzf AdGuardHome_linux_amd64.tar.gz
   cd AdGuardHome
   ./AdGuardHome -s install
   ./AdGuardHome -s start
   ```

## 配置示例

```yaml
http:
  address: 0.0.0.0:80
  session_ttl: 30m

users:
  - name: admin
    password: "$bcrypt_hash"

security:
  single_user_mode: true
  custom_path: "your-secret-path-12345678"
  password_policy:
    min_length: 12
    require_upper: true
    require_lower: true
    require_digit: true
    require_special: true
  totp:
    enabled: true
    secret: "YOUR_TOTP_SECRET"
  session:
    single_device: true
    timeout: 30m
  login:
    max_attempts: 5
    lockout_period: 30m
  allowed_dns_clients:
    - 192.168.1.0/24

audit:
  enabled: true
  retention_days: 90

notify:
  enabled: true
  smtp:
    host: smtp.example.com
    port: 587
    use_tls: true
    username: your@email.com
    password: "$encrypted$..."
    from: noreply@example.com
    to: admin@example.com
  events:
    - login_success
    - login_failure
    - login_lockout
    - new_device
    - geo_anomaly
```

## 从源码构建

### 前置要求

- Go 1.25+
- Node.js 18+
- npm

### 构建

```bash
# 克隆仓库
git clone https://github.com/xiaoxinqian/AdGuardHome.git
cd AdGuardHome

# 构建
make build

# 或者使用简化脚本构建发布版本
./scripts/build-release-simple.sh 1.0.0
```

### 构建产物

构建脚本会生成以下平台的二进制文件：

- Linux: amd64, arm64, armv6, armv7
- macOS: amd64 (Intel), arm64 (Apple Silicon)
- Windows: amd64, arm64

## 移动端优化

本版本针对重度手机用户进行了 UI 优化：

- 响应式登录页面
- 大尺寸触摸按钮 (44x44px+)
- TOTP 验证码输入优化
- 账户锁定提示
- 密码显示/隐藏切换

## 与官方版本的区别

| 特性 | 官方版本 | 私人定制安全版 |
|------|---------|---------------|
| 多语言支持 | 38种语言 | 仅简体中文 |
| 用户管理 | 多用户 | 单用户模式 |
| TOTP | 无 | 内置支持 |
| 密码策略 | 可配置 | 强制强密码 |
| 审计日志 | 无 | 完整记录 |
| 邮件告警 | 无 | 内置 SMTP |
| 安全评分 | 无 | 7项检查 |
| 移动端优化 | 基础 | 深度优化 |

## 安全建议

1. **启用 TOTP** - 防止密码泄露后被未授权访问
2. **配置自定义路径** - 隐藏管理入口，防止自动化扫描
3. **启用邮件告警** - 及时了解安全事件
4. **配置 DNS 白名单** - 防止 DNS 滥用
5. **定期检查审计日志** - 发现异常登录行为

## 项目文档

- [需求规格文档](.monkeycode/specs/adguard-private-security/requirements.md)
- [技术设计文档](.monkeycode/specs/adguard-private-security/design.md)
- [实施任务列表](.monkeycode/specs/adguard-private-security/tasklist.md)

## 致谢

本项目基于 [AdGuard Home](https://github.com/AdguardTeam/AdGuardHome) 官方版本进行二次开发，感谢 AdGuard 团队的开源贡献。

## License

GNU General Public License v3.0

---

**警告**: 本版本专为公网暴露、动态 IP、单人使用场景设计。所有安全功能默认开启，请妥善保管管理路径和 TOTP 密钥。
