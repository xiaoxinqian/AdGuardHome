package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	Version        = "1.0.0"
	ConfigFileName = "AdGuardHome.yaml"
	DataDirName    = "data"
	ServiceName    = "adguard-home"
)

var (
	configDir string
	dataDir   string
)

func main() {
	if len(os.Args) < 2 {
		printHelp()
		os.Exit(1)
	}

	detectPaths()

	command := os.Args[1]
	args := os.Args[2:]

	switch command {
	case "status":
		cmdStatus()
	case "reset-password":
		cmdResetPassword(args)
	case "disable-2fa":
		cmdDisable2FA()
	case "reset-2fa":
		cmdReset2FA()
	case "sessions":
		cmdSessions()
	case "logout":
		cmdLogout(args)
	case "logs":
		cmdLogs(args)
	case "whitelist":
		cmdWhitelist(args)
	case "security-check":
		cmdSecurityCheck()
	case "security-wizard":
		cmdSecurityWizard()
	case "notify":
		cmdNotify(args)
	case "version":
		fmt.Printf("agh 版本 %s\n", Version)
		fmt.Printf("系统: %s/%s\n", runtime.GOOS, runtime.GOARCH)
	case "help", "-h", "--help":
		printHelp()
	default:
		fmt.Printf("未知命令: %s\n\n", command)
		printHelp()
		os.Exit(1)
	}
}

func detectPaths() {
	execPath, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "获取可执行文件路径失败: %v\n", err)
		os.Exit(1)
	}

	configDir = filepath.Dir(execPath)
	dataDir = filepath.Join(configDir, DataDirName)

	if _, err := os.Stat(filepath.Join(configDir, ConfigFileName)); os.IsNotExist(err) {
		altConfigDir := "/opt/adguard-home"
		if _, err := os.Stat(filepath.Join(altConfigDir, ConfigFileName)); err == nil {
			configDir = altConfigDir
			dataDir = filepath.Join(configDir, DataDirName)
		}
	}
}

func printHelp() {
	fmt.Println(`AdGuardHome 私人定制安全版 - 命令行管理工具

用法: agh <命令> [参数]

命令:
  status           查看系统状态、版本、端口、运行信息
  reset-password   重置管理员密码
  disable-2fa      禁用二步验证
  reset-2fa        重置二步验证密钥
  sessions         查看当前活跃会话
  logout <会话ID>  强制注销指定会话
  logs [类型]      查看登录与安全审计日志
  whitelist        管理访问规则 (DNS 白名单)
  security-check   执行安全检查并输出报告
  security-wizard  一键安全配置向导
  notify           配置、测试、开关邮件告警
  version          显示版本信息
  help             显示帮助信息

示例:
  agh status
  agh reset-password
  agh logs login
  agh whitelist add 192.168.1.100
  agh notify test
`)
}

func cmdStatus() {
	fmt.Println("=== AdGuardHome 私人定制安全版 ===")
	fmt.Println()

	fmt.Println("【系统信息】")
	fmt.Printf("  版本: %s\n", Version)
	fmt.Printf("  系统: %s/%s\n", runtime.GOOS, runtime.GOARCH)
	fmt.Printf("  配置目录: %s\n", configDir)
	fmt.Printf("  数据目录: %s\n", dataDir)
	fmt.Println()

	fmt.Println("【服务状态】")
	if isServiceRunning() {
		fmt.Println("  状态: 运行中 ✓")

		pid := getServicePID()
		if pid > 0 {
			fmt.Printf("  PID: %d\n", pid)
		}

		uptime := getServiceUptime()
		if uptime > 0 {
			fmt.Printf("  运行时间: %s\n", formatDuration(uptime))
		}
	} else {
		fmt.Println("  状态: 未运行 ✗")
	}
	fmt.Println()

	fmt.Println("【网络配置】")
	port := getConfigPort()
	if port != "" {
		fmt.Printf("  HTTP 端口: %s\n", port)
	}

	tlsPort := getConfigTLSPort()
	if tlsPort != "" {
		fmt.Printf("  HTTPS 端口: %s\n", tlsPort)
	}

	dnsPort := getConfigDNSPort()
	if dnsPort != "" {
		fmt.Printf("  DNS 端口: %s\n", dnsPort)
	}
	fmt.Println()

	fmt.Println("【安全配置】")
	printSecurityStatus()
}

func isServiceRunning() bool {
	if runtime.GOOS == "linux" {
		cmd := exec.Command("systemctl", "is-active", ServiceName)
		if err := cmd.Run(); err == nil {
			return true
		}
	}

	pidFile := filepath.Join(dataDir, "AdGuardHome.pid")
	if data, err := os.ReadFile(pidFile); err == nil {
		pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
		if err == nil {
			if process, err := os.FindProcess(pid); err == nil {
				if err := process.Signal(syscall.Signal(0)); err == nil {
					return true
				}
			}
		}
	}

	return false
}

func getServicePID() int {
	pidFile := filepath.Join(dataDir, "AdGuardHome.pid")
	if data, err := os.ReadFile(pidFile); err == nil {
		pid, _ := strconv.Atoi(strings.TrimSpace(string(data)))
		return pid
	}
	return 0
}

func getServiceUptime() time.Duration {
	pidFile := filepath.Join(dataDir, "AdGuardHome.pid")
	stat, err := os.Stat(pidFile)
	if err != nil {
		return 0
	}
	return time.Since(stat.ModTime())
}

func getConfigPort() string {
	configFile := filepath.Join(configDir, ConfigFileName)
	data, err := os.ReadFile(configFile)
	if err != nil {
		return ""
	}

	lines := strings.Split(string(data), "\n")
	for i, line := range lines {
		if strings.Contains(line, "address:") && i > 0 {
			parts := strings.Split(line, ":")
			if len(parts) >= 2 {
				addr := strings.TrimSpace(parts[len(parts)-1])
				if strings.Contains(addr, ":") {
					return addr[strings.LastIndex(addr, ":")+1:]
				}
				return addr
			}
		}
	}
	return "80"
}

func getConfigTLSPort() string {
	return ""
}

func getConfigDNSPort() string {
	return "53"
}

func printSecurityStatus() {
	configFile := filepath.Join(configDir, ConfigFileName)
	data, err := os.ReadFile(configFile)
	if err != nil {
		fmt.Println("  无法读取配置文件")
		return
	}

	content := string(data)

	hasTOTP := strings.Contains(content, "totp:") && strings.Contains(content, "enabled: true")
	if hasTOTP {
		fmt.Println("  TOTP 二步验证: 已启用 ✓")
	} else {
		fmt.Println("  TOTP 二步验证: 未启用")
	}

	hasCustomPath := strings.Contains(content, "custom_path:")
	if hasCustomPath {
		fmt.Println("  自定义管理路径: 已配置 ✓")
	} else {
		fmt.Println("  自定义管理路径: 未配置")
	}

	hasPasswordPolicy := strings.Contains(content, "password_policy:")
	if hasPasswordPolicy {
		fmt.Println("  强密码策略: 已启用 ✓")
	} else {
		fmt.Println("  强密码策略: 未启用")
	}

	hasNotify := strings.Contains(content, "notify:") && strings.Contains(content, "enabled: true")
	if hasNotify {
		fmt.Println("  邮件告警: 已启用 ✓")
	} else {
		fmt.Println("  邮件告警: 未启用")
	}
}

func cmdResetPassword(args []string) {
	fmt.Println("=== 重置管理员密码 ===")

	policy := `
密码策略要求:
  - 最少 12 位字符
  - 包含大写字母
  - 包含小写字母
  - 包含数字
  - 包含特殊字符 (!@#$%^&* 等)
`
	fmt.Println(policy)

	reader := bufio.NewReader(os.Stdin)

	var password string
	for {
		fmt.Print("请输入新密码: ")
		password, _ = reader.ReadString('\n')
		password = strings.TrimSpace(password)

		if !validatePassword(password) {
			fmt.Println("密码不符合策略要求，请重新输入")
			continue
		}

		fmt.Print("请再次输入密码: ")
		confirm, _ := reader.ReadString('\n')
		confirm = strings.TrimSpace(confirm)

		if password != confirm {
			fmt.Println("两次输入的密码不一致，请重试")
			continue
		}

		break
	}

	fmt.Println("\n正在重置密码...")

	cmd := exec.Command(filepath.Join(configDir, "AdGuardHome"), "--reset-password", password)
	cmd.Dir = configDir
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("重置密码失败: %v\n%s\n", err, output)
		os.Exit(1)
	}

	fmt.Println("密码重置成功!")
}

func validatePassword(password string) bool {
	if len(password) < 12 {
		return false
	}

	hasUpper := false
	hasLower := false
	hasDigit := false
	hasSpecial := false

	for _, c := range password {
		switch {
		case c >= 'A' && c <= 'Z':
			hasUpper = true
		case c >= 'a' && c <= 'z':
			hasLower = true
		case c >= '0' && c <= '9':
			hasDigit = true
		default:
			if strings.Contains("!@#$%^&*()_+-=[]{}|;':\",./<>?`~", string(c)) {
				hasSpecial = true
			}
		}
	}

	return hasUpper && hasLower && hasDigit && hasSpecial
}

func cmdDisable2FA() {
	fmt.Println("=== 禁用二步验证 ===")

	configFile := filepath.Join(configDir, ConfigFileName)
	data, err := os.ReadFile(configFile)
	if err != nil {
		fmt.Printf("读取配置文件失败: %v\n", err)
		os.Exit(1)
	}

	content := string(data)

	if !strings.Contains(content, "totp:") {
		fmt.Println("TOTP 未配置")
		return
	}

	lines := strings.Split(content, "\n")
	var newLines []string
	inTOTP := false

	for _, line := range lines {
		if strings.HasPrefix(line, "  totp:") {
			inTOTP = true
			newLines = append(newLines, "  totp:")
			newLines = append(newLines, "    enabled: false")
			continue
		}

		if inTOTP && strings.HasPrefix(line, "    ") {
			if strings.HasPrefix(line, "    enabled:") {
				continue
			}
			if strings.HasPrefix(line, "    secret:") {
				continue
			}
		}

		if inTOTP && !strings.HasPrefix(line, "    ") {
			inTOTP = false
		}

		if !inTOTP || !strings.HasPrefix(line, "    enabled:") {
			newLines = append(newLines, line)
		}
	}

	newContent := strings.Join(newLines, "\n")
	if err := os.WriteFile(configFile, []byte(newContent), 0600); err != nil {
		fmt.Printf("写入配置文件失败: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("二步验证已禁用")
	fmt.Println("请重启服务使配置生效: systemctl restart adguard-home")
}

func cmdReset2FA() {
	fmt.Println("=== 重置二步验证密钥 ===")

	secret := generateTOTPSecret()

	configFile := filepath.Join(configDir, ConfigFileName)
	data, err := os.ReadFile(configFile)
	if err != nil {
		fmt.Printf("读取配置文件失败: %v\n", err)
		os.Exit(1)
	}

	content := string(data)

	if !strings.Contains(content, "totp:") {
		lines := strings.Split(content, "\n")
		var newLines []string
		inserted := false

		for _, line := range lines {
			newLines = append(newLines, line)
			if strings.HasPrefix(line, "users:") && !inserted {
				newLines = append(newLines, "  totp:")
				newLines = append(newLines, "    enabled: true")
				newLines = append(newLines, fmt.Sprintf("    secret: %s", secret))
				inserted = true
			}
		}

		content = strings.Join(newLines, "\n")
	} else {
		content = strings.Replace(content, "enabled: false", "enabled: true", 1)
		if strings.Contains(content, "secret:") {
			re := regexp.MustCompile(`secret:\s*\S+`)
			content = re.ReplaceAllString(content, fmt.Sprintf("secret: %s", secret))
		}
	}

	if err := os.WriteFile(configFile, []byte(content), 0600); err != nil {
		fmt.Printf("写入配置文件失败: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("新的 TOTP 密钥: %s\n", secret)
	fmt.Println("请使用 Google Authenticator 或其他验证器扫描二维码")
	fmt.Println("请重启服务使配置生效: systemctl restart adguard-home")
}

func generateTOTPSecret() string {
	const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	b := make([]byte, 32)
	for i := range b {
		b[i] = charset[i%len(charset)]
	}
	return string(b)
}

func cmdSessions() {
	fmt.Println("=== 当前活跃会话 ===")

	sessionsDB := filepath.Join(dataDir, "sessions.db")
	if _, err := os.Stat(sessionsDB); os.IsNotExist(err) {
		fmt.Println("无会话数据库")
		return
	}

	fmt.Println("会话列表功能需要服务端 API 支持")
	fmt.Printf("会话数据库位置: %s\n", sessionsDB)
}

func cmdLogout(args []string) {
	if len(args) == 0 {
		fmt.Println("用法: agh logout <会话ID>")
		os.Exit(1)
	}

	sessionID := args[0]
	fmt.Printf("正在注销会话: %s\n", sessionID)
	fmt.Println("注销功能需要服务端 API 支持")
}

func cmdLogs(args []string) {
	logType := "all"
	if len(args) > 0 {
		logType = args[0]
	}

	fmt.Println("=== 审计日志 ===")

	auditLog := filepath.Join(dataDir, "audit.log")
	if _, err := os.Stat(auditLog); os.IsNotExist(err) {
		fmt.Println("无审计日志文件")
		return
	}

	file, err := os.Open(auditLog)
	if err != nil {
		fmt.Printf("打开日志文件失败: %v\n", err)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineCount := 0
	maxLines := 50

	for scanner.Scan() {
		line := scanner.Text()
		if logType != "all" && !strings.Contains(strings.ToLower(line), logType) {
			continue
		}

		fmt.Println(line)
		lineCount++

		if lineCount >= maxLines {
			fmt.Printf("\n... 显示最近 %d 条记录，使用 'agh logs' 查看更多\n", maxLines)
			break
		}
	}
}

func cmdWhitelist(args []string) {
	if len(args) == 0 {
		printWhitelistHelp()
		return
	}

	subCmd := args[0]
	subArgs := args[1:]

	switch subCmd {
	case "list":
		listWhitelist()
	case "add":
		if len(subArgs) == 0 {
			fmt.Println("用法: agh whitelist add <IP或CIDR>")
			os.Exit(1)
		}
		addWhitelist(subArgs[0])
	case "remove", "delete":
		if len(subArgs) == 0 {
			fmt.Println("用法: agh whitelist remove <IP或CIDR>")
			os.Exit(1)
		}
		removeWhitelist(subArgs[0])
	default:
		printWhitelistHelp()
	}
}

func printWhitelistHelp() {
	fmt.Println(`DNS 白名单管理

用法: agh whitelist <命令> [参数]

命令:
  list             显示当前白名单
  add <IP>         添加 IP 到白名单
  remove <IP>      从白名单移除 IP

示例:
  agh whitelist list
  agh whitelist add 192.168.1.100
  agh whitelist add 192.168.1.0/24
  agh whitelist remove 192.168.1.100
`)
}

func listWhitelist() {
	fmt.Println("=== DNS 白名单 ===")

	configFile := filepath.Join(configDir, ConfigFileName)
	data, err := os.ReadFile(configFile)
	if err != nil {
		fmt.Printf("读取配置文件失败: %v\n", err)
		return
	}

	content := string(data)

	if !strings.Contains(content, "allowed_dns_clients:") {
		fmt.Println("未配置 DNS 白名单 (默认允许所有)")
		return
	}

	fmt.Println("已授权的 DNS 客户端:")
	fmt.Println("(配置解析需要完整实现)")
}

func addWhitelist(ip string) {
	fmt.Printf("添加 %s 到白名单...\n", ip)
	fmt.Println("白名单管理功能需要修改配置文件并重启服务")
}

func removeWhitelist(ip string) {
	fmt.Printf("从白名单移除 %s...\n", ip)
	fmt.Println("白名单管理功能需要修改配置文件并重启服务")
}

func cmdSecurityCheck() {
	fmt.Println("=== 安全检查 ===")
	fmt.Println()

	score := 0
	maxScore := 100

	fmt.Println("【检查项目】")

	if checkPasswordPolicy() {
		fmt.Println("✓ 强密码策略已启用")
		score += 20
	} else {
		fmt.Println("✗ 强密码策略未启用")
	}

	if checkTOTP() {
		fmt.Println("✓ TOTP 二步验证已启用")
		score += 20
	} else {
		fmt.Println("✗ TOTP 二步验证未启用")
	}

	if checkCustomPath() {
		fmt.Println("✓ 自定义管理路径已配置")
		score += 15
	} else {
		fmt.Println("✗ 自定义管理路径未配置")
	}

	if checkHTTPS() {
		fmt.Println("✓ HTTPS 已启用")
		score += 15
	} else {
		fmt.Println("✗ HTTPS 未启用")
	}

	if checkNotify() {
		fmt.Println("✓ 邮件告警已启用")
		score += 10
	} else {
		fmt.Println("✗ 邮件告警未启用")
	}

	if checkAuditLog() {
		fmt.Println("✓ 审计日志已启用")
		score += 10
	} else {
		fmt.Println("✗ 审计日志未启用")
	}

	if checkDNSWhitelist() {
		fmt.Println("✓ DNS 访问控制已配置")
		score += 10
	} else {
		fmt.Println("✗ DNS 访问控制未配置")
	}

	fmt.Println()
	fmt.Printf("【安全评分】%d/%d\n", score, maxScore)

	if score >= 80 {
		fmt.Println("安全等级: 优秀")
	} else if score >= 60 {
		fmt.Println("安全等级: 良好")
	} else if score >= 40 {
		fmt.Println("安全等级: 一般")
	} else {
		fmt.Println("安全等级: 较差")
	}

	fmt.Println()
	fmt.Println("建议运行 'agh security-wizard' 进行一键安全加固")
}

func checkPasswordPolicy() bool {
	configFile := filepath.Join(configDir, ConfigFileName)
	data, err := os.ReadFile(configFile)
	if err != nil {
		return false
	}
	return strings.Contains(string(data), "password_policy:")
}

func checkTOTP() bool {
	configFile := filepath.Join(configDir, ConfigFileName)
	data, err := os.ReadFile(configFile)
	if err != nil {
		return false
	}
	content := string(data)
	return strings.Contains(content, "totp:") && strings.Contains(content, "enabled: true")
}

func checkCustomPath() bool {
	configFile := filepath.Join(configDir, ConfigFileName)
	data, err := os.ReadFile(configFile)
	if err != nil {
		return false
	}
	return strings.Contains(string(data), "custom_path:")
}

func checkHTTPS() bool {
	configFile := filepath.Join(configDir, ConfigFileName)
	data, err := os.ReadFile(configFile)
	if err != nil {
		return false
	}
	content := string(data)
	return strings.Contains(content, "tls:") && strings.Contains(content, "enabled: true")
}

func checkNotify() bool {
	configFile := filepath.Join(configDir, ConfigFileName)
	data, err := os.ReadFile(configFile)
	if err != nil {
		return false
	}
	content := string(data)
	return strings.Contains(content, "notify:") && strings.Contains(content, "enabled: true")
}

func checkAuditLog() bool {
	configFile := filepath.Join(configDir, ConfigFileName)
	data, err := os.ReadFile(configFile)
	if err != nil {
		return false
	}
	content := string(data)
	return strings.Contains(content, "audit:") && strings.Contains(content, "enabled: true")
}

func checkDNSWhitelist() bool {
	configFile := filepath.Join(configDir, ConfigFileName)
	data, err := os.ReadFile(configFile)
	if err != nil {
		return false
	}
	return strings.Contains(string(data), "allowed_dns_clients:")
}

func cmdSecurityWizard() {
	fmt.Println("=== 安全配置向导 ===")
	fmt.Println()

	reader := bufio.NewReader(os.Stdin)

	fmt.Println("此向导将帮助您配置以下安全功能:")
	fmt.Println("  1. 强密码策略")
	fmt.Println("  2. TOTP 二步验证")
	fmt.Println("  3. 自定义管理路径")
	fmt.Println("  4. 邮件告警")
	fmt.Println("  5. 审计日志")
	fmt.Println()

	fmt.Print("是否继续? (y/n): ")
	confirm, _ := reader.ReadString('\n')
	confirm = strings.TrimSpace(strings.ToLower(confirm))

	if confirm != "y" && confirm != "yes" {
		fmt.Println("已取消")
		return
	}

	fmt.Println("\n配置中...")

	customPath := generateCustomPath()
	totpSecret := generateTOTPSecret()

	configAdditions := fmt.Sprintf(`
security:
  single_user_mode: true
  custom_path: "%s"
  password_policy:
    min_length: 12
    require_upper: true
    require_lower: true
    require_digit: true
    require_special: true
  totp:
    enabled: true
    secret: %s

audit:
  enabled: true
  retention_days: 90
`, customPath, totpSecret)

	fmt.Println("\n请在配置文件中添加以下内容:")
	fmt.Println(configAdditions)

	fmt.Printf("\n自定义管理路径: /%s\n", customPath)
	fmt.Printf("TOTP 密钥: %s\n", totpSecret)
	fmt.Println("\n请使用验证器应用添加 TOTP")
	fmt.Println("\n配置完成后，请重启服务: systemctl restart adguard-home")
}

func generateCustomPath() string {
	b := make([]byte, 8)
	for i := range b {
		b[i] = "abcdefghijklmnopqrstuvwxyz0123456789"[i%36]
	}
	return fmt.Sprintf("%x", b)
}

func cmdNotify(args []string) {
	if len(args) == 0 {
		printNotifyHelp()
		return
	}

	subCmd := args[0]

	switch subCmd {
	case "test":
		testNotify()
	case "enable":
		setNotifyEnabled(true)
	case "disable":
		setNotifyEnabled(false)
	case "status":
		notifyStatus()
	case "config":
		notifyConfig()
	default:
		printNotifyHelp()
	}
}

func printNotifyHelp() {
	fmt.Println(`邮件告警管理

用法: agh notify <命令>

命令:
  test      发送测试邮件
  enable    启用邮件告警
  disable   禁用邮件告警
  status    查看告警状态
  config    配置 SMTP

示例:
  agh notify test
  agh notify enable
`)
}

func testNotify() {
	fmt.Println("发送测试邮件...")
	fmt.Println("此功能需要服务端 API 支持")
}

func setNotifyEnabled(enabled bool) {
	status := "启用"
	if !enabled {
		status = "禁用"
	}
	fmt.Printf("正在%s邮件告警...\n", status)
	fmt.Println("此功能需要修改配置文件")
}

func notifyStatus() {
	fmt.Println("=== 邮件告警状态 ===")
	if checkNotify() {
		fmt.Println("状态: 已启用")
	} else {
		fmt.Println("状态: 未启用")
	}
}

func notifyConfig() {
	fmt.Println("=== SMTP 配置 ===")
	fmt.Println("请手动编辑配置文件配置 SMTP:")
	fmt.Println()
	fmt.Println(`notify:
  enabled: true
  smtp:
    host: smtp.example.com
    port: 587
    use_tls: true
    username: your@email.com
    password: your_password
    from: noreply@example.com
    to: admin@example.com
  events:
    - login_success
    - login_failure
    - login_lockout
    - new_device
    - geo_anomaly
`)
}

func formatDuration(d time.Duration) string {
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	minutes := int(d.Minutes()) % 60

	if days > 0 {
		return fmt.Sprintf("%d天%d小时%d分钟", days, hours, minutes)
	}
	if hours > 0 {
		return fmt.Sprintf("%d小时%d分钟", hours, minutes)
	}
	return fmt.Sprintf("%d分钟", minutes)
}
