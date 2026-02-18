package notify

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/smtp"
	"strings"
	"sync"
	"time"

	"github.com/AdguardTeam/AdGuardHome/internal/auditlog"
	"github.com/AdguardTeam/AdGuardHome/internal/crypto"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
)

var (
	ErrNotConfigured = errors.New("notify service not configured")
	ErrTestFailed    = errors.New("notification test failed")
	ErrInvalidConfig = errors.New("invalid smtp configuration")
)

type SMTPConfig struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	UseTLS   bool   `yaml:"use_tls"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	From     string `yaml:"from"`
	To       string `yaml:"to"`
}

type NotifyConfig struct {
	Enabled bool                 `yaml:"enabled"`
	SMTP    *SMTPConfig          `yaml:"smtp"`
	Events  []auditlog.EventType `yaml:"events"`
}

type NotifyService struct {
	mu        sync.RWMutex
	config    *NotifyConfig
	encryptor *crypto.EncryptedStore
	logger    *slog.Logger
	templates map[auditlog.EventType]*template.Template
	enabled   bool
}

type NotifyServiceConfig struct {
	Config    *NotifyConfig
	Encryptor *crypto.EncryptedStore
	Logger    *slog.Logger
}

func NewNotifyService(conf *NotifyServiceConfig) *NotifyService {
	if conf.Logger == nil {
		conf.Logger = slog.Default()
	}

	ns := &NotifyService{
		config:    conf.Config,
		encryptor: conf.Encryptor,
		logger:    conf.Logger.With(slogutil.KeyPrefix, "notify"),
		templates: make(map[auditlog.EventType]*template.Template),
	}

	if conf.Config != nil {
		ns.enabled = conf.Config.Enabled
	}

	ns.initTemplates()

	return ns
}

func (ns *NotifyService) initTemplates() {
	templates := map[auditlog.EventType]string{
		auditlog.EventLoginSuccess: `
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family: Arial, sans-serif; padding: 20px;">
<h2 style="color: #28a745;">登录成功通知</h2>
<p>您的 AdGuardHome 管理后台有新的登录：</p>
<ul>
<li><strong>用户名：</strong> {{.Username}}</li>
<li><strong>IP 地址：</strong> {{.IPAddress}}</li>
<li><strong>时间：</strong> {{.Timestamp}}</li>
<li><strong>设备：</strong> {{.UserAgent}}</li>
</ul>
<p>如果这不是您本人的操作，请立即修改密码。</p>
</body>
</html>`,
		auditlog.EventLoginFailure: `
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family: Arial, sans-serif; padding: 20px;">
<h2 style="color: #ffc107;">登录失败警告</h2>
<p>检测到登录失败尝试：</p>
<ul>
<li><strong>用户名：</strong> {{.Username}}</li>
<li><strong>IP 地址：</strong> {{.IPAddress}}</li>
<li><strong>时间：</strong> {{.Timestamp}}</li>
</ul>
<p>请关注账户安全。</p>
</body>
</html>`,
		auditlog.EventLoginLockout: `
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family: Arial, sans-serif; padding: 20px;">
<h2 style="color: #dc3545;">账户锁定警告</h2>
<p>由于多次登录失败，IP 已被锁定：</p>
<ul>
<li><strong>IP 地址：</strong> {{.IPAddress}}</li>
<li><strong>时间：</strong> {{.Timestamp}}</li>
</ul>
<p>如果这不是您本人的操作，您的账户可能正在遭受暴力破解攻击。</p>
</body>
</html>`,
		auditlog.EventNewDevice: `
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family: Arial, sans-serif; padding: 20px;">
<h2 style="color: #17a2b8;">新设备登录通知</h2>
<p>检测到新设备登录您的账户：</p>
<ul>
<li><strong>用户名：</strong> {{.Username}}</li>
<li><strong>IP 地址：</strong> {{.IPAddress}}</li>
<li><strong>时间：</strong> {{.Timestamp}}</li>
<li><strong>设备：</strong> {{.UserAgent}}</li>
</ul>
<p>如果这不是您本人的操作，请立即修改密码。</p>
</body>
</html>`,
		auditlog.EventGeoAnomaly: `
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family: Arial, sans-serif; padding: 20px;">
<h2 style="color: #dc3545;">异地登录警告</h2>
<p>检测到异常的异地登录：</p>
<ul>
<li><strong>用户名：</strong> {{.Username}}</li>
<li><strong>IP 地址：</strong> {{.IPAddress}}</li>
<li><strong>时间：</strong> {{.Timestamp}}</li>
</ul>
<p>如果这不是您本人的操作，请立即修改密码。</p>
</body>
</html>`,
		auditlog.EventConfigChange: `
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family: Arial, sans-serif; padding: 20px;">
<h2 style="color: #17a2b8;">配置修改通知</h2>
<p>安全配置已被修改：</p>
<ul>
<li><strong>用户名：</strong> {{.Username}}</li>
<li><strong>IP 地址：</strong> {{.IPAddress}}</li>
<li><strong>时间：</strong> {{.Timestamp}}</li>
<li><strong>操作：</strong> {{.Action}}</li>
</ul>
</body>
</html>`,
	}

	for eventType, tmplStr := range templates {
		tmpl, err := template.New(string(eventType)).Parse(tmplStr)
		if err != nil {
			ns.logger.Error("parsing template", "event", eventType, slogutil.KeyError, err)
			continue
		}
		ns.templates[eventType] = tmpl
	}
}

func (ns *NotifyService) Send(ctx context.Context, event *auditlog.AuditEvent) error {
	ns.mu.RLock()
	defer ns.mu.RUnlock()

	if !ns.enabled {
		return nil
	}

	if ns.config == nil || ns.config.SMTP == nil {
		return ErrNotConfigured
	}

	if !ns.shouldNotify(event.EventType) {
		return nil
	}

	tmpl, ok := ns.templates[event.EventType]
	if !ok {
		return nil
	}

	var body bytes.Buffer
	if err := tmpl.Execute(&body, event); err != nil {
		return fmt.Errorf("executing template: %w", err)
	}

	subject := ns.getSubject(event.EventType)

	return ns.sendEmail(ctx, subject, body.String())
}

func (ns *NotifyService) shouldNotify(eventType auditlog.EventType) bool {
	if len(ns.config.Events) == 0 {
		return true
	}

	for _, e := range ns.config.Events {
		if e == eventType {
			return true
		}
	}

	return false
}

func (ns *NotifyService) getSubject(eventType auditlog.EventType) string {
	subjects := map[auditlog.EventType]string{
		auditlog.EventLoginSuccess:   "[AdGuardHome] 登录成功通知",
		auditlog.EventLoginFailure:   "[AdGuardHome] 登录失败警告",
		auditlog.EventLoginLockout:   "[AdGuardHome] 账户锁定警告",
		auditlog.EventNewDevice:      "[AdGuardHome] 新设备登录通知",
		auditlog.EventGeoAnomaly:     "[AdGuardHome] 异地登录警告",
		auditlog.EventConfigChange:   "[AdGuardHome] 配置修改通知",
		auditlog.EventTOTPEnable:     "[AdGuardHome] TOTP 已启用",
		auditlog.EventTOTPDisable:    "[AdGuardHome] TOTP 已禁用",
		auditlog.EventPasswordChange: "[AdGuardHome] 密码已修改",
	}

	if subject, ok := subjects[eventType]; ok {
		return subject
	}

	return "[AdGuardHome] 安全通知"
}

func (ns *NotifyService) sendEmail(ctx context.Context, subject, body string) error {
	smtpConfig := ns.config.SMTP

	password := smtpConfig.Password
	if ns.encryptor != nil && strings.HasPrefix(password, "$encrypted$") {
		decrypted, err := ns.encryptor.DecryptString(strings.TrimPrefix(password, "$encrypted$"))
		if err != nil {
			return fmt.Errorf("decrypting password: %w", err)
		}
		password = decrypted
	}

	addr := fmt.Sprintf("%s:%d", smtpConfig.Host, smtpConfig.Port)

	var auth smtp.Auth
	if smtpConfig.Username != "" {
		auth = smtp.PlainAuth("", smtpConfig.Username, password, smtpConfig.Host)
	}

	msg := fmt.Sprintf("From: %s\r\n", smtpConfig.From)
	msg += fmt.Sprintf("To: %s\r\n", smtpConfig.To)
	msg += fmt.Sprintf("Subject: %s\r\n", subject)
	msg += "MIME-version: 1.0;\r\nContent-Type: text/html; charset=\"utf-8\";\r\n"
	msg += "\r\n"
	msg += body

	var client *smtp.Client
	var err error

	if smtpConfig.UseTLS {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: false,
			ServerName:         smtpConfig.Host,
		}

		conn, err := tls.Dial("tcp", addr, tlsConfig)
		if err != nil {
			return fmt.Errorf("tls dial: %w", err)
		}

		client, err = smtp.NewClient(conn, smtpConfig.Host)
		if err != nil {
			return fmt.Errorf("creating smtp client: %w", err)
		}
	} else {
		client, err = smtp.Dial(addr)
		if err != nil {
			return fmt.Errorf("dialing smtp: %w", err)
		}
	}
	defer client.Close()

	if auth != nil {
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("smtp auth: %w", err)
		}
	}

	if err := client.Mail(smtpConfig.From); err != nil {
		return fmt.Errorf("setting sender: %w", err)
	}

	if err := client.Rcpt(smtpConfig.To); err != nil {
		return fmt.Errorf("setting recipient: %w", err)
	}

	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("getting data writer: %w", err)
	}

	_, err = w.Write([]byte(msg))
	if err != nil {
		return fmt.Errorf("writing message: %w", err)
	}

	if err := w.Close(); err != nil {
		return fmt.Errorf("closing writer: %w", err)
	}

	if err := client.Quit(); err != nil {
		ns.logger.DebugContext(ctx, "quit smtp client", slogutil.KeyError, err)
	}

	ns.logger.InfoContext(ctx, "email sent", "to", smtpConfig.To, "subject", subject)

	return nil
}

func (ns *NotifyService) Test(ctx context.Context) error {
	ns.mu.RLock()
	defer ns.mu.RUnlock()

	if ns.config == nil || ns.config.SMTP == nil {
		return ErrNotConfigured
	}

	_ = &auditlog.AuditEvent{
		EventType: auditlog.EventLoginSuccess,
		Timestamp: time.Now(),
		Username:  "test",
		IPAddress: "127.0.0.1",
		UserAgent: "Test Agent",
	}

	return ns.sendEmail(ctx, "[AdGuardHome] 测试邮件", `
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family: Arial, sans-serif; padding: 20px;">
<h2>测试邮件</h2>
<p>这是一封测试邮件，用于验证 SMTP 配置是否正确。</p>
<p>发送时间: `+time.Now().Format("2006-01-02 15:04:05")+`</p>
</body>
</html>`)
}

func (ns *NotifyService) SetConfig(config *NotifyConfig) error {
	ns.mu.Lock()
	defer ns.mu.Unlock()

	ns.config = config
	ns.enabled = config.Enabled

	return nil
}

func (ns *NotifyService) SetEnabled(enabled bool) {
	ns.mu.Lock()
	defer ns.mu.Unlock()

	ns.enabled = enabled
	if ns.config != nil {
		ns.config.Enabled = enabled
	}
}

func (ns *NotifyService) IsEnabled() bool {
	ns.mu.RLock()
	defer ns.mu.RUnlock()

	return ns.enabled
}

func (ns *NotifyService) GetConfig() *NotifyConfig {
	ns.mu.RLock()
	defer ns.mu.RUnlock()

	return ns.config
}

func (ns *NotifyService) EncryptPassword(encryptor *crypto.EncryptedStore, password string) (string, error) {
	if encryptor == nil {
		return password, nil
	}

	encrypted, err := encryptor.EncryptString(password)
	if err != nil {
		return "", fmt.Errorf("encrypting password: %w", err)
	}

	return "$encrypted$" + encrypted, nil
}
