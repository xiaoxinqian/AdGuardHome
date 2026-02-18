package home

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/AdguardTeam/AdGuardHome/internal/aghhttp"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
)

func (web *webAPI) registerSecurityHandlers() {
	web.conf.mux.Handle(http.MethodGet+" "+"/control/security/status", web.postInstallHandler(http.HandlerFunc(web.handleSecurityStatus)))
	web.conf.mux.Handle(http.MethodGet+" "+"/control/security/score", web.postInstallHandler(http.HandlerFunc(web.handleSecurityScore)))
	web.conf.mux.Handle(http.MethodPost+" "+"/control/security/totp/enable", web.postInstallHandler(http.HandlerFunc(web.handleTOTPEnable)))
	web.conf.mux.Handle(http.MethodPost+" "+"/control/security/totp/disable", web.postInstallHandler(http.HandlerFunc(web.handleTOTPDisable)))
	web.conf.mux.Handle(http.MethodGet+" "+"/control/security/totp/qrcode", web.postInstallHandler(http.HandlerFunc(web.handleTOTPQRCode)))
}

type securityStatusResponse struct {
	TOTPEnabled       bool `json:"totp_enabled"`
	PasswordPolicy    bool `json:"password_policy"`
	CustomPath        bool `json:"custom_path"`
	SessionTimeout    int  `json:"session_timeout_minutes"`
	MaxLoginAttempts  int  `json:"max_login_attempts"`
	NotifyEnabled     bool `json:"notify_enabled"`
	AuditEnabled      bool `json:"audit_enabled"`
	DNSWhitelistCount int  `json:"dns_whitelist_count"`
}

func (web *webAPI) handleSecurityStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	resp := &securityStatusResponse{}

	config.RLock()
	defer config.RUnlock()

	if config.Security != nil {
		resp.CustomPath = config.Security.CustomPath != ""

		if config.Security.TOTP != nil {
			resp.TOTPEnabled = config.Security.TOTP.Enabled
		}

		if config.Security.PasswordPolicy != nil {
			resp.PasswordPolicy = true
		}

		if config.Security.Login != nil {
			resp.MaxLoginAttempts = config.Security.Login.MaxAttempts
		}

		if config.Security.Session != nil {
			resp.SessionTimeout = int(time.Duration(config.Security.Session.Timeout).Minutes())
		}

		resp.DNSWhitelistCount = len(config.Security.AllowedDNSClients)
	}

	if config.Notify != nil {
		resp.NotifyEnabled = config.Notify.Enabled
	}

	if config.Audit != nil {
		resp.AuditEnabled = config.Audit.Enabled
	}

	aghhttp.WriteJSONResponseOK(ctx, web.logger, w, r, resp)
}

type securityScoreResponse struct {
	Score       int             `json:"score"`
	MaxScore    int             `json:"max_score"`
	Level       string          `json:"level"`
	Checks      []securityCheck `json:"checks"`
	Suggestions []string        `json:"suggestions"`
}

type securityCheck struct {
	Name        string `json:"name"`
	Passed      bool   `json:"passed"`
	Description string `json:"description"`
}

func (web *webAPI) handleSecurityScore(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	score := 0
	maxScore := 100
	var checks []securityCheck
	var suggestions []string

	config.RLock()
	defer config.RUnlock()

	totpEnabled := config.Security != nil && config.Security.TOTP != nil && config.Security.TOTP.Enabled
	checks = append(checks, securityCheck{
		Name:        "totp",
		Passed:      totpEnabled,
		Description: "TOTP 二步验证",
	})
	if totpEnabled {
		score += 20
	} else {
		suggestions = append(suggestions, "启用 TOTP 二步验证以提高账户安全")
	}

	policyEnabled := config.Security != nil && config.Security.PasswordPolicy != nil
	checks = append(checks, securityCheck{
		Name:        "password_policy",
		Passed:      policyEnabled,
		Description: "强密码策略",
	})
	if policyEnabled {
		score += 20
	} else {
		suggestions = append(suggestions, "启用强密码策略以防止弱密码")
	}

	customPathEnabled := config.Security != nil && config.Security.CustomPath != ""
	checks = append(checks, securityCheck{
		Name:        "custom_path",
		Passed:      customPathEnabled,
		Description: "自定义管理路径",
	})
	if customPathEnabled {
		score += 15
	} else {
		suggestions = append(suggestions, "配置自定义管理路径以隐藏登录入口")
	}

	httpsEnabled := config.TLS.Enabled
	checks = append(checks, securityCheck{
		Name:        "https",
		Passed:      httpsEnabled,
		Description: "HTTPS 加密",
	})
	if httpsEnabled {
		score += 15
	} else {
		suggestions = append(suggestions, "启用 HTTPS 以加密通信")
	}

	notifyEnabled := config.Notify != nil && config.Notify.Enabled
	checks = append(checks, securityCheck{
		Name:        "notify",
		Passed:      notifyEnabled,
		Description: "邮件告警",
	})
	if notifyEnabled {
		score += 10
	} else {
		suggestions = append(suggestions, "配置邮件告警以及时获取安全事件通知")
	}

	auditEnabled := config.Audit != nil && config.Audit.Enabled
	checks = append(checks, securityCheck{
		Name:        "audit",
		Passed:      auditEnabled,
		Description: "审计日志",
	})
	if auditEnabled {
		score += 10
	} else {
		suggestions = append(suggestions, "启用审计日志以记录安全事件")
	}

	dnsWhitelistEnabled := config.Security != nil && len(config.Security.AllowedDNSClients) > 0
	checks = append(checks, securityCheck{
		Name:        "dns_whitelist",
		Passed:      dnsWhitelistEnabled,
		Description: "DNS 访问控制",
	})
	if dnsWhitelistEnabled {
		score += 10
	} else {
		suggestions = append(suggestions, "配置 DNS 白名单以防止 DNS 滥用")
	}

	level := "较差"
	if score >= 80 {
		level = "优秀"
	} else if score >= 60 {
		level = "良好"
	} else if score >= 40 {
		level = "一般"
	}

	resp := &securityScoreResponse{
		Score:       score,
		MaxScore:    maxScore,
		Level:       level,
		Checks:      checks,
		Suggestions: suggestions,
	}

	aghhttp.WriteJSONResponseOK(ctx, web.logger, w, r, resp)
}

func (web *webAPI) handleTOTPEnable(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req struct {
		Secret string `json:"secret"`
		Code   string `json:"code"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		aghhttp.ErrorAndLog(ctx, web.logger, r, w, http.StatusBadRequest, "json decode: %s", err)
		return
	}

	config.Lock()
	defer config.Unlock()

	if config.Security == nil {
		config.Security = &securityConfig{}
	}
	if config.Security.TOTP == nil {
		config.Security.TOTP = &totpConfig{}
	}

	config.Security.TOTP.Enabled = true
	config.Security.TOTP.Secret = req.Secret

	web.logger.InfoContext(ctx, "totp enabled", slogutil.KeyPrefix, "security")

	aghhttp.WriteJSONResponseOK(ctx, web.logger, w, r, map[string]bool{"success": true})
}

func (web *webAPI) handleTOTPDisable(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	config.Lock()
	defer config.Unlock()

	if config.Security != nil && config.Security.TOTP != nil {
		config.Security.TOTP.Enabled = false
	}

	web.logger.InfoContext(ctx, "totp disabled", slogutil.KeyPrefix, "security")

	aghhttp.WriteJSONResponseOK(ctx, web.logger, w, r, map[string]bool{"success": true})
}

func (web *webAPI) handleTOTPQRCode(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	config.RLock()
	if config.Security == nil || config.Security.TOTP == nil || !config.Security.TOTP.Enabled {
		config.RUnlock()
		aghhttp.ErrorAndLog(ctx, web.logger, r, w, http.StatusNotFound, "totp not enabled")
		return
	}
	secret := config.Security.TOTP.Secret
	config.RUnlock()

	username := "admin"
	config.RLock()
	if len(config.Users) > 0 {
		username = config.Users[0].Name
	}
	config.RUnlock()

	qrCode, err := generateTOTPQRCode(secret, username)
	if err != nil {
		aghhttp.ErrorAndLog(ctx, web.logger, r, w, http.StatusInternalServerError, "generating qr code: %s", err)
		return
	}

	w.Header().Set("Content-Type", "image/png")
	w.Write(qrCode)
	web.logger.DebugContext(ctx, "totp qr code generated", slogutil.KeyPrefix, "security")
}

func generateTOTPQRCode(secret, username string) ([]byte, error) {
	svc := NewTOTPService(&TOTPServiceConfig{
		Issuer: "AdGuardHome",
	})
	if err := svc.SetSecret(secret); err != nil {
		return nil, err
	}
	return svc.GenerateQRCode(username)
}
