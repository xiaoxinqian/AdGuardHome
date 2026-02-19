package home

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/AdguardTeam/AdGuardHome/internal/auditlog"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
)

const (
	DefaultMaxLoginAttempts = 5
	DefaultLockoutPeriod    = 30 * time.Minute
	DefaultCustomPathLength = 16
)

type SecurityConfig struct {
	CustomPath       string
	MaxLoginAttempts int
	LockoutPeriod    time.Duration
	HideVersion      bool
}

type SecurityMiddleware struct {
	logger          *slog.Logger
	config          *SecurityConfig
	rateLimiter     *authRateLimiter
	auditLogger     *auditlog.AuditLogger
	staticPaths     []string
	securityHeaders map[string]string
	scannerPatterns []string
}

type SecurityMiddlewareConfig struct {
	Logger      *slog.Logger
	Config      *SecurityConfig
	AuditLogger *auditlog.AuditLogger
	StaticPaths []string
}

func NewSecurityMiddleware(conf *SecurityMiddlewareConfig) *SecurityMiddleware {
	if conf.Config == nil {
		conf.Config = &SecurityConfig{
			MaxLoginAttempts: DefaultMaxLoginAttempts,
			LockoutPeriod:    DefaultLockoutPeriod,
			HideVersion:      true,
		}
	}

	if conf.Config.MaxLoginAttempts == 0 {
		conf.Config.MaxLoginAttempts = DefaultMaxLoginAttempts
	}
	if conf.Config.LockoutPeriod == 0 {
		conf.Config.LockoutPeriod = DefaultLockoutPeriod
	}

	securityHeaders := map[string]string{
		"X-Content-Type-Options":  "nosniff",
		"X-Frame-Options":         "DENY",
		"X-XSS-Protection":        "1; mode=block",
		"Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; frame-ancestors 'none';",
		"Referrer-Policy":         "strict-origin-when-cross-origin",
	}

	scannerPatterns := []string{
		"nikto", "sqlmap", "nmap", "masscan", "zap", "burp",
		"dirbuster", "gobuster", "wpscan", "nuclei", "acunetix",
		"nessus", "openvas", "w3af", "arachni", "skipfish",
	}

	return &SecurityMiddleware{
		logger:          conf.Logger.With(slogutil.KeyPrefix, "security_mw"),
		config:          conf.Config,
		rateLimiter:     newAuthRateLimiter(conf.Config.LockoutPeriod, uint(conf.Config.MaxLoginAttempts)),
		auditLogger:     conf.AuditLogger,
		staticPaths:     conf.StaticPaths,
		securityHeaders: securityHeaders,
		scannerPatterns: scannerPatterns,
	}
}

func (sm *SecurityMiddleware) Wrap(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		sm.addSecurityHeaders(w)

		w.Header().Del("Server")
		w.Header().Del("X-Powered-By")

		if sm.isScanner(r) {
			sm.logger.InfoContext(ctx, "blocked scanner request", "ip", r.RemoteAddr, "user_agent", r.UserAgent())
			http.Error(w, "Not Found", http.StatusNotFound)
			return
		}

		if sm.config.CustomPath != "" && !sm.isPublicPath(r.URL.Path) {
			if !sm.isValidCustomPath(r.URL.Path) {
				http.Error(w, "Not Found", http.StatusNotFound)
				return
			}
		}

		h.ServeHTTP(w, r)
	})
}

func (sm *SecurityMiddleware) addSecurityHeaders(w http.ResponseWriter) {
	for key, value := range sm.securityHeaders {
		w.Header().Set(key, value)
	}
}

func (sm *SecurityMiddleware) isScanner(r *http.Request) bool {
	userAgent := strings.ToLower(r.UserAgent())
	for _, pattern := range sm.scannerPatterns {
		if strings.Contains(userAgent, pattern) {
			return true
		}
	}
	return false
}

func (sm *SecurityMiddleware) isPublicPath(p string) bool {
	publicPaths := []string{
		"/control/login",
		"/control/logout",
		"/control/install/get_addresses",
		"/control/install/check_config",
		"/control/install/configure",
		"/dns-query",
	}

	isAsset, _ := path.Match("/assets/*", p)
	isLogin, _ := path.Match("/login.*", p)

	if isAsset || isLogin {
		return true
	}

	if strings.HasPrefix(p, "/dns-query/") {
		return true
	}

	return slices.Contains(publicPaths, p)
}

func (sm *SecurityMiddleware) isValidCustomPath(p string) bool {
	customLogin := "/" + sm.config.CustomPath
	customLoginHtml := "/" + sm.config.CustomPath + ".html"

	return p == customLogin ||
		p == customLoginHtml ||
		strings.HasPrefix(p, "/assets/") ||
		strings.HasPrefix(p, "/"+sm.config.CustomPath+"/")
}

func (sm *SecurityMiddleware) CheckLoginLockout(ip string) (locked bool, remaining time.Duration) {
	remaining = sm.rateLimiter.check(ip)
	return remaining > 0, remaining
}

func (sm *SecurityMiddleware) RecordLoginFailure(ctx context.Context, ip, username, userAgent string) {
	sm.rateLimiter.inc(ip)

	sm.logger.InfoContext(ctx, "login failure recorded",
		"ip", ip,
		"username", username,
	)

	if sm.auditLogger != nil {
		sm.auditLogger.Log(ctx, &auditlog.AuditEvent{
			EventType: auditlog.EventLoginFailure,
			Severity:  auditlog.SeverityWarning,
			Username:  username,
			IPAddress: ip,
			UserAgent: userAgent,
		})
	}

	if locked, _ := sm.CheckLoginLockout(ip); locked {
		sm.logger.WarnContext(ctx, "account locked due to failed attempts", "ip", ip)

		if sm.auditLogger != nil {
			sm.auditLogger.Log(ctx, &auditlog.AuditEvent{
				EventType: auditlog.EventLoginLockout,
				Severity:  auditlog.SeverityCritical,
				IPAddress: ip,
				Details: map[string]interface{}{
					"username": username,
				},
			})
		}
	}
}

func (sm *SecurityMiddleware) RecordLoginSuccess(ctx context.Context, ip, username, userAgent string) {
	sm.rateLimiter.remove(ip)

	sm.logger.InfoContext(ctx, "login success", "ip", ip, "username", username)

	if sm.auditLogger != nil {
		sm.auditLogger.Log(ctx, &auditlog.AuditEvent{
			EventType: auditlog.EventLoginSuccess,
			Severity:  auditlog.SeverityInfo,
			Username:  username,
			IPAddress: ip,
			UserAgent: userAgent,
		})
	}
}

func (sm *SecurityMiddleware) SetCustomPath(path string) {
	sm.config.CustomPath = path
}

func (sm *SecurityMiddleware) GetCustomPath() string {
	return sm.config.CustomPath
}

func (sm *SecurityMiddleware) GetRateLimiter() loginRateLimiter {
	return sm.rateLimiter
}

func GenerateRandomPath() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating random bytes: %w", err)
	}
	return hex.EncodeToString(b), nil
}

func (sm *SecurityMiddleware) LogSecurityEvent(ctx context.Context, eventType auditlog.EventType, severity auditlog.Severity, username, ip, userAgent string, details map[string]interface{}) {
	if sm.auditLogger == nil {
		return
	}

	sm.auditLogger.Log(ctx, &auditlog.AuditEvent{
		EventType: eventType,
		Severity:  severity,
		Username:  username,
		IPAddress: ip,
		UserAgent: userAgent,
		Details:   details,
	})
}

func (sm *SecurityMiddleware) CheckRateLimit(ip string) (blocked bool, retryAfter time.Duration) {
	retryAfter = sm.rateLimiter.check(ip)
	return retryAfter > 0, retryAfter
}

func FormatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%d秒", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%d分钟", int(d.Minutes()))
	}
	return fmt.Sprintf("%d小时%d分钟", int(d.Hours()), int(d.Minutes())%60)
}
