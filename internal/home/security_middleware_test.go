package home

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSecurityMiddleware_AddSecurityHeaders(t *testing.T) {
	sm := NewSecurityMiddleware(&SecurityMiddlewareConfig{
		Logger: slog.Default(),
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	sm.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rec, req)

	headers := rec.Header()

	if headers.Get("X-Content-Type-Options") != "nosniff" {
		t.Error("X-Content-Type-Options header not set")
	}

	if headers.Get("X-Frame-Options") != "DENY" {
		t.Error("X-Frame-Options header not set")
	}

	if headers.Get("Content-Security-Policy") == "" {
		t.Error("Content-Security-Policy header not set")
	}

	if headers.Get("Server") != "" {
		t.Error("Server header should be removed")
	}
}

func TestSecurityMiddleware_ScannerDetection(t *testing.T) {
	sm := NewSecurityMiddleware(&SecurityMiddlewareConfig{
		Logger: slog.Default(),
	})

	tests := []struct {
		name      string
		userAgent string
		wantBlock bool
	}{
		{"normal browser", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)", false},
		{"nikto scanner", "Nikto/2.1.6", true},
		{"sqlmap scanner", "sqlmap/1.4.7", true},
		{"nmap scanner", "Nmap Scripting Engine", true},
		{"burp suite", "Burp Suite Professional", true},
		{"mixed case scanner", "NIKTO/2.1.6", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set("User-Agent", tt.userAgent)
			rec := httptest.NewRecorder()

			called := false
			sm.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				w.WriteHeader(http.StatusOK)
			})).ServeHTTP(rec, req)

			if tt.wantBlock {
				if called {
					t.Error("handler should not be called for scanner")
				}
				if rec.Code != http.StatusNotFound {
					t.Errorf("status = %d, want %d", rec.Code, http.StatusNotFound)
				}
			} else {
				if !called {
					t.Error("handler should be called for normal request")
				}
			}
		})
	}
}

func TestSecurityMiddleware_CustomPath(t *testing.T) {
	sm := NewSecurityMiddleware(&SecurityMiddlewareConfig{
		Logger: slog.Default(),
		Config: &SecurityConfig{
			CustomPath: "secret-admin-path",
		},
	})

	tests := []struct {
		path      string
		wantAllow bool
	}{
		{"/secret-admin-path", true},
		{"/secret-admin-path.html", true},
		{"/login.html", true},
		{"/", false},
		{"/assets/main.js", true},
		{"/control/login", true},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			rec := httptest.NewRecorder()

			called := false
			sm.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				w.WriteHeader(http.StatusOK)
			})).ServeHTTP(rec, req)

			if tt.wantAllow && !called {
				t.Errorf("path %s should be allowed", tt.path)
			}
			if !tt.wantAllow && called {
				t.Errorf("path %s should be blocked", tt.path)
			}
		})
	}
}

func TestSecurityMiddleware_LoginLockout(t *testing.T) {
	sm := NewSecurityMiddleware(&SecurityMiddlewareConfig{
		Logger: slog.Default(),
		Config: &SecurityConfig{
			MaxLoginAttempts: 3,
			LockoutPeriod:    1 * time.Minute,
		},
	})

	ctx := context.Background()
	ip := "192.168.1.100"

	for i := 0; i < 3; i++ {
		sm.RecordLoginFailure(ctx, ip, "admin", "test-agent")
	}

	locked, remaining := sm.CheckLoginLockout(ip)
	if !locked {
		t.Error("IP should be locked after 3 failures")
	}

	if remaining <= 0 {
		t.Error("remaining time should be positive")
	}

	sm.RecordLoginSuccess(ctx, ip, "admin", "test-agent")

	locked, _ = sm.CheckLoginLockout(ip)
	if locked {
		t.Error("IP should not be locked after successful login")
	}
}

func TestSecurityMiddleware_RateLimitCheck(t *testing.T) {
	sm := NewSecurityMiddleware(&SecurityMiddlewareConfig{
		Logger: slog.Default(),
		Config: &SecurityConfig{
			MaxLoginAttempts: 2,
			LockoutPeriod:    1 * time.Minute,
		},
	})

	ip := "192.168.1.100"

	blocked, _ := sm.CheckRateLimit(ip)
	if blocked {
		t.Error("IP should not be blocked initially")
	}

	sm.rateLimiter.inc(ip)
	sm.rateLimiter.inc(ip)

	blocked, retryAfter := sm.CheckRateLimit(ip)
	if !blocked {
		t.Error("IP should be blocked after max attempts")
	}
	if retryAfter <= 0 {
		t.Error("retryAfter should be positive when blocked")
	}
}

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		duration time.Duration
		want     string
	}{
		{30 * time.Second, "30秒"},
		{90 * time.Second, "1分钟"},
		{150 * time.Second, "2分钟"},
		{90 * time.Minute, "1小时30分钟"},
	}

	for _, tt := range tests {
		got := FormatDuration(tt.duration)
		if !strings.Contains(got, strings.TrimSuffix(tt.want, "分钟")[:1]) {
			t.Errorf("FormatDuration(%v) = %s, want %s", tt.duration, got, tt.want)
		}
	}
}

func TestGenerateRandomPath(t *testing.T) {
	path1, err := GenerateRandomPath()
	if err != nil {
		t.Fatalf("GenerateRandomPath() error = %v", err)
	}
	path2, err := GenerateRandomPath()
	if err != nil {
		t.Fatalf("GenerateRandomPath() error = %v", err)
	}

	if len(path1) != DefaultCustomPathLength {
		t.Errorf("path length = %d, want %d", len(path1), DefaultCustomPathLength)
	}

	if path1 == path2 {
		t.Error("consecutive paths should differ")
	}
}
