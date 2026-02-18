package auditlog

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAuditLoggerLog(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "audit-test")
	if err != nil {
		t.Fatalf("creating temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	dbPath := filepath.Join(tmpDir, "audit.db")
	logFile := filepath.Join(tmpDir, "audit.log")

	al, err := NewAuditLogger(&AuditConfig{
		DBPath:  dbPath,
		LogFile: logFile,
		Enabled: true,
	})
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}
	defer al.Close()

	ctx := context.Background()

	event := &AuditEvent{
		EventType: EventLoginSuccess,
		Severity:  SeverityInfo,
		Username:  "admin",
		IPAddress: "192.168.1.100",
		UserAgent: "Mozilla/5.0",
	}

	if err := al.Log(ctx, event); err != nil {
		t.Fatalf("Log: %v", err)
	}

	if event.ID == "" {
		t.Error("event ID should be set")
	}

	if event.Timestamp.IsZero() {
		t.Error("event timestamp should be set")
	}

	if _, err := os.Stat(logFile); os.IsNotExist(err) {
		t.Error("log file was not created")
	}
}

func TestAuditLoggerQuery(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "audit-test")
	if err != nil {
		t.Fatalf("creating temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	dbPath := filepath.Join(tmpDir, "audit.db")

	al, err := NewAuditLogger(&AuditConfig{
		DBPath:  dbPath,
		Enabled: true,
	})
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}
	defer al.Close()

	ctx := context.Background()

	events := []*AuditEvent{
		{EventType: EventLoginSuccess, Severity: SeverityInfo, Username: "admin", IPAddress: "192.168.1.100"},
		{EventType: EventLoginFailure, Severity: SeverityWarning, Username: "admin", IPAddress: "192.168.1.101"},
		{EventType: EventLoginSuccess, Severity: SeverityInfo, Username: "admin", IPAddress: "192.168.1.100"},
	}

	for _, e := range events {
		if err := al.Log(ctx, e); err != nil {
			t.Fatalf("Log: %v", err)
		}
		time.Sleep(time.Millisecond)
	}

	tests := []struct {
		name      string
		filter    *AuditFilter
		wantCount int
	}{
		{
			name:      "all events",
			filter:    nil,
			wantCount: 3,
		},
		{
			name:      "by event type",
			filter:    &AuditFilter{EventType: EventLoginSuccess},
			wantCount: 2,
		},
		{
			name:      "by severity",
			filter:    &AuditFilter{Severity: SeverityWarning},
			wantCount: 1,
		},
		{
			name:      "by IP",
			filter:    &AuditFilter{IPAddress: "192.168.1.100"},
			wantCount: 2,
		},
		{
			name:      "with limit",
			filter:    &AuditFilter{Limit: 1},
			wantCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results, err := al.Query(ctx, tt.filter)
			if err != nil {
				t.Fatalf("Query: %v", err)
			}

			if len(results) != tt.wantCount {
				t.Errorf("got %d events, want %d", len(results), tt.wantCount)
			}
		})
	}
}

func TestAuditLoggerRotate(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "audit-test")
	if err != nil {
		t.Fatalf("creating temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	dbPath := filepath.Join(tmpDir, "audit.db")

	al, err := NewAuditLogger(&AuditConfig{
		DBPath:  dbPath,
		Enabled: true,
	})
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}
	defer al.Close()

	ctx := context.Background()

	oldEvent := &AuditEvent{
		EventType: EventLoginSuccess,
		Username:  "admin",
		IPAddress: "192.168.1.100",
	}
	oldEvent.Timestamp = time.Now().Add(-48 * time.Hour)

	if err := al.Log(ctx, oldEvent); err != nil {
		t.Fatalf("Log old event: %v", err)
	}

	newEvent := &AuditEvent{
		EventType: EventLoginSuccess,
		Username:  "admin",
		IPAddress: "192.168.1.101",
	}

	if err := al.Log(ctx, newEvent); err != nil {
		t.Fatalf("Log new event: %v", err)
	}

	if err := al.Rotate(ctx, 24*time.Hour); err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	count, err := al.Count(ctx, nil)
	if err != nil {
		t.Fatalf("Count: %v", err)
	}

	if count != 1 {
		t.Errorf("after rotation, count = %d, want 1", count)
	}
}

func TestAuditLoggerDisabled(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "audit-test")
	if err != nil {
		t.Fatalf("creating temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	dbPath := filepath.Join(tmpDir, "audit.db")

	al, err := NewAuditLogger(&AuditConfig{
		DBPath:  dbPath,
		Enabled: false,
	})
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}
	defer al.Close()

	ctx := context.Background()

	event := &AuditEvent{
		EventType: EventLoginSuccess,
		Username:  "admin",
		IPAddress: "192.168.1.100",
	}

	if err := al.Log(ctx, event); err != nil {
		t.Fatalf("Log: %v", err)
	}

	count, err := al.Count(ctx, nil)
	if err != nil {
		t.Fatalf("Count: %v", err)
	}

	if count != 0 {
		t.Errorf("disabled logger should not store events, got %d", count)
	}
}

func TestAuditLoggerSetEnabled(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "audit-test")
	if err != nil {
		t.Fatalf("creating temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	dbPath := filepath.Join(tmpDir, "audit.db")

	al, err := NewAuditLogger(&AuditConfig{
		DBPath:  dbPath,
		Enabled: true,
	})
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}
	defer al.Close()

	if !al.IsEnabled() {
		t.Error("logger should be enabled")
	}

	al.SetEnabled(false)

	if al.IsEnabled() {
		t.Error("logger should be disabled")
	}
}

func TestLogSimple(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "audit-test")
	if err != nil {
		t.Fatalf("creating temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	dbPath := filepath.Join(tmpDir, "audit.db")

	al, err := NewAuditLogger(&AuditConfig{
		DBPath:  dbPath,
		Enabled: true,
	})
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}
	defer al.Close()

	ctx := context.Background()

	if err := al.LogSimple(ctx, EventLoginFailure, SeverityWarning, "admin", "192.168.1.100", "test-agent"); err != nil {
		t.Fatalf("LogSimple: %v", err)
	}

	events, err := al.Query(ctx, &AuditFilter{EventType: EventLoginFailure})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}

	if len(events) != 1 {
		t.Fatalf("got %d events, want 1", len(events))
	}

	if events[0].Username != "admin" {
		t.Errorf("username = %q, want %q", events[0].Username, "admin")
	}
}
