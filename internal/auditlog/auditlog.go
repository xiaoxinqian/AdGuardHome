package auditlog

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/AdguardTeam/golibs/logutil/slogutil"
	bolt "go.etcd.io/bbolt"
)

const (
	BucketName   = "audit_events"
	MaxBatchSize = 100
)

type EventType string

const (
	EventLoginSuccess   EventType = "login_success"
	EventLoginFailure   EventType = "login_failure"
	EventLoginLockout   EventType = "login_lockout"
	EventLogout         EventType = "logout"
	EventTOTPEnable     EventType = "totp_enable"
	EventTOTPDisable    EventType = "totp_disable"
	EventTOTPFailure    EventType = "totp_failure"
	EventPasswordChange EventType = "password_change"
	EventNewDevice      EventType = "new_device"
	EventGeoAnomaly     EventType = "geo_anomaly"
	EventConfigChange   EventType = "config_change"
	EventSessionTimeout EventType = "session_timeout"
	EventSessionKicked  EventType = "session_kicked"
	EventSecurityAlert  EventType = "security_alert"
)

type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityWarning  Severity = "warning"
	SeverityCritical Severity = "critical"
)

type AuditEvent struct {
	ID        string                 `json:"id"`
	Timestamp time.Time              `json:"timestamp"`
	EventType EventType              `json:"event_type"`
	Severity  Severity               `json:"severity"`
	UserID    string                 `json:"user_id,omitempty"`
	Username  string                 `json:"username,omitempty"`
	IPAddress string                 `json:"ip_address"`
	UserAgent string                 `json:"user_agent,omitempty"`
	DeviceID  string                 `json:"device_id,omitempty"`
	Action    string                 `json:"action,omitempty"`
	Resource  string                 `json:"resource,omitempty"`
	Details   map[string]interface{} `json:"details,omitempty"`
	RiskScore int                    `json:"risk_score"`
}

type AuditFilter struct {
	EventType EventType
	Severity  Severity
	UserID    string
	IPAddress string
	StartTime *time.Time
	EndTime   *time.Time
	Limit     int
	Offset    int
}

type AuditLogger struct {
	mu       sync.RWMutex
	db       *bolt.DB
	logger   *slog.Logger
	file     *os.File
	filePath string
	enabled  bool
}

type AuditConfig struct {
	Logger  *slog.Logger
	DBPath  string
	LogFile string
	Enabled bool
	MaxAge  time.Duration
	MaxSize int64
}

func NewAuditLogger(conf *AuditConfig) (*AuditLogger, error) {
	al := &AuditLogger{
		enabled: conf.Enabled,
	}

	if conf.Logger != nil {
		al.logger = conf.Logger.With(slogutil.KeyPrefix, "audit")
	} else {
		al.logger = slog.Default().With(slogutil.KeyPrefix, "audit")
	}

	if conf.DBPath != "" {
		dir := filepath.Dir(conf.DBPath)
		if err := os.MkdirAll(dir, 0700); err != nil {
			return nil, fmt.Errorf("creating db directory: %w", err)
		}

		db, err := bolt.Open(conf.DBPath, 0600, nil)
		if err != nil {
			return nil, fmt.Errorf("opening db: %w", err)
		}

		err = db.Update(func(tx *bolt.Tx) error {
			_, err := tx.CreateBucketIfNotExists([]byte(BucketName))
			return err
		})
		if err != nil {
			db.Close()
			return nil, fmt.Errorf("creating bucket: %w", err)
		}

		al.db = db
	}

	if conf.LogFile != "" {
		dir := filepath.Dir(conf.LogFile)
		if err := os.MkdirAll(dir, 0700); err != nil {
			return nil, fmt.Errorf("creating log directory: %w", err)
		}

		f, err := os.OpenFile(conf.LogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			return nil, fmt.Errorf("opening log file: %w", err)
		}

		al.file = f
		al.filePath = conf.LogFile
	}

	return al, nil
}

func (al *AuditLogger) Log(ctx context.Context, event *AuditEvent) error {
	if !al.enabled {
		return nil
	}

	al.mu.Lock()
	defer al.mu.Unlock()

	if event.ID == "" {
		event.ID = generateEventID()
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}
	if event.Severity == "" {
		event.Severity = SeverityInfo
	}

	if al.file != nil {
		data, err := json.Marshal(event)
		if err != nil {
			al.logger.ErrorContext(ctx, "marshaling event", slogutil.KeyError, err)
		} else {
			if _, err := al.file.Write(append(data, '\n')); err != nil {
				al.logger.ErrorContext(ctx, "writing to log file", slogutil.KeyError, err)
			}
		}
	}

	if al.db != nil {
		err := al.db.Update(func(tx *bolt.Tx) error {
			b := tx.Bucket([]byte(BucketName))
			if b == nil {
				return fmt.Errorf("bucket not found")
			}

			key := []byte(event.ID)
			value, err := json.Marshal(event)
			if err != nil {
				return fmt.Errorf("marshaling event: %w", err)
			}

			return b.Put(key, value)
		})

		if err != nil {
			return fmt.Errorf("storing event: %w", err)
		}
	}

	al.logger.DebugContext(ctx, "audit event logged",
		"event_type", event.EventType,
		"severity", event.Severity,
		"ip", event.IPAddress,
		"user", event.Username,
	)

	return nil
}

func (al *AuditLogger) LogSimple(ctx context.Context, eventType EventType, severity Severity, username, ip, userAgent string) error {
	return al.Log(ctx, &AuditEvent{
		EventType: eventType,
		Severity:  severity,
		Username:  username,
		IPAddress: ip,
		UserAgent: userAgent,
	})
}

func (al *AuditLogger) Query(ctx context.Context, filter *AuditFilter) ([]*AuditEvent, error) {
	if al.db == nil {
		return nil, fmt.Errorf("database not configured")
	}

	var events []*AuditEvent
	logger := al.logger

	err := al.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(BucketName))
		if b == nil {
			return nil
		}

		c := b.Cursor()
		count := 0
		skip := 0

		if filter != nil && filter.Offset > 0 {
			skip = filter.Offset
		}

		limit := 100
		if filter != nil && filter.Limit > 0 {
			limit = filter.Limit
		}

		for k, v := c.Last(); k != nil; k, v = c.Prev() {
			var event AuditEvent
			if err := json.Unmarshal(v, &event); err != nil {
				if logger != nil {
					logger.ErrorContext(ctx, "unmarshaling event", slogutil.KeyError, err)
				}
				continue
			}

			if !al.matchFilter(&event, filter) {
				continue
			}

			if skip > 0 {
				skip--
				continue
			}

			events = append(events, &event)
			count++

			if count >= limit {
				break
			}
		}

		return nil
	})

	return events, err
}

func (al *AuditLogger) matchFilter(event *AuditEvent, filter *AuditFilter) bool {
	if filter == nil {
		return true
	}

	if filter.EventType != "" && event.EventType != filter.EventType {
		return false
	}

	if filter.Severity != "" && event.Severity != filter.Severity {
		return false
	}

	if filter.UserID != "" && event.UserID != filter.UserID {
		return false
	}

	if filter.IPAddress != "" && event.IPAddress != filter.IPAddress {
		return false
	}

	if filter.StartTime != nil && event.Timestamp.Before(*filter.StartTime) {
		return false
	}

	if filter.EndTime != nil && event.Timestamp.After(*filter.EndTime) {
		return false
	}

	return true
}

func (al *AuditLogger) Rotate(ctx context.Context, maxAge time.Duration) error {
	if al.db == nil {
		return nil
	}

	cutoff := time.Now().Add(-maxAge)

	return al.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(BucketName))
		if b == nil {
			return nil
		}

		var keysToDelete [][]byte

		c := b.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var event AuditEvent
			if err := json.Unmarshal(v, &event); err != nil {
				continue
			}

			if event.Timestamp.Before(cutoff) {
				keysToDelete = append(keysToDelete, k)
			}
		}

		for _, key := range keysToDelete {
			if err := b.Delete(key); err != nil {
				al.logger.ErrorContext(ctx, "deleting old event", slogutil.KeyError, err)
			}
		}

		al.logger.InfoContext(ctx, "rotated audit log", "deleted", len(keysToDelete))

		return nil
	})
}

func (al *AuditLogger) Count(ctx context.Context, filter *AuditFilter) (int, error) {
	if al.db == nil {
		return 0, fmt.Errorf("database not configured")
	}

	count := 0

	err := al.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(BucketName))
		if b == nil {
			return nil
		}

		c := b.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var event AuditEvent
			if err := json.Unmarshal(v, &event); err != nil {
				return nil
			}

			if al.matchFilter(&event, filter) {
				count++
			}
		}

		return nil
	})

	return count, err
}

func (al *AuditLogger) Close() error {
	al.mu.Lock()
	defer al.mu.Unlock()

	var errs []error

	if al.db != nil {
		if err := al.db.Close(); err != nil {
			errs = append(errs, fmt.Errorf("closing db: %w", err))
		}
	}

	if al.file != nil {
		if err := al.file.Close(); err != nil {
			errs = append(errs, fmt.Errorf("closing log file: %w", err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("errors closing audit logger: %v", errs)
	}

	return nil
}

func (al *AuditLogger) SetEnabled(enabled bool) {
	al.mu.Lock()
	defer al.mu.Unlock()
	al.enabled = enabled
}

func (al *AuditLogger) IsEnabled() bool {
	al.mu.RLock()
	defer al.mu.RUnlock()
	return al.enabled
}

func generateEventID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}
