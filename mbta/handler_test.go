package mbta

import (
	"log/slog"
	"runtime"
	"testing"
	"time"

	"github.com/iuboy/mebsuta"
)

func TestConfigValidate_RequiredFields(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{
			name:    "empty config fails",
			cfg:     Config{},
			wantErr: true,
		},
		{
			name:    "missing server fails",
			cfg:     Config{AgentID: "agent-1"},
			wantErr: true,
		},
		{
			name:    "missing agent ID fails",
			cfg:     Config{Server: "localhost:7400"},
			wantErr: true,
		},
		{
			name:    "valid config passes",
			cfg:     Config{Server: "localhost:7400", AgentID: "agent-1"},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestConfigValidate_Defaults(t *testing.T) {
	cfg, err := Config{Server: "localhost:7400", AgentID: "agent-1"}.Validate()
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}

	if cfg.Level != slog.LevelInfo {
		t.Errorf("Level = %v, want LevelInfo", cfg.Level)
	}
	if cfg.BufferSize != defaultBufferSize {
		t.Errorf("BufferSize = %d, want %d", cfg.BufferSize, defaultBufferSize)
	}
	if cfg.FlushPeriod != defaultFlushPeriod {
		t.Errorf("FlushPeriod = %v, want %v", cfg.FlushPeriod, defaultFlushPeriod)
	}
	if cfg.BatchSize != defaultBatchSize {
		t.Errorf("BatchSize = %d, want %d", cfg.BatchSize, defaultBatchSize)
	}
	if cfg.MaxRetries != defaultMaxRetries {
		t.Errorf("MaxRetries = %d, want %d", cfg.MaxRetries, defaultMaxRetries)
	}
	if cfg.Tag != "mebsuta" {
		t.Errorf("Tag = %q, want %q", cfg.Tag, "mebsuta")
	}
	if cfg.Source == "" {
		t.Error("Source should default to hostname")
	}
}

func newRecord(level slog.Level, msg string) slog.Record {
	var pcs [1]uintptr
	runtime.Callers(2, pcs[:])
	return slog.NewRecord(time.Now(), level, msg, pcs[0])
}

func TestRecordToSignal(t *testing.T) {
	r := newRecord(slog.LevelInfo, "hello world")
	r.AddAttrs(slog.String("key", "value"), slog.Int("count", 42))

	rec := recordToSignal(r, "testhost")

	if rec.SignalType != "log" {
		t.Errorf("SignalType = %q, want %q", rec.SignalType, "log")
	}
	if rec.Body != "hello world" {
		t.Errorf("Body = %q, want %q", rec.Body, "hello world")
	}
	if rec.SeverityText != "INFO" {
		t.Errorf("SeverityText = %q, want %q", rec.SeverityText, "INFO")
	}
	if rec.EventID == "" {
		t.Error("EventID should not be empty")
	}
	if rec.TimeUnixMs == 0 {
		t.Error("TimeUnixMs should not be zero")
	}

	attrs := rec.Attributes
	if attrs["key"] != "value" {
		t.Errorf("Attributes[\"key\"] = %v, want %v", attrs["key"], "value")
	}
	if attrs["count"] != int64(42) {
		t.Errorf("Attributes[\"count\"] = %v, want 42", attrs["count"])
	}
}

func TestRecordToSignal_AuditLevel(t *testing.T) {
	r := newRecord(mebsuta.LevelAudit, "audit event")
	rec := recordToSignal(r, "testhost")

	if rec.SeverityText != "AUDIT" {
		t.Errorf("SeverityText = %q, want %q", rec.SeverityText, "AUDIT")
	}
}

func TestRecordToSignal_GroupAttrs(t *testing.T) {
	r := newRecord(slog.LevelInfo, "grouped")
	r.AddAttrs(slog.Group("request", slog.String("method", "GET"), slog.Int("status", 200)))

	rec := recordToSignal(r, "testhost")
	attrs := rec.Attributes

	req, ok := attrs["request"].(map[string]any)
	if !ok {
		t.Fatalf("Attributes[\"request\"] type = %T, want map[string]any", attrs["request"])
	}
	if req["method"] != "GET" {
		t.Errorf("request.method = %v, want GET", req["method"])
	}
}
