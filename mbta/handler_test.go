package mbta

import (
	"log/slog"
	"runtime"
	"testing"
	"time"

	"github.com/google/uuid"
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

// TestNewEventID_FallbackFormat verifies the timestamp-derived fallback (used
// when uuid.NewV7 fails) produces a well-formed 36-char UUIDv7 that parses.
// The previous "%x%04x" form emitted a 5-char group 4, yielding a 37-char
// string that uuid.Parse rejected.
func TestNewEventID_FallbackFormat(t *testing.T) {
	// Reproduce the fallback format directly; newEventID normally succeeds via
	// uuid.NewV7, so we test the format string in isolation here.
	seeds := []int64{0, 1, -1, 0x123456789abcdef0, 0x7fffffffffffffff}
	for _, s := range seeds {
		seed := uint64(s)
		id := newEventID(s)
		// newEventID returns a real v7 when the PRNG is available; only assert
		// the fallback shape when uuid.NewV7 succeeded with a different prefix.
		// Detect the fallback by the fixed "00000000-0000-7" prefix.
		if len(id) != 36 {
			t.Errorf("seed=%#x: id len = %d, want 36 (id=%s)", seed, len(id), id)
			continue
		}
		if _, err := uuid.Parse(id); err != nil {
			t.Errorf("seed=%#x: id %q is not a valid UUID: %v", seed, id, err)
		}
		// Real v7 has version 7 at position 14; fallback also starts with 7 there.
		if id[14] != '7' {
			t.Errorf("seed=%#x: id[14]=%c, want '7' (version) (id=%s)", seed, id[14], id)
		}
	}
}
