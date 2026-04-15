package mebsuta

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/iuboy/mebsuta/config"
)

// =============================================================================
// levelHandler 测试
// =============================================================================

func TestLevelHandler_Enabled(t *testing.T) {
	h := levelHandler{level: slog.LevelWarn}

	tests := []struct {
		level    slog.Level
		expected bool
	}{
		{slog.LevelDebug, false},
		{slog.LevelInfo, false},
		{slog.LevelWarn, true},
		{slog.LevelError, true},
	}

	for _, tt := range tests {
		if got := h.Enabled(context.Background(), tt.level); got != tt.expected {
			t.Errorf("Enabled(%v) = %v, want %v", tt.level, got, tt.expected)
		}
	}
}

// =============================================================================
// StdoutHandler 测试
// =============================================================================

func newTestHandler(level slog.Level, format EncodingType) (*StdoutHandler, *bytes.Buffer) {
	var buf bytes.Buffer
	h := newStdoutHandlerWithWriter(&buf, level, format)
	return h, &buf
}

func TestStdoutHandler_JSONFormat(t *testing.T) {
	h, buf := newTestHandler(slog.LevelInfo, JSON)
	logger := slog.New(h)

	logger.Info("hello", "key", "value")

	var result map[string]any
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON output: %v, got: %s", err, buf.String())
	}
	if result["msg"] != "hello" {
		t.Errorf("msg = %v, want hello", result["msg"])
	}
	if result["key"] != "value" {
		t.Errorf("key = %v, want value", result["key"])
	}
	if result["level"] != "INFO" {
		t.Errorf("level = %v, want INFO", result["level"])
	}
}

func TestStdoutHandler_TextFormat(t *testing.T) {
	h, buf := newTestHandler(slog.LevelInfo, Console)
	logger := slog.New(h)

	logger.Info("hello", "key", "value")

	output := buf.String()
	if !strings.Contains(output, "hello") {
		t.Errorf("output should contain 'hello', got: %s", output)
	}
	if !strings.Contains(output, "key=value") {
		t.Errorf("output should contain 'key=value', got: %s", output)
	}
}

func TestStdoutHandler_LevelFilter(t *testing.T) {
	h, buf := newTestHandler(slog.LevelWarn, JSON)
	logger := slog.New(h)

	logger.Info("should be filtered")
	if buf.Len() > 0 {
		t.Errorf("Info should be filtered at Warn level, got output: %s", buf.String())
	}

	logger.Warn("should pass")
	if buf.Len() == 0 {
		t.Error("Warn should pass at Warn level")
	}
}

func TestStdoutHandler_WithAttrs(t *testing.T) {
	h, buf := newTestHandler(slog.LevelInfo, JSON)
	child := h.WithAttrs([]slog.Attr{slog.String("preset", "value")})
	logger := slog.New(child)

	logger.Info("test")

	var result map[string]any
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if result["preset"] != "value" {
		t.Errorf("preset = %v, want value", result["preset"])
	}
}

func TestStdoutHandler_WithGroup(t *testing.T) {
	h, buf := newTestHandler(slog.LevelInfo, JSON)
	child := h.WithGroup("request")
	logger := slog.New(child)

	logger.Info("test", "id", "123")

	var result map[string]any
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	req, ok := result["request"].(map[string]any)
	if !ok {
		t.Fatalf("request should be a group, got: %v", result["request"])
	}
	if req["id"] != "123" {
		t.Errorf("request.id = %v, want 123", req["id"])
	}
}

func TestStdoutHandler_ConcurrentWrites(t *testing.T) {
	h, buf := newTestHandler(slog.LevelInfo, JSON)
	logger := slog.New(h)

	const goroutines = 100
	done := make(chan struct{})

	for i := 0; i < goroutines; i++ {
		go func(n int) {
			logger.Info("concurrent", "n", n)
			done <- struct{}{}
		}(i)
	}

	for i := 0; i < goroutines; i++ {
		<-done
	}

	lines := strings.Count(buf.String(), "\n")
	if lines != goroutines {
		t.Errorf("expected %d lines, got %d", goroutines, lines)
	}
}

func TestStdoutHandler_Close(t *testing.T) {
	h, _ := newTestHandler(slog.LevelInfo, JSON)
	// Close should be nop for stdout, not error
	if err := h.Close(); err != nil {
		t.Errorf("Close() returned error: %v", err)
	}
}

// =============================================================================
// New() 和 HandlerOption 测试
// =============================================================================

func TestNew_SingleHandler(t *testing.T) {
	handler := NewStdoutHandler(slog.LevelInfo, JSON)
	logger, err := New(WithHandler(handler))
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	if logger == nil {
		t.Fatal("New() returned nil logger")
	}
}

func TestNew_MultipleHandlers(t *testing.T) {
	h1 := NewStdoutHandler(slog.LevelInfo, JSON)
	h2 := NewStdoutHandler(slog.LevelWarn, JSON)
	logger, err := New(WithHandler(h1), WithHandler(h2))
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	if logger == nil {
		t.Fatal("New() returned nil logger")
	}
}

func TestNew_NilHandler(t *testing.T) {
	_, err := New(WithHandler(nil))
	if err == nil {
		t.Fatal("expected error for nil handler")
	}
}

func TestNew_NoHandlers(t *testing.T) {
	_, err := New()
	if err == nil {
		t.Fatal("expected error for no handlers")
	}
}

// =============================================================================
// CloseAll 测试
// =============================================================================

func TestCloseAll_NilHandler(t *testing.T) {
	if err := CloseAll(nil); err != nil {
		t.Errorf("CloseAll(nil) returned error: %v", err)
	}
}

func TestCloseAll_StdoutHandler(t *testing.T) {
	h := NewStdoutHandler(slog.LevelInfo, JSON)
	// StdoutHandler.Close is nop, should succeed
	if err := CloseAll(h); err != nil {
		t.Errorf("CloseAll() error: %v", err)
	}
}

func TestCloseAll_MultiHandler(t *testing.T) {
	h1 := NewStdoutHandler(slog.LevelInfo, JSON)
	h2 := NewStdoutHandler(slog.LevelWarn, JSON)
	multi := safeMultiHandler(slog.NewMultiHandler(h1, h2), []slog.Handler{h1, h2})

	// safeMulti 实现了 io.Closer，应递归关闭子 handler
	if err := CloseAll(multi); err != nil {
		t.Errorf("CloseAll(multi) error: %v", err)
	}
}

func TestCloseAll_DecoratorChain(t *testing.T) {
	inner := NewStdoutHandler(slog.LevelInfo, JSON)
	sampling := WithSampling(inner, config.SamplingConfig{Enabled: true, Initial: 10, Thereafter: 1, Window: time.Second})

	// CloseAll 应通过 unwrapHandler 递归关闭 inner
	if err := CloseAll(sampling); err != nil {
		t.Errorf("CloseAll(sampling) error: %v", err)
	}
}

// =============================================================================
// RecordToLogEntry 测试
// =============================================================================

func TestRecordToLogEntry(t *testing.T) {
	now := time.Now()
	r := slog.NewRecord(now, slog.LevelInfo, "test message", 0)
	r.AddAttrs(slog.String("key", "value"))

	entry := RecordToLogEntry(r)

	if !entry.Time.Equal(now) {
		t.Errorf("Time = %v, want %v", entry.Time, now)
	}
	if entry.Message != "test message" {
		t.Errorf("Message = %v, want 'test message'", entry.Message)
	}
	if entry.Level != slog.LevelInfo {
		t.Errorf("Level = %v, want Info", entry.Level)
	}
	if len(entry.Attrs) != 1 {
		t.Fatalf("len(Attrs) = %d, want 1", len(entry.Attrs))
	}
	if entry.Attrs[0].Key != "key" {
		t.Errorf("Attr key = %v, want 'key'", entry.Attrs[0].Key)
	}
}
