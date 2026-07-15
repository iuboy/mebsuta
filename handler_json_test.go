package mebsuta

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"math"
	"sync"
	"testing"
	"time"
)

// newJSONHandler creates a contractJSONHandler writing to a buffer for testing.
func newJSONHandler(t *testing.T) (*contractJSONHandler, *bytes.Buffer) {
	t.Helper()
	var buf bytes.Buffer
	h := newContractJSONHandler(&buf, nil).(*contractJSONHandler)
	return h, &buf
}

func parseJSONLine(t *testing.T, data []byte) map[string]any {
	t.Helper()
	var result map[string]any
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("invalid JSON: %v, got: %s", err, string(data))
	}
	return result
}

// =============================================================================
// 必选字段
// =============================================================================

func TestContractJSONHandler_RequiredFields(t *testing.T) {
	h, buf := newJSONHandler(t)

	r := slog.NewRecord(time.Date(2026, 5, 24, 12, 0, 0, 0, time.UTC), slog.LevelInfo, "test message", 0)
	_ = h.Handle(context.Background(), r)

	result := parseJSONLine(t, buf.Bytes())

	for _, key := range []string{"time", "level", "message", "attributes"} {
		if _, ok := result[key]; !ok {
			t.Errorf("missing required key: %s", key)
		}
	}
	if result["message"] != "test message" {
		t.Errorf("message = %v, want 'test message'", result["message"])
	}
	if result["level"] != "INFO" {
		t.Errorf("level = %v, want INFO", result["level"])
	}
}

// =============================================================================
// Level 字符串
// =============================================================================

func TestContractJSONHandler_LevelStrings(t *testing.T) {
	tests := []struct {
		level slog.Level
		want  string
	}{
		{slog.LevelDebug, "DEBUG"},
		{slog.LevelInfo, "INFO"},
		{slog.LevelWarn, "WARN"},
		{slog.LevelError, "ERROR"},
		{slog.LevelError + 4, "AUDIT"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			h, buf := newJSONHandler(t)
			r := slog.NewRecord(time.Now(), tt.level, "test", 0)
			_ = h.Handle(context.Background(), r)
			result := parseJSONLine(t, buf.Bytes())
			if result["level"] != tt.want {
				t.Errorf("level = %v, want %s", result["level"], tt.want)
			}
		})
	}
}

// =============================================================================
// Attributes
// =============================================================================

func TestContractJSONHandler_UserAttributes(t *testing.T) {
	h, buf := newJSONHandler(t)

	r := slog.NewRecord(time.Now(), slog.LevelInfo, "attrs", 0)
	r.AddAttrs(
		slog.String("str", "hello"),
		slog.Int("num", 42),
		slog.Bool("flag", true),
	)
	_ = h.Handle(context.Background(), r)

	result := parseJSONLine(t, buf.Bytes())
	attrs := result["attributes"].(map[string]any)

	if attrs["str"] != "hello" {
		t.Errorf("attrs.str = %v, want hello", attrs["str"])
	}
	if attrs["num"] != float64(42) {
		t.Errorf("attrs.num = %v, want 42", attrs["num"])
	}
	if attrs["flag"] != true {
		t.Errorf("attrs.flag = %v, want true", attrs["flag"])
	}
}

// =============================================================================
// Audit 字段提升
// =============================================================================

func TestContractJSONHandler_AuditFieldPromotion(t *testing.T) {
	h, buf := newJSONHandler(t)

	r := slog.NewRecord(time.Now(), slog.LevelError+4, "login event", 0)
	r.AddAttrs(
		slog.String("event_type", "login"),
		slog.String("actor", "user:42"),
		slog.Bool("success", true),
		slog.String("ip", "127.0.0.1"),
	)
	_ = h.Handle(context.Background(), r)

	result := parseJSONLine(t, buf.Bytes())

	// event_type, actor, success 提升到顶层
	if result["event_type"] != "login" {
		t.Errorf("event_type = %v, want login", result["event_type"])
	}
	if result["actor"] != "user:42" {
		t.Errorf("actor = %v, want user:42", result["actor"])
	}
	if result["success"] != true {
		t.Errorf("success = %v, want true", result["success"])
	}

	// ip 留在 attributes 中
	attrs := result["attributes"].(map[string]any)
	if attrs["ip"] != "127.0.0.1" {
		t.Errorf("attributes.ip = %v, want 127.0.0.1", attrs["ip"])
	}

	// 提升的字段不应出现在 attributes 中
	if _, ok := attrs["event_type"]; ok {
		t.Error("event_type should not be in attributes after promotion")
	}
	if _, ok := attrs["actor"]; ok {
		t.Error("actor should not be in attributes after promotion")
	}
	if _, ok := attrs["success"]; ok {
		t.Error("success should not be in attributes after promotion")
	}
}

// 类型不匹配时不提升：event_type 不是 string、success 不是 bool
func TestContractJSONHandler_AuditFieldNoPromotionOnTypeMismatch(t *testing.T) {
	h, buf := newJSONHandler(t)

	r := slog.NewRecord(time.Now(), slog.LevelInfo, "type mismatch", 0)
	r.AddAttrs(
		slog.Int("event_type", 123),
		slog.Int("success", 1),
	)
	_ = h.Handle(context.Background(), r)

	result := parseJSONLine(t, buf.Bytes())

	// 不应提升到顶层（类型不匹配）
	if _, ok := result["event_type"]; ok {
		t.Error("event_type should not be promoted when not a string")
	}
	if _, ok := result["success"]; ok {
		t.Error("success should not be promoted when not a bool")
	}

	attrs := result["attributes"].(map[string]any)
	if attrs["event_type"] == nil {
		t.Error("event_type should remain in attributes")
	}
}

// =============================================================================
// 非有限浮点值
// =============================================================================

func TestContractJSONHandler_NonFiniteFloats(t *testing.T) {
	h, buf := newJSONHandler(t)

	r := slog.NewRecord(time.Now(), slog.LevelInfo, "floats", 0)
	r.AddAttrs(
		slog.Float64("nan", math.NaN()),
		slog.Float64("pos_inf", math.Inf(1)),
		slog.Float64("neg_inf", math.Inf(-1)),
	)
	_ = h.Handle(context.Background(), r)

	// 必须产生有效 JSON
	result := parseJSONLine(t, buf.Bytes())
	attrs := result["attributes"].(map[string]any)

	// NaNSafe 策略：NaN/Inf → nil
	for _, key := range []string{"nan", "pos_inf", "neg_inf"} {
		if _, ok := attrs[key]; !ok {
			t.Errorf("%s missing from attributes", key)
		}
	}
}

// =============================================================================
// WithGroup 点分隔
// =============================================================================

func TestContractJSONHandler_WithGroup(t *testing.T) {
	h, buf := newJSONHandler(t)

	child := h.WithGroup("request")
	r := slog.NewRecord(time.Now(), slog.LevelInfo, "grouped", 0)
	r.AddAttrs(slog.String("id", "abc"))
	_ = child.Handle(context.Background(), r)

	result := parseJSONLine(t, buf.Bytes())
	attrs := result["attributes"].(map[string]any)
	if attrs["request.id"] != "abc" {
		t.Errorf("attributes[request.id] = %v, want abc", attrs["request.id"])
	}
}

// =============================================================================
// WithGroup + WithAttrs 组合
// =============================================================================

func TestContractJSONHandler_WithGroupWithAttrs(t *testing.T) {
	h, buf := newJSONHandler(t)

	child := h.WithGroup("http").
		WithAttrs([]slog.Attr{slog.String("method", "GET")})

	r := slog.NewRecord(time.Now(), slog.LevelInfo, "combined", 0)
	r.AddAttrs(slog.Int("status", 200))
	_ = child.Handle(context.Background(), r)

	result := parseJSONLine(t, buf.Bytes())
	attrs := result["attributes"].(map[string]any)

	if attrs["http.method"] != "GET" {
		t.Errorf("attributes[http.method] = %v, want GET", attrs["http.method"])
	}
	if attrs["http.status"] != float64(200) {
		t.Errorf("attributes[http.status] = %v, want 200", attrs["http.status"])
	}
}

// =============================================================================
// 嵌套 Group
// =============================================================================

func TestContractJSONHandler_NestedGroup(t *testing.T) {
	h, buf := newJSONHandler(t)

	child := h.WithGroup("http").WithGroup("request")
	r := slog.NewRecord(time.Now(), slog.LevelInfo, "nested", 0)
	r.AddAttrs(slog.String("id", "123"))
	_ = child.Handle(context.Background(), r)

	result := parseJSONLine(t, buf.Bytes())
	attrs := result["attributes"].(map[string]any)
	if attrs["http.request.id"] != "123" {
		t.Errorf("attributes[http.request.id] = %v, want 123", attrs["http.request.id"])
	}
}

// =============================================================================
// source 字段（caller info）
// =============================================================================

func TestContractJSONHandler_SourceField(t *testing.T) {
	h, buf := newJSONHandler(t)

	// 使用 slog.New + handler 会自动设置 PC
	logger := slog.New(h)
	logger.Info("source test")

	result := parseJSONLine(t, buf.Bytes())
	if source, ok := result["source"].(string); ok {
		if source == "" {
			t.Error("source field should not be empty when PC is set")
		}
		if !contains(source, "json_handler_test.go") {
			t.Errorf("source should contain test file name, got: %s", source)
		}
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstr(s, substr))
}

func containsSubstr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// =============================================================================
// Concurrent writes
// =============================================================================

func TestContractJSONHandler_Concurrent(t *testing.T) {
	h, buf := newJSONHandler(t)

	var wg sync.WaitGroup
	for i := range 100 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := slog.NewRecord(time.Now(), slog.LevelInfo, "concurrent", 0)
			r.AddAttrs(slog.Int("i", i))
			_ = h.Handle(context.Background(), r)
		}()
	}
	wg.Wait()

	// All lines must be valid JSON
	lines := bytes.Split(bytes.TrimSpace(buf.Bytes()), []byte("\n"))
	for _, line := range lines {
		if len(line) == 0 {
			continue
		}
		var result map[string]any
		if err := json.Unmarshal(line, &result); err != nil {
			t.Errorf("invalid JSON line: %v, got: %s", err, string(line))
		}
	}
	if len(lines) != 100 {
		t.Errorf("expected 100 lines, got %d", len(lines))
	}
}
