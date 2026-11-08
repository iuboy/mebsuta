package mebsuta

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"strings"
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

	// Trusted values come from preset attrs (WithAttrs at construction).
	derived := h.WithAttrs([]slog.Attr{
		slog.String("event_type", "login"),
		slog.String("actor", "user:42"),
		slog.Bool("success", true),
	})

	r := slog.NewRecord(time.Now(), slog.LevelError+4, "login event", 0)
	// Record attrs carrying the SAME keys must NOT reach the promoted fields —
	// otherwise any log call could forge actor/event_type/success.
	r.AddAttrs(
		slog.String("actor", "attacker"),
		slog.String("event_type", "forged"),
		slog.Bool("success", false),
		slog.String("ip", "127.0.0.1"),
	)
	_ = derived.Handle(context.Background(), r)

	result := parseJSONLine(t, buf.Bytes())

	// Promoted top-level fields carry the PRESET values.
	if result["event_type"] != "login" {
		t.Errorf("event_type = %v, want login (preset)", result["event_type"])
	}
	if result["actor"] != "user:42" {
		t.Errorf("actor = %v, want user:42 (preset)", result["actor"])
	}
	if result["success"] != true {
		t.Errorf("success = %v, want true (preset)", result["success"])
	}

	attrs := result["attributes"].(map[string]any)
	if attrs["ip"] != "127.0.0.1" {
		t.Errorf("attributes.ip = %v, want 127.0.0.1", attrs["ip"])
	}

	// The forged record-level values remain inside attributes as forensic
	// evidence — they could not reach the promoted top-level fields.
	if attrs["actor"] != "attacker" {
		t.Errorf("attributes.actor = %v, want attacker (record value kept for evidence)", attrs["actor"])
	}
	if attrs["event_type"] != "forged" {
		t.Errorf("attributes.event_type = %v, want forged (record value kept for evidence)", attrs["event_type"])
	}
	if attrs["success"] != false {
		t.Errorf("attributes.success = %v, want false (record value kept for evidence)", attrs["success"])
	}
}

// TestContractJSONHandler_RecordAttrNoPromotion verifies that when NO preset
// attr defines the contract fields, record-level actor/event_type/success are
// not promoted at all — they must remain inside attributes.
func TestContractJSONHandler_RecordAttrNoPromotion(t *testing.T) {
	h, buf := newJSONHandler(t)

	r := slog.NewRecord(time.Now(), slog.LevelInfo, "user action", 0)
	r.AddAttrs(
		slog.String("actor", "attacker"),
		slog.String("event_type", "delete"),
		slog.Bool("success", true),
	)
	_ = h.Handle(context.Background(), r)

	result := parseJSONLine(t, buf.Bytes())
	if _, ok := result["actor"]; ok {
		t.Error("record-level actor must not be promoted to top level")
	}
	if _, ok := result["event_type"]; ok {
		t.Error("record-level event_type must not be promoted to top level")
	}
	if _, ok := result["success"]; ok {
		t.Error("record-level success must not be promoted to top level")
	}
	attrs := result["attributes"].(map[string]any)
	if attrs["actor"] != "attacker" {
		t.Errorf("attributes.actor = %v, want attacker", attrs["actor"])
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

// =============================================================================
// 四轮审计批 C：AUDIT 级 record 提升信任锚 + 截断标记
// =============================================================================

// TestContractJSONHandler_AuditRecordLevelPromotion: an AUDIT record without
// preset attrs carries its own trust anchor — record-level event_type/actor/
// success are promoted to top level (the only way audit.AuditEvent output
// can satisfy the top-level contract when the logger has no presets).
func TestContractJSONHandler_AuditRecordLevelPromotion(t *testing.T) {
	h, buf := newJSONHandler(t)

	r := slog.NewRecord(time.Now(), LevelAudit, "user login", 0)
	r.AddAttrs(
		slog.String("event_type", "login"),
		slog.String("actor", "user:42"),
		slog.Bool("success", true),
		slog.String("ip", "127.0.0.1"),
	)
	_ = h.Handle(context.Background(), r)

	result := parseJSONLine(t, buf.Bytes())
	if result["event_type"] != "login" {
		t.Errorf("event_type = %v, want login promoted from the AUDIT record", result["event_type"])
	}
	if result["actor"] != "user:42" {
		t.Errorf("actor = %v, want user:42 promoted from the AUDIT record", result["actor"])
	}
	if result["success"] != true {
		t.Errorf("success = %v, want true promoted from the AUDIT record", result["success"])
	}
	attrs := result["attributes"].(map[string]any)
	if _, ok := attrs["event_type"]; ok {
		t.Error("promoted event_type must be removed from attributes")
	}
	if _, ok := attrs["actor"]; ok {
		t.Error("promoted actor must be removed from attributes")
	}
	if _, ok := attrs["success"]; ok {
		t.Error("promoted success must be removed from attributes")
	}
	if attrs["ip"] != "127.0.0.1" {
		t.Errorf("attributes.ip = %v, want 127.0.0.1", attrs["ip"])
	}
}

// TestContractJSONHandler_AuditPresetWinsOverRecord: with BOTH a preset and
// an AUDIT record attr defining the same field, the preset value stays
// authoritative and the record value remains inside attributes as evidence.
func TestContractJSONHandler_AuditPresetWinsOverRecord(t *testing.T) {
	h, buf := newJSONHandler(t)

	derived := h.WithAttrs([]slog.Attr{slog.String("event_type", "login")})
	r := slog.NewRecord(time.Now(), LevelAudit, "forged attempt", 0)
	r.AddAttrs(slog.String("event_type", "delete"))
	_ = derived.Handle(context.Background(), r)

	result := parseJSONLine(t, buf.Bytes())
	if result["event_type"] != "login" {
		t.Errorf("event_type = %v, want login (preset wins)", result["event_type"])
	}
	attrs := result["attributes"].(map[string]any)
	if attrs["event_type"] != "delete" {
		t.Errorf("attributes.event_type = %v, want delete (record value kept as evidence)", attrs["event_type"])
	}
}

// TestContractJSONHandler_InfoPresetPromotesRecordStays: on non-AUDIT
// records the preset still promotes, but a record attr with the same key
// stays inside attributes — the trust anchor is the level, not the key.
func TestContractJSONHandler_InfoPresetPromotesRecordStays(t *testing.T) {
	h, buf := newJSONHandler(t)

	derived := h.WithAttrs([]slog.Attr{slog.String("actor", "user:42")})
	r := slog.NewRecord(time.Now(), slog.LevelInfo, "routine", 0)
	r.AddAttrs(slog.String("actor", "impostor"))
	_ = derived.Handle(context.Background(), r)

	result := parseJSONLine(t, buf.Bytes())
	if result["actor"] != "user:42" {
		t.Errorf("actor = %v, want user:42 (preset promotes on INFO too)", result["actor"])
	}
	attrs := result["attributes"].(map[string]any)
	if attrs["actor"] != "impostor" {
		t.Errorf("attributes.actor = %v, want impostor (record value never promoted on INFO)", attrs["actor"])
	}
}

// TestContractJSONHandler_AuditRecordTypeMismatchNoPromotion: a type-
// mismatched AUDIT record attr (event_type not a string) must not promote.
func TestContractJSONHandler_AuditRecordTypeMismatchNoPromotion(t *testing.T) {
	h, buf := newJSONHandler(t)

	r := slog.NewRecord(time.Now(), LevelAudit, "mismatch", 0)
	r.AddAttrs(
		slog.Int("event_type", 123),
		slog.Int("success", 1),
	)
	_ = h.Handle(context.Background(), r)

	result := parseJSONLine(t, buf.Bytes())
	if _, ok := result["event_type"]; ok {
		t.Error("int event_type must not be promoted, even on AUDIT records")
	}
	if _, ok := result["success"]; ok {
		t.Error("int success must not be promoted, even on AUDIT records")
	}
	attrs := result["attributes"].(map[string]any)
	if attrs["event_type"] == nil {
		t.Error("type-mismatched event_type should remain in attributes")
	}
}

// =============================================================================
// 截断标记（attributes._truncated，对齐 syslog 的 _truncated PARAM-NAME）
// =============================================================================

// TestContractJSONHandler_TruncationMarkerOnAttrCount: exceeding the 1024
// attribute cap must drop the surplus AND surface attributes._truncated.
func TestContractJSONHandler_TruncationMarkerOnAttrCount(t *testing.T) {
	h, buf := newJSONHandler(t)

	r := slog.NewRecord(time.Now(), slog.LevelInfo, "flood", 0)
	for i := 0; i < 1100; i++ {
		r.AddAttrs(slog.String(fmt.Sprintf("k%04d", i), "v"))
	}
	_ = h.Handle(context.Background(), r)

	result := parseJSONLine(t, buf.Bytes())
	attrs := result["attributes"].(map[string]any)
	if attrs["_truncated"] != true {
		t.Error("attributes._truncated must be true when the attr count cap is hit")
	}
	// 1024 capped entries + the marker itself.
	if len(attrs) != 1025 {
		t.Errorf("attributes len = %d, want 1025 (1024 cap + marker)", len(attrs))
	}
}

// TestContractJSONHandler_TruncationMarkerOnKeyLen: a key longer than the
// 256-byte cap must be clipped to valid UTF-8 AND surface the marker.
func TestContractJSONHandler_TruncationMarkerOnKeyLen(t *testing.T) {
	h, buf := newJSONHandler(t)

	longKey := strings.Repeat("k", 300)
	r := slog.NewRecord(time.Now(), slog.LevelInfo, "long key", 0)
	r.AddAttrs(slog.String(longKey, "v"))
	_ = h.Handle(context.Background(), r)

	result := parseJSONLine(t, buf.Bytes())
	attrs := result["attributes"].(map[string]any)
	if attrs["_truncated"] != true {
		t.Error("attributes._truncated must be true when a key is clipped")
	}
	foundClipped := false
	for k := range attrs {
		if k != "_truncated" && strings.HasPrefix(k, strings.Repeat("k", 200)) && len(k) <= 256 {
			foundClipped = true
		}
	}
	if !foundClipped {
		t.Errorf("expected a clipped <=256B key among attributes: %d entries", len(attrs))
	}
}

// TestContractJSONHandler_NoTruncationMarker: intact records must not carry
// the marker, so consumers can trust its absence as a completeness signal.
func TestContractJSONHandler_NoTruncationMarker(t *testing.T) {
	h, buf := newJSONHandler(t)

	r := slog.NewRecord(time.Now(), slog.LevelInfo, "normal", 0)
	r.AddAttrs(slog.String("k", "v"))
	_ = h.Handle(context.Background(), r)

	result := parseJSONLine(t, buf.Bytes())
	attrs := result["attributes"].(map[string]any)
	if _, ok := attrs["_truncated"]; ok {
		t.Error("_truncated must be absent when nothing was dropped or clipped")
	}
}

// TestContractJSONHandler_TruncationMarkerOnDepth: a group nesting deeper
// than the flatten cap drops the subtree and must surface the marker.
func TestContractJSONHandler_TruncationMarkerOnDepth(t *testing.T) {
	h, buf := newJSONHandler(t)

	// 20 levels of nesting exceeds maxFlattenDepth (16).
	r := slog.NewRecord(time.Now(), slog.LevelInfo, "deep", 0)
	deep := slog.String("leaf", "v")
	for i := 0; i < 20; i++ {
		deep = slog.Group("g", deep)
	}
	r.AddAttrs(deep)
	_ = h.Handle(context.Background(), r)

	result := parseJSONLine(t, buf.Bytes())
	attrs := result["attributes"].(map[string]any)
	if attrs["_truncated"] != true {
		t.Error("attributes._truncated must be true when the nesting cap drops a subtree")
	}
}
