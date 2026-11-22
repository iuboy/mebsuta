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

	"github.com/stretchr/testify/require"
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
	require.NoError(t, json.Unmarshal(data, &result), "invalid JSON: %s", string(data))
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
		require.Contains(t, result, key, "missing required key")
	}
	require.Equal(t, "test message", result["message"], "message")
	require.Equal(t, "INFO", result["level"], "level")
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
			require.Equal(t, tt.want, result["level"], "level")
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

	require.Equal(t, "hello", attrs["str"], "attrs.str")
	require.Equal(t, float64(42), attrs["num"], "attrs.num")
	require.Equal(t, true, attrs["flag"], "attrs.flag")
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
	require.Equal(t, "login", result["event_type"], "event_type (preset)")
	require.Equal(t, "user:42", result["actor"], "actor (preset)")
	require.Equal(t, true, result["success"], "success (preset)")

	attrs := result["attributes"].(map[string]any)
	require.Equal(t, "127.0.0.1", attrs["ip"], "attributes.ip")

	// The forged record-level values remain inside attributes as forensic
	// evidence — they could not reach the promoted top-level fields.
	require.Equal(t, "attacker", attrs["actor"], "attributes.actor (record value kept for evidence)")
	require.Equal(t, "forged", attrs["event_type"], "attributes.event_type (record value kept for evidence)")
	require.Equal(t, false, attrs["success"], "attributes.success (record value kept for evidence)")
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
	require.NotContains(t, result, "actor", "record-level actor must not be promoted to top level")
	require.NotContains(t, result, "event_type", "record-level event_type must not be promoted to top level")
	require.NotContains(t, result, "success", "record-level success must not be promoted to top level")
	attrs := result["attributes"].(map[string]any)
	require.Equal(t, "attacker", attrs["actor"], "attributes.actor")
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
	require.NotContains(t, result, "event_type", "event_type should not be promoted when not a string")
	require.NotContains(t, result, "success", "success should not be promoted when not a bool")

	attrs := result["attributes"].(map[string]any)
	require.NotNil(t, attrs["event_type"], "event_type should remain in attributes")
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
		require.Contains(t, attrs, key, "missing from attributes")
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
	require.Equal(t, "abc", attrs["request.id"], "attributes[request.id]")
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

	require.Equal(t, "GET", attrs["http.method"], "attributes[http.method]")
	require.Equal(t, float64(200), attrs["http.status"], "attributes[http.status]")
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
	require.Equal(t, "123", attrs["http.request.id"], "attributes[http.request.id]")
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
		require.NotEmpty(t, source, "source field should not be empty when PC is set")
		require.Contains(t, source, "json_handler_test.go", "source should contain test file name")
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
		require.NoError(t, json.Unmarshal(line, &result), "invalid JSON line: %s", string(line))
	}
	require.Len(t, lines, 100, "expected 100 lines")
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
	require.Equal(t, "login", result["event_type"], "event_type promoted from the AUDIT record")
	require.Equal(t, "user:42", result["actor"], "actor promoted from the AUDIT record")
	require.Equal(t, true, result["success"], "success promoted from the AUDIT record")
	attrs := result["attributes"].(map[string]any)
	require.NotContains(t, attrs, "event_type", "promoted event_type must be removed from attributes")
	require.NotContains(t, attrs, "actor", "promoted actor must be removed from attributes")
	require.NotContains(t, attrs, "success", "promoted success must be removed from attributes")
	require.Equal(t, "127.0.0.1", attrs["ip"], "attributes.ip")
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
	require.Equal(t, "login", result["event_type"], "event_type (preset wins)")
	attrs := result["attributes"].(map[string]any)
	require.Equal(t, "delete", attrs["event_type"], "attributes.event_type (record value kept as evidence)")
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
	require.Equal(t, "user:42", result["actor"], "actor (preset promotes on INFO too)")
	attrs := result["attributes"].(map[string]any)
	require.Equal(t, "impostor", attrs["actor"], "attributes.actor (record value never promoted on INFO)")
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
	require.NotContains(t, result, "event_type", "int event_type must not be promoted, even on AUDIT records")
	require.NotContains(t, result, "success", "int success must not be promoted, even on AUDIT records")
	attrs := result["attributes"].(map[string]any)
	require.NotNil(t, attrs["event_type"], "type-mismatched event_type should remain in attributes")
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
	require.Equal(t, true, attrs["_truncated"], "attributes._truncated must be true when the attr count cap is hit")
	// 1024 capped entries + the marker itself.
	require.Len(t, attrs, 1025, "attributes len (1024 cap + marker)")
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
	require.Equal(t, true, attrs["_truncated"], "attributes._truncated must be true when a key is clipped")
	foundClipped := false
	for k := range attrs {
		if k != "_truncated" && strings.HasPrefix(k, strings.Repeat("k", 200)) && len(k) <= 256 {
			foundClipped = true
		}
	}
	require.True(t, foundClipped, "expected a clipped <=256B key among attributes: %d entries", len(attrs))
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
	require.NotContains(t, attrs, "_truncated", "_truncated must be absent when nothing was dropped or clipped")
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
	require.Equal(t, true, attrs["_truncated"], "attributes._truncated must be true when the nesting cap drops a subtree")
}

// TestContractJSONHandler_NestedUnserializableFallback is the regression test
// for the silent record loss: a NaN (or chan/func) nested inside a map attr
// used to fail json.Marshal, and Handle returned the error — which
// slog.Logger discards — so the record vanished with no trace. Now a
// fallback ERROR record must be written.
func TestContractJSONHandler_NestedUnserializableFallback(t *testing.T) {
	h, buf := newJSONHandler(t)

	r := slog.NewRecord(time.Now(), slog.LevelInfo, "IMPORTANT audit message", 0)
	r.AddAttrs(slog.Any("nested", map[string]any{"ratio": math.NaN()}))
	require.NoError(t, h.Handle(context.Background(), r), "Handle returned error instead of degrading")

	out := buf.String()
	require.Contains(t, out, "marshal failed", "expected fallback record")
	var parsed map[string]any
	require.NoError(t, json.Unmarshal([]byte(strings.TrimSpace(out)), &parsed), "fallback output is not valid JSON: %s", out)
	require.Equal(t, "ERROR", parsed["level"], "fallback level")
	attrs := parsed["attributes"].(map[string]any)
	require.Contains(t, attrs["original_message"].(string), "IMPORTANT audit message", "fallback lost original message")
	require.NotNil(t, attrs["marshal_error"], "fallback missing marshal_error attribute")
}
