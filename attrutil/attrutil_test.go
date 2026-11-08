package attrutil

import (
	"errors"
	"fmt"
	"log/slog"
	"math"
	"strings"
	"testing"
	"time"
)

// TestSlogValueAny_Error is the regression test for the "error":{} bug:
// an error-typed value must return its message string, not the backing
// struct (which json.Marshal renders as "{}").
func TestSlogValueAny_Error(t *testing.T) {
	wrapped := fmt.Errorf("read config file: %w", errors.New("yaml: line 10: bad key"))
	got := SlogValueAny(slog.AnyValue(wrapped), NaNSafe)
	s, ok := got.(string)
	if !ok {
		t.Fatalf("SlogValueAny(error) returned %T (%v), want string", got, got)
	}
	if s != "read config file: yaml: line 10: bad key" {
		t.Errorf("SlogValueAny(error) = %q, want full wrapped message", s)
	}

	// A plain (non-wrapped) error must also work.
	plain := errors.New("plain failure")
	got2 := SlogValueAny(slog.AnyValue(plain), NaNSafe)
	if s2, ok := got2.(string); !ok || s2 != "plain failure" {
		t.Errorf("plain error = %v (%T), want \"plain failure\"", got2, got2)
	}
}

func TestSlogValueAny_Kinds(t *testing.T) {
	tests := []struct {
		name string
		val  slog.Value
		want any
	}{
		{"string", slog.StringValue("hello"), "hello"},
		{"int64", slog.Int64Value(42), int64(42)},
		{"uint64", slog.Uint64Value(100), uint64(100)},
		{"bool_true", slog.BoolValue(true), true},
		{"bool_false", slog.BoolValue(false), false},
		{"duration", slog.DurationValue(time.Second), "1s"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SlogValueAny(tt.val, NaNSafe)
			if got != tt.want {
				t.Errorf("SlogValueAny(%v) = %v, want %v", tt.val, got, tt.want)
			}
		})
	}
}

func TestSlogValueAny_Float64_NaN(t *testing.T) {
	tests := []struct {
		name    string
		nan     NaNBehavior
		wantNil bool
		wantStr bool
	}{
		{"safe returns nil", NaNSafe, true, false},
		{"string returns string", NaNString, false, true},
		{"raw returns float", NaNRaw, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SlogValueAny(slog.Float64Value(math.NaN()), tt.nan)
			if tt.wantNil && got != nil {
				t.Errorf("expected nil, got %v", got)
			}
			if tt.wantStr {
				s, ok := got.(string)
				if !ok {
					t.Errorf("expected string, got %T", got)
				}
				if s != "NaN" {
					t.Errorf("expected 'NaN', got %q", s)
				}
			}
			if !tt.wantNil && !tt.wantStr {
				f, ok := got.(float64)
				if !ok || !math.IsNaN(f) {
					t.Errorf("expected NaN float64, got %v", got)
				}
			}
		})
	}
}

func TestSlogValueAny_Float64_Inf(t *testing.T) {
	got := SlogValueAny(slog.Float64Value(math.Inf(1)), NaNSafe)
	if got != nil {
		t.Errorf("Inf with NaNSafe should return nil, got %v", got)
	}
	got = SlogValueAny(slog.Float64Value(math.Inf(-1)), NaNString)
	s, ok := got.(string)
	if !ok {
		t.Errorf("Inf with NaNString should return string, got %T", got)
	}
	if s != "+Inf" && s != "-Inf" {
		t.Errorf("unexpected Inf string: %q", s)
	}
}

func TestSlogValueAny_Float64_Normal(t *testing.T) {
	got := SlogValueAny(slog.Float64Value(3.14), NaNSafe)
	f, ok := got.(float64)
	if !ok || f != 3.14 {
		t.Errorf("normal float should pass through, got %v", got)
	}
}

func TestSlogValueAny_Time(t *testing.T) {
	now := time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)
	got := SlogValueAny(slog.TimeValue(now), NaNSafe)
	tm, ok := got.(time.Time)
	if !ok {
		t.Errorf("expected time.Time, got %T", got)
	}
	if !tm.Equal(now) {
		t.Errorf("time mismatch: got %v, want %v", tm, now)
	}
}

func TestSlogValueAny_Group(t *testing.T) {
	v := slog.GroupValue(slog.String("key", "val"), slog.Int("num", 1))
	got := SlogValueAny(v, NaNSafe)
	m, ok := got.(map[string]any)
	if !ok {
		t.Fatalf("expected map, got %T", got)
	}
	if m["key"] != "val" {
		t.Errorf("key = %v, want val", m["key"])
	}
	if m["num"] != int64(1) {
		t.Errorf("num = %v, want 1", m["num"])
	}
}

func TestFlattenAttr_Simple(t *testing.T) {
	out := make(map[string]any)
	FlattenAttr(out, "", slog.String("name", "test"), NaNSafe)
	if out["name"] != "test" {
		t.Errorf("name = %v, want test", out["name"])
	}
}

func TestFlattenAttr_WithPrefix(t *testing.T) {
	out := make(map[string]any)
	FlattenAttr(out, "req", slog.String("id", "123"), NaNSafe)
	if out["req.id"] != "123" {
		t.Errorf("req.id = %v, want 123", out["req.id"])
	}
}

func TestFlattenAttr_Group(t *testing.T) {
	out := make(map[string]any)
	FlattenAttr(out, "", slog.Group("http", slog.String("method", "GET"), slog.Int("status", 200)), NaNSafe)
	if out["http.method"] != "GET" {
		t.Errorf("http.method = %v, want GET", out["http.method"])
	}
	if out["http.status"] != int64(200) {
		t.Errorf("http.status = %v, want 200", out["http.status"])
	}
}

func TestFlattenAttr_EmptyKey(t *testing.T) {
	out := make(map[string]any)
	FlattenAttr(out, "", slog.Attr{}, NaNSafe)
	if len(out) != 0 {
		t.Errorf("empty key should not produce output, got %v", out)
	}
}

func TestFlattenAttrsToMap(t *testing.T) {
	attrs := []slog.Attr{
		slog.String("a", "1"),
		slog.Int("b", 2),
	}
	out := FlattenAttrsToMap(attrs, NaNSafe)
	if out["a"] != "1" {
		t.Errorf("a = %v, want 1", out["a"])
	}
	if out["b"] != int64(2) {
		t.Errorf("b = %v, want 2", out["b"])
	}
}

func TestFormatTime(t *testing.T) {
	now := time.Date(2025, 6, 1, 12, 30, 0, 123456789, time.UTC)
	got := FormatTime(now)
	if got != "2025-06-01T12:30:00.123456789Z" {
		t.Errorf("FormatTime = %q", got)
	}
}

func TestFormatTime_ConvertsToUTC(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	tm := time.Date(2025, 6, 1, 20, 0, 0, 0, loc)
	got := FormatTime(tm)
	if got != "2025-06-01T12:00:00Z" {
		t.Errorf("FormatTime should convert to UTC: %q", got)
	}
}

func TestFlattenAttr_MaxKeyLen(t *testing.T) {
	longKey := make([]byte, maxKeyLen+100)
	for i := range longKey {
		longKey[i] = 'a'
	}
	out := make(map[string]any)
	FlattenAttr(out, "", slog.String(string(longKey), "val"), NaNSafe)
	if len(out) != 1 {
		t.Fatalf("expected 1 key, got %d", len(out))
	}
	for k := range out {
		if len(k) != maxKeyLen {
			t.Errorf("key length = %d, want max %d", len(k), maxKeyLen)
		}
	}
}

func TestFlattenAttr_MaxAttrCount(t *testing.T) {
	out := make(map[string]any)
	for i := 0; i < maxAttrCount+100; i++ {
		FlattenAttr(out, "", slog.Int("key", i), NaNSafe)
	}
	if len(out) > maxAttrCount {
		t.Errorf("output map has %d entries, want max %d", len(out), maxAttrCount)
	}
}

// =============================================================================
// 四轮审计批 C：截断信息外泄（FlattenAttrMarked）
// =============================================================================

// TestFlattenAttrMarked_NoTruncation: a plain attr flattens unmarked.
func TestFlattenAttrMarked_NoTruncation(t *testing.T) {
	out := make(map[string]any)
	if truncated := FlattenAttrMarked(out, "", slog.String("k", "v"), NaNSafe); truncated {
		t.Error("plain attr must not report truncation")
	}
	if out["k"] != "v" {
		t.Errorf("out[k] = %v, want v", out["k"])
	}
}

// TestFlattenAttrMarked_KeyTruncated: a key over maxKeyLen is clipped and
// reported.
func TestFlattenAttrMarked_KeyTruncated(t *testing.T) {
	out := make(map[string]any)
	long := strings.Repeat("k", 300)
	truncated := FlattenAttrMarked(out, "", slog.String(long, "v"), NaNSafe)
	if !truncated {
		t.Error("clipped key must report truncation")
	}
	for k := range out {
		if len(k) > maxKeyLen {
			t.Errorf("key not clipped: %d bytes", len(k))
		}
	}
}

// TestFlattenAttrMarked_AttrCountCap: once the map hits the cap, further
// attrs are dropped and reported.
func TestFlattenAttrMarked_AttrCountCap(t *testing.T) {
	out := make(map[string]any)
	for i := 0; i < maxAttrCount; i++ {
		FlattenAttrMarked(out, "", slog.String(fmt.Sprintf("k%04d", i), "v"), NaNSafe)
	}
	truncated := FlattenAttrMarked(out, "", slog.String("overflow", "v"), NaNSafe)
	if !truncated {
		t.Error("attr dropped by the count cap must report truncation")
	}
	if _, ok := out["overflow"]; ok {
		t.Error("attr beyond the cap must be dropped")
	}
}

// TestFlattenAttrMarked_DepthCap: a group nesting deeper than the cap drops
// the subtree and reports truncation.
func TestFlattenAttrMarked_DepthCap(t *testing.T) {
	out := make(map[string]any)
	deep := slog.String("leaf", "v")
	for i := 0; i < 20; i++ { // maxFlattenDepth is 16
		deep = slog.Group("g", deep)
	}
	if truncated := FlattenAttrMarked(out, "", deep, NaNSafe); !truncated {
		t.Error("subtree dropped by the depth cap must report truncation")
	}
}

// TestFlattenAttrMarked_EmptyKeyNotTruncation: the empty-key sanitation drop
// is by-design input hygiene, not a truncation event.
func TestFlattenAttrMarked_EmptyKeyNotTruncation(t *testing.T) {
	out := make(map[string]any)
	if truncated := FlattenAttrMarked(out, "prefix", slog.String("", "v"), NaNSafe); truncated {
		t.Error("empty-key drop is sanitation, not truncation")
	}
}
