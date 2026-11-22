package attrutil

import (
	"errors"
	"fmt"
	"log/slog"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestSlogValueAny_Error 是 "error":{} 缺陷的回归测试：error 类型的值
// 必须返回其消息字符串，而非底层结构（json.Marshal 会把它渲染成 "{}"）。
func TestSlogValueAny_Error(t *testing.T) {
	wrapped := fmt.Errorf("read config file: %w", errors.New("yaml: line 10: bad key"))
	got := SlogValueAny(slog.AnyValue(wrapped), NaNSafe)
	s, ok := got.(string)
	require.True(t, ok, "SlogValueAny(error) 返回了 %T (%v)，应为 string", got, got)
	require.Equal(t, "read config file: yaml: line 10: bad key", s, "应为完整的包装后消息")

	// 普通（未包装的）error 也必须可用。
	plain := errors.New("plain failure")
	got2 := SlogValueAny(slog.AnyValue(plain), NaNSafe)
	s2, ok := got2.(string)
	require.True(t, ok, "普通 error 应为 string")
	require.Equal(t, "plain failure", s2)
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
			require.Equal(t, tt.want, got, "SlogValueAny(%v)", tt.val)
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
			if tt.wantNil {
				require.Nil(t, got, "应为 nil")
			}
			if tt.wantStr {
				s, ok := got.(string)
				require.True(t, ok, "应为 string")
				require.Equal(t, "NaN", s)
			}
			if !tt.wantNil && !tt.wantStr {
				f, ok := got.(float64)
				require.True(t, ok, "应为 float64")
				require.True(t, math.IsNaN(f), "应为 NaN float64")
			}
		})
	}
}

func TestSlogValueAny_Float64_Inf(t *testing.T) {
	got := SlogValueAny(slog.Float64Value(math.Inf(1)), NaNSafe)
	require.Nil(t, got, "NaNSafe 下的 Inf 应返回 nil")
	got = SlogValueAny(slog.Float64Value(math.Inf(-1)), NaNString)
	s, ok := got.(string)
	require.True(t, ok, "NaNString 下的 Inf 应返回 string")
	require.Contains(t, []string{"+Inf", "-Inf"}, s, "Inf 字符串应为 +Inf 或 -Inf")
}

func TestSlogValueAny_Float64_Normal(t *testing.T) {
	got := SlogValueAny(slog.Float64Value(3.14), NaNSafe)
	f, ok := got.(float64)
	require.True(t, ok, "普通浮点应原样通过")
	require.Equal(t, 3.14, f)
}

func TestSlogValueAny_Time(t *testing.T) {
	now := time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)
	got := SlogValueAny(slog.TimeValue(now), NaNSafe)
	tm, ok := got.(time.Time)
	require.True(t, ok, "应为 time.Time")
	require.True(t, tm.Equal(now), "时间应为 %v，实际 %v", now, tm)
}

func TestSlogValueAny_Group(t *testing.T) {
	v := slog.GroupValue(slog.String("key", "val"), slog.Int("num", 1))
	got := SlogValueAny(v, NaNSafe)
	m, ok := got.(map[string]any)
	require.True(t, ok, "应为 map")
	require.Equal(t, "val", m["key"])
	require.Equal(t, int64(1), m["num"])
}

func TestFlattenAttr_Simple(t *testing.T) {
	out := make(map[string]any)
	FlattenAttr(out, "", slog.String("name", "test"), NaNSafe)
	require.Equal(t, "test", out["name"])
}

func TestFlattenAttr_WithPrefix(t *testing.T) {
	out := make(map[string]any)
	FlattenAttr(out, "req", slog.String("id", "123"), NaNSafe)
	require.Equal(t, "123", out["req.id"])
}

func TestFlattenAttr_Group(t *testing.T) {
	out := make(map[string]any)
	FlattenAttr(out, "", slog.Group("http", slog.String("method", "GET"), slog.Int("status", 200)), NaNSafe)
	require.Equal(t, "GET", out["http.method"])
	require.Equal(t, int64(200), out["http.status"])
}

func TestFlattenAttr_EmptyKey(t *testing.T) {
	out := make(map[string]any)
	FlattenAttr(out, "", slog.Attr{}, NaNSafe)
	require.Empty(t, out, "空键不应产生输出")
}

func TestFlattenAttrsToMap(t *testing.T) {
	attrs := []slog.Attr{
		slog.String("a", "1"),
		slog.Int("b", 2),
	}
	out := FlattenAttrsToMap(attrs, NaNSafe)
	require.Equal(t, "1", out["a"])
	require.Equal(t, int64(2), out["b"])
}

func TestFormatTime(t *testing.T) {
	now := time.Date(2025, 6, 1, 12, 30, 0, 123456789, time.UTC)
	got := FormatTime(now)
	require.Equal(t, "2025-06-01T12:30:00.123456789Z", got)
}

func TestFormatTime_ConvertsToUTC(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	tm := time.Date(2025, 6, 1, 20, 0, 0, 0, loc)
	got := FormatTime(tm)
	require.Equal(t, "2025-06-01T12:00:00Z", got, "FormatTime 应转换为 UTC")
}

func TestFlattenAttr_MaxKeyLen(t *testing.T) {
	longKey := make([]byte, maxKeyLen+100)
	for i := range longKey {
		longKey[i] = 'a'
	}
	out := make(map[string]any)
	FlattenAttr(out, "", slog.String(string(longKey), "val"), NaNSafe)
	require.Len(t, out, 1)
	for k := range out {
		require.Len(t, k, maxKeyLen, "键长不得超过 %d", maxKeyLen)
	}
}

func TestFlattenAttr_MaxAttrCount(t *testing.T) {
	out := make(map[string]any)
	for i := 0; i < maxAttrCount+100; i++ {
		FlattenAttr(out, "", slog.Int("key", i), NaNSafe)
	}
	require.LessOrEqual(t, len(out), maxAttrCount, "输出映射条目不得超过 %d", maxAttrCount)
}

// =============================================================================
// 四轮审计批 C：截断信息外泄（FlattenAttrMarked）
// =============================================================================

// TestFlattenAttrMarked_NoTruncation：普通属性扁平化后不标记截断。
func TestFlattenAttrMarked_NoTruncation(t *testing.T) {
	out := make(map[string]any)
	require.False(t, FlattenAttrMarked(out, "", slog.String("k", "v"), NaNSafe), "普通属性不得报告截断")
	require.Equal(t, "v", out["k"])
}

// TestFlattenAttrMarked_KeyTruncated：超过 maxKeyLen 的键被裁剪并报告。
func TestFlattenAttrMarked_KeyTruncated(t *testing.T) {
	out := make(map[string]any)
	long := strings.Repeat("k", 300)
	truncated := FlattenAttrMarked(out, "", slog.String(long, "v"), NaNSafe)
	require.True(t, truncated, "被裁剪的键必须报告截断")
	for k := range out {
		require.LessOrEqual(t, len(k), maxKeyLen, "键未被裁剪：%d 字节", len(k))
	}
}

// TestFlattenAttrMarked_AttrCountCap：映射达到上限后，后续属性被丢弃
// 并报告。
func TestFlattenAttrMarked_AttrCountCap(t *testing.T) {
	out := make(map[string]any)
	for i := 0; i < maxAttrCount; i++ {
		FlattenAttrMarked(out, "", slog.String(fmt.Sprintf("k%04d", i), "v"), NaNSafe)
	}
	truncated := FlattenAttrMarked(out, "", slog.String("overflow", "v"), NaNSafe)
	require.True(t, truncated, "被数量上限丢弃的属性必须报告截断")
	require.NotContains(t, out, "overflow", "超出上限的属性必须被丢弃")
}

// TestFlattenAttrMarked_DepthCap：超过嵌套上限的 group 子树被丢弃并
// 报告截断。
func TestFlattenAttrMarked_DepthCap(t *testing.T) {
	out := make(map[string]any)
	deep := slog.String("leaf", "v")
	for i := 0; i < 20; i++ { // maxFlattenDepth 为 16
		deep = slog.Group("g", deep)
	}
	require.True(t, FlattenAttrMarked(out, "", deep, NaNSafe), "被深度上限丢弃的子树必须报告截断")
}

// TestFlattenAttrMarked_EmptyKeyNotTruncation：空键的清洁性丢弃是设计
// 之上的输入卫生，不是截断事件。
func TestFlattenAttrMarked_EmptyKeyNotTruncation(t *testing.T) {
	out := make(map[string]any)
	require.False(t, FlattenAttrMarked(out, "prefix", slog.String("", "v"), NaNSafe),
		"空键丢弃是输入清洁，不是截断")
}
