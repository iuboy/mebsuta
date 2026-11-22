package handlerkit

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// =============================================================================
// MergeAttrs / RecordWithGroupAttrs 测试（自根包迁入——两轮结构收敛后
// 的覆盖回归修复）
// =============================================================================

func TestMergeAttrs(t *testing.T) {
	existing := []slog.Attr{slog.String("a", "1")}
	newAttrs := []slog.Attr{slog.String("b", "2")}

	// 空 group：原样合并，不加前缀。
	merged := MergeAttrs(existing, newAttrs, "")
	require.Len(t, merged, 2, "empty group: 2 attrs")
	require.Equal(t, "a", merged[0].Key, "first key unchanged")
	require.Equal(t, "b", merged[1].Key, "second key unchanged")

	// 非空 group：只为 newAttrs 加前缀，existing 保持原样。
	merged = MergeAttrs(existing, newAttrs, "req")
	require.Len(t, merged, 2, "group: 2 attrs")
	require.Equal(t, "a", merged[0].Key, "existing key unprefixed")
	require.Equal(t, "req.b", merged[1].Key, "new key prefixed")
}

func TestRecordWithGroupAttrs(t *testing.T) {
	r := slog.NewRecord(time.Now(), slog.LevelInfo, "msg", 0)
	r.AddAttrs(slog.String("id", "1"))

	newR := RecordWithGroupAttrs(r, "req", []slog.Attr{slog.String("extra", "data")})

	var attrs []slog.Attr
	newR.Attrs(func(a slog.Attr) bool {
		attrs = append(attrs, a)
		return true
	})

	require.Len(t, attrs, 2, "expected 2 attrs")
	require.Equal(t, "req.id", attrs[0].Key, "first attr key")
	require.Equal(t, "extra", attrs[1].Key, "second attr key")
}

// =============================================================================
// AttrsSub / GroupSub 测试
// =============================================================================

// captureHandler 记录收到的每条 record，供断言转发语义。
type captureHandler struct {
	records []slog.Record
	attrs   [][]slog.Attr
}

func (c *captureHandler) Enabled(context.Context, slog.Level) bool { return true }

func (c *captureHandler) Handle(_ context.Context, r slog.Record) error {
	var attrs []slog.Attr
	r.Attrs(func(a slog.Attr) bool {
		attrs = append(attrs, a)
		return true
	})
	c.records = append(c.records, r)
	c.attrs = append(c.attrs, attrs)
	return nil
}

func (c *captureHandler) WithAttrs(attrs []slog.Attr) slog.Handler { return c }
func (c *captureHandler) WithGroup(string) slog.Handler            { return c }

func TestAttrsSub_HandleDoesNotMutateCallerRecord(t *testing.T) {
	parent := &captureHandler{}
	sub := &AttrsSub{Parent: parent, Attrs: []slog.Attr{slog.String("preset", "p")}}

	r := slog.NewRecord(time.Now(), slog.LevelInfo, "m", 0)
	r.AddAttrs(slog.String("k", "v"))
	require.NoError(t, sub.Handle(context.Background(), r))

	// slog 契约：handler 不得修改调用方的记录——原记录的属性集不变。
	require.Equal(t, 1, r.NumAttrs(), "caller record attr count unchanged")
	r.Attrs(func(a slog.Attr) bool {
		require.Equal(t, "k", a.Key, "caller record attr key unchanged")
		return true
	})
	// 转发记录携带预设属性 + 记录属性。
	require.Len(t, parent.records, 1, "one record forwarded")
	require.Len(t, parent.attrs[0], 2, "preset + record attrs forwarded")
}

func TestAttrsSub_WithGroupEmptyNameNoop(t *testing.T) {
	parent := &captureHandler{}
	sub := &AttrsSub{Parent: parent, Attrs: []slog.Attr{slog.String("a", "1")}}
	require.Equal(t, sub, sub.WithGroup(""), "WithGroup(\"\") must return receiver")
}

func TestGroupSub_HandlePrefixesRecordAttrs(t *testing.T) {
	parent := &captureHandler{}
	sub := &GroupSub{Parent: parent, Group: "g", Attrs: []slog.Attr{slog.String("preset", "p")}}

	r := slog.NewRecord(time.Now(), slog.LevelInfo, "m", 0)
	r.AddAttrs(slog.String("k", "v"))
	require.NoError(t, sub.Handle(context.Background(), r))

	require.Len(t, parent.attrs[0], 2, "prefixed record attr + preset attr")
	require.Equal(t, "g.k", parent.attrs[0][0].Key, "record attr prefixed")
	require.Equal(t, "preset", parent.attrs[0][1].Key, "preset attr at root (pre-group)")
}

// =============================================================================
// SafeLevel / IsNilLeveler 测试
// =============================================================================

func TestIsNilLeveler(t *testing.T) {
	require.True(t, IsNilLeveler(nil), "nil interface")
	require.True(t, IsNilLeveler((*slog.Level)(nil)), "typed nil *slog.Level")
	require.True(t, IsNilLeveler((*slog.LevelVar)(nil)), "typed nil *slog.LevelVar")
	require.False(t, IsNilLeveler(slog.LevelInfo), "value slog.Level")
	require.False(t, IsNilLeveler(new(slog.LevelVar)), "live *slog.LevelVar")
}

func TestSafeLevel(t *testing.T) {
	require.Equal(t, slog.LevelInfo, SafeLevel(nil), "nil → Info")
	require.Equal(t, slog.LevelInfo, SafeLevel((*slog.Level)(nil)), "typed nil → Info, no panic")
	require.Equal(t, slog.LevelWarn, SafeLevel(slog.LevelWarn), "plain level passthrough")
	lv := new(slog.LevelVar)
	lv.Set(slog.LevelError)
	require.Equal(t, slog.LevelError, SafeLevel(lv), "LevelVar resolved")
}

// =============================================================================
// LevelGate 测试
// =============================================================================

func TestLevelGate_Enabled(t *testing.T) {
	g := NewLevelGate(slog.LevelWarn)
	require.False(t, g.Enabled(slog.LevelInfo), "below threshold")
	require.True(t, g.Enabled(slog.LevelWarn), "at threshold")
	require.True(t, g.Enabled(slog.LevelError), "above threshold")

	// 零值：nil Leveler → Info 门限，不 panic。
	var zero LevelGate
	require.False(t, zero.Enabled(slog.LevelDebug), "zero gate: Debug below Info")
	require.True(t, zero.Enabled(slog.LevelInfo), "zero gate: Info at threshold")
}

func TestLevelGate_Set(t *testing.T) {
	// 固定级别：不可热调，返回 false（SetLevel 的 skipped 诚实面）。
	fixed := NewLevelGate(slog.LevelInfo)
	require.False(t, fixed.Set(slog.LevelError), "fixed level not hot-adjustable")

	// LevelVar：热调生效并反映在 Enabled 上。
	lv := new(slog.LevelVar)
	lv.Set(slog.LevelInfo)
	g := NewLevelGate(lv)
	require.True(t, g.Set(slog.LevelError), "LevelVar hot-adjustable")
	require.True(t, g.Enabled(slog.LevelError), "gate reflects new level")
	require.False(t, g.Enabled(slog.LevelWarn), "old threshold no longer passes")
}

// =============================================================================
// ErrorSlot 测试
// =============================================================================

func TestErrorSlot(t *testing.T) {
	var got *HandlerError
	fn := ErrorHandler(func(he *HandlerError) { got = he })

	s := NewErrorSlot(fn)
	require.NotNil(t, s.Load(), "initial value stored")

	s.Report(&HandlerError{Component: "test", Operation: "op", Err: errors.New("boom")})
	require.NotNil(t, got, "handler invoked")
	require.Equal(t, "test", got.Component, "component")
	require.False(t, got.Time.IsZero(), "Time filled by Report")

	// 热换后新 handler 生效：重置第一阶段的记录再上报。
	got = nil
	var second *HandlerError
	s.Store(func(he *HandlerError) { second = he })
	s.Report(&HandlerError{Component: "t2", Err: errors.New("x")})
	require.Nil(t, got, "old handler not invoked after Store")
	require.NotNil(t, second, "new handler invoked")
	require.Equal(t, "t2", second.Component, "new handler received report")
}

func TestErrorSlot_ReportNilHandlerNoPanic(t *testing.T) {
	// 未初始化槽位（零值指针 Load 为 nil）：Report 静默丢弃而非 panic。
	s := new(ErrorSlot)
	require.Nil(t, s.Load(), "uninitialized slot loads nil")
	require.NotPanics(t, func() {
		s.Report(&HandlerError{Component: "x", Err: errors.New("y")})
	}, "Report with nil handler must not panic")
}

// =============================================================================
// RateGate 测试
// =============================================================================

func TestRateGate_FirstAllowThenThrottle(t *testing.T) {
	var g RateGate
	require.True(t, g.Allow(), "cold gate allows first call")
	require.False(t, g.Allow(), "second call within interval throttled")
}

func TestRateGate_ConcurrentSingleWinner(t *testing.T) {
	var g RateGate
	var winners atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if g.Allow() {
				winners.Add(1)
			}
		}()
	}
	wg.Wait()
	require.Equal(t, int64(1), winners.Load(), "exactly one winner per interval under contention")
}
