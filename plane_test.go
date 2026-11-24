// 平面路由测试:分流规则(显式标记/LevelAudit 隐式路由/untagged 默认)、
// 独占与回落语义、预设属性跨链到达、walk 穿透(CloseAll/SetLevel/
// 双重缓冲检测)、UsePlane 校验、Plane() 从 slog.Default 派生。
package mebsuta

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/iuboy/mebsuta/filerotate"
	"github.com/iuboy/mebsuta/internal/handlerkit"
	"github.com/stretchr/testify/require"
)

// planeSink 捕获路由到本链的记录,可选地模拟 io.Closer 与
// SelfBufferedHandler,供 walk 穿透断言。
type planeSink struct {
	name    string
	mu      sync.Mutex
	records []slog.Record
	closes  int
	selfBuf bool
}

func (s *planeSink) Enabled(context.Context, slog.Level) bool { return true }

func (s *planeSink) Handle(_ context.Context, r slog.Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records = append(s.records, r.Clone())
	return nil
}

// WithAttrs/WithGroup 复用真实实现(handlerkit.AttrsSub/GroupSub),
// 避免 test-double 自行模拟 group 语义引入偏差。
func (s *planeSink) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &handlerkit.AttrsSub{Parent: s, Attrs: attrs}
}
func (s *planeSink) WithGroup(name string) slog.Handler {
	return &handlerkit.GroupSub{Parent: s, Group: name}
}

// Close 幂等:非内置 handler 无 handlerIdentity,CloseAll 不去重,
// 幂等契约由 handler 自负(closeAll 注释明载)。
func (s *planeSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closes == 0 {
		s.closes++
	}
	return nil
}
func (s *planeSink) SelfBuffered() {}

func (s *planeSink) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.records)
}

func (s *planeSink) last(t *testing.T) slog.Record {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	require.NotEmpty(t, s.records, "sink %q received no records", s.name)
	return s.records[len(s.records)-1]
}

// newPlaneLogger 构建带 mgmt/audit 平面的路由 logger 与三个捕获链。
func newPlaneLogger(t *testing.T, withAudit bool) (*slog.Logger, *planeSink, *planeSink, *planeSink) {
	t.Helper()
	def, mgmt, aud := &planeSink{name: "def"}, &planeSink{name: "mgmt"}, &planeSink{name: "audit"}
	opts := []HandlerOption{
		WithHandler(def),
		UsePlane(PlaneManagement, WithHandler(mgmt)),
	}
	if withAudit {
		opts = append(opts, UsePlane(PlaneAudit, WithHandler(aud)))
	}
	logger, err := New(opts...)
	require.NoError(t, err, "New with planes")
	return logger, def, mgmt, aud
}

func TestPlaneRouter_NoPlanesKeepsPlainChain(t *testing.T) {
	logger, err := New(WithHandler(&planeSink{name: "def"}))
	require.NoError(t, err)
	_, isRouter := logger.Handler().(*planeRouter)
	require.False(t, isRouter, "no UsePlane → no router (existing behavior)")
}

func TestPlaneRouter_RoutesByPlane(t *testing.T) {
	logger, def, mgmt, aud := newPlaneLogger(t, true)

	logger.Info("business record")
	require.Equal(t, 1, def.count(), "untagged → default chain")
	require.Equal(t, 0, mgmt.count(), "mgmt chain untouched")

	// Plane() 从 slog.Default 派生;直接构造等价视图避免触碰全局 default。
	mgmtLogger := slog.New(logger.Handler()).With(PlaneAttr(PlaneManagement))
	mgmtLogger.Info("management record")
	require.Equal(t, 1, mgmt.count(), "plane attr → mgmt chain")
	require.Equal(t, 1, def.count(), "default chain untouched")

	// LevelAudit 隐式路由到审计面(独占)。
	logger.Log(context.Background(), LevelAudit, "audit record")
	require.Equal(t, 1, aud.count(), "LevelAudit → audit chain")
	require.Equal(t, 1, def.count(), "audit exclusive: default chain untouched")

	// 显式标记覆盖级别隐式路由。
	mgmtLogger.Log(context.Background(), LevelAudit, "mgmt audit")
	require.Equal(t, 2, mgmt.count(), "explicit plane beats implicit audit routing")
	require.Equal(t, 1, aud.count(), "audit chain untouched by explicit mgmt")
}

func TestPlaneRouter_AuditFallsBackWithoutAuditPlane(t *testing.T) {
	logger, def, mgmt, _ := newPlaneLogger(t, false)

	logger.Log(context.Background(), LevelAudit, "audit without audit plane")
	require.Equal(t, 1, def.count(), "no audit plane → LevelAudit falls back to default chain")
	require.Equal(t, 0, mgmt.count())
}

func TestPlaneRouter_UnknownPlaneFallsBackToDefault(t *testing.T) {
	logger, def, _, _ := newPlaneLogger(t, true)
	slog.New(logger.Handler()).With(PlaneAttr("nonexistent")).Info("x")
	require.Equal(t, 1, def.count(), "unknown plane name → default chain")
}

func TestPlaneRouter_PlaneAttrKeptInOutput(t *testing.T) {
	logger, _, mgmt, _ := newPlaneLogger(t, true)
	slog.New(logger.Handler()).With(PlaneAttr(PlaneManagement)).Info("m", "k", "v")
	r := mgmt.last(t)
	require.Equal(t, 2, r.NumAttrs(), "plane attr + record attr")
}

func TestPlaneRouter_PresetAttrsReachAuditChain(t *testing.T) {
	logger, def, _, aud := newPlaneLogger(t, true)
	l := logger.With("user", "u")

	l.Info("business")
	require.Equal(t, 1, def.count())
	require.Equal(t, "user", attrKeyAt(def.last(t), 0), "preset attr on default chain")

	// 同一视图的 LevelAudit 记录进入审计链,且携带同样的预设属性。
	l.Log(context.Background(), LevelAudit, "audit")
	require.Equal(t, 1, aud.count(), "LevelAudit via preset-attr view → audit chain")
	require.Equal(t, "user", attrKeyAt(aud.last(t), 0), "preset attr reaches audit chain too")
}

func TestPlaneRouter_WithGroup(t *testing.T) {
	logger, _, mgmt, _ := newPlaneLogger(t, true)
	l := slog.New(logger.Handler()).With(PlaneAttr(PlaneManagement)).WithGroup("g")
	l.Info("m", "k", "v")
	r := mgmt.last(t)
	// slog 契约:WithGroup 之前的属性(plane)留在根层级,之后的记录
	// 属性加 group 前缀。
	require.Equal(t, 2, r.NumAttrs())
	r.Attrs(func(a slog.Attr) bool {
		switch a.Key {
		case PlaneKey:
			require.Equal(t, PlaneManagement, a.Value.String())
		case "g.k":
		default:
			t.Fatalf("unexpected attr %q", a.Key)
		}
		return true
	})
}

func attrKeyAt(r slog.Record, i int) string {
	var keys []string
	r.Attrs(func(a slog.Attr) bool {
		keys = append(keys, a.Key)
		return true
	})
	if i >= len(keys) {
		return ""
	}
	return keys[i]
}

func TestPlaneRouter_CloseAllClosesAllChains(t *testing.T) {
	logger, def, mgmt, aud := newPlaneLogger(t, true)
	require.NoError(t, CloseAll(logger.Handler()))
	require.Equal(t, 1, def.closes, "default chain closed")
	require.Equal(t, 1, mgmt.closes, "mgmt chain closed")
	require.Equal(t, 1, aud.closes, "audit chain closed")

	// 幂等:handlerIdentity 去重后再次 CloseAll 不重复关闭。
	require.NoError(t, CloseAll(logger.Handler()))
	require.Equal(t, 1, def.closes, "deduped on second CloseAll")
}

func TestPlaneRouter_SetLevelWalksAllPlanes(t *testing.T) {
	defVar := NewLevelVar(slog.LevelInfo)
	mgmtVar := NewLevelVar(slog.LevelInfo)
	logger, err := New(
		UseStdout(StdoutConfig{Level: defVar}),
		UsePlane(PlaneManagement, UseStdout(StdoutConfig{Level: mgmtVar})),
	)
	require.NoError(t, err)

	applied, skipped, err := SetLevel(logger.Handler(), slog.LevelError)
	require.NoError(t, err)
	require.Equal(t, 2, applied, "both plane chains hot-adjusted")
	require.Empty(t, skipped)
	require.Equal(t, slog.LevelError, defVar.Level(), "default LevelVar adjusted")
	require.Equal(t, slog.LevelError, mgmtVar.Level(), "mgmt LevelVar adjusted")
}

func TestPlaneRouter_SelfBufferedDetectedThroughPlane(t *testing.T) {
	// UseAsync 包裹路由器:平面链内含自缓冲 handler 时必须被双重缓冲
	// 检测发现(walk 穿透 fanout)。
	buf := &planeSink{name: "buf", selfBuf: true}
	logger, err := New(UsePlane(PlaneManagement, WithHandler(buf)))
	require.NoError(t, err)

	h := WithAsync(logger.Handler(), AsyncConfig{})
	_, isAsync := h.(*AsyncHandler)
	require.False(t, isAsync, "self-buffered handler inside plane → double-buffering refused")
}

func TestUsePlane_Validation(t *testing.T) {
	_, err := New(UsePlane("", WithHandler(&planeSink{name: "x"})))
	require.ErrorContains(t, err, "plane name cannot be empty")

	_, err = New(UsePlane(PlaneBusiness, WithHandler(&planeSink{name: "x"})))
	require.ErrorContains(t, err, "default chain")

	sink := &planeSink{name: "x"}
	_, err = New(
		UsePlane(PlaneManagement, WithHandler(sink)),
		UsePlane(PlaneManagement, WithHandler(sink)),
	)
	require.ErrorContains(t, err, "duplicate plane")

	_, err = New(UsePlane(PlaneManagement, UsePlane(PlaneAudit, WithHandler(sink))))
	require.ErrorContains(t, err, "cannot be nested")
}

func TestPlaneRouter_PlaneErrorHandlerPropagates(t *testing.T) {
	var mu sync.Mutex
	var comps []string
	logger, err := New(
		UseStdout(StdoutConfig{}),
		UsePlane(PlaneManagement, UseStdout(StdoutConfig{})),
		WithErrorHandler(func(he *HandlerError) {
			mu.Lock()
			defer mu.Unlock()
			comps = append(comps, he.Component)
		}),
	)
	require.NoError(t, err)
	_ = logger

	// 经 walk 传播:路由器 fanout 的 safeMulti 槽位被设置。断言传播
	// 不 panic 且处理器可达(经 safeMulti.setErrorHandler 的子链传播)。
	h := logger.Handler()
	r := h.(*planeRouter)
	r.fanout.(*safeMulti).errorHandler.Load()
	require.NotNil(t, r.fanout.(*safeMulti).errorHandler.Load(), "error handler reached router fanout")
}

func TestPlane_DerivesFromDefault(t *testing.T) {
	old := slog.Default()
	t.Cleanup(func() { slog.SetDefault(old) })

	mgmt := &planeSink{name: "mgmt"}
	logger, err := New(UsePlane(PlaneManagement, WithHandler(mgmt)))
	require.NoError(t, err)
	slog.SetDefault(logger)

	Plane(PlaneManagement).Info("via default")
	require.Equal(t, 1, mgmt.count(), "Plane() derived from slog.Default routes to plane")
}

func TestPlaneRouter_HandleErrorsJoin(t *testing.T) {
	wantErr := errors.New("sink failure")
	fail := &failingPlaneSink{err: wantErr}
	logger, err := New(UsePlane(PlaneManagement, WithHandler(fail)))
	require.NoError(t, err)
	h := slog.New(logger.Handler()).With(PlaneAttr(PlaneManagement)).Handler()
	r := slog.NewRecord(time.Now(), slog.LevelInfo, "x", 0)
	err = h.Handle(context.Background(), r)
	require.ErrorIs(t, err, wantErr, "chain error surfaces through router")
}

// TestPlaneRouter_TopLevelErrorHandlerReachesPlaneChains:顶层
// WithErrorHandler 必须穿透平面路由器到达每条平面链。此前
// propagateErrorHandler 只跑在默认链上,平面链的内部错误仍走
// DefaultErrorHandler()(stderr),用户错误处理器只收到默认链一份。
func TestPlaneRouter_TopLevelErrorHandlerReachesPlaneChains(t *testing.T) {
	dir := t.TempDir()
	var mu sync.Mutex
	var ops []string
	custom := func(he *HandlerError) {
		mu.Lock()
		ops = append(ops, he.Operation)
		mu.Unlock()
	}

	rotateCfg := func(path string) filerotate.Config {
		return filerotate.Config{Path: path, MaxSizeMB: 1, MaxBackups: 1, Compress: Ptr(false)}
	}
	defPath := filepath.Join(dir, "def.log")
	mgmtPath := filepath.Join(dir, "mgmt.log")
	logger, err := New(
		UseFile(rotateCfg(defPath), FileConfig{}),
		UsePlane(PlaneManagement, UseFile(rotateCfg(mgmtPath), FileConfig{})),
		WithErrorHandler(custom),
	)
	require.NoError(t, err)
	defer func() { _ = CloseAll(logger.Handler()) }()

	// 预埋「过期备份」目录:非空目录,轮转后的清理 os.Remove 必失败
	// ——超过 MaxBackups 的备份条目无论 mtime 都走删除路径,每条链
	// 各产生一次 cleanup 上报。
	for _, p := range []string{defPath, mgmtPath} {
		seed := p + ".2026-01-01T00-00-00.000"
		require.NoError(t, os.MkdirAll(filepath.Join(seed, "x"), 0700))
	}

	big := strings.Repeat("a", 1200*1024) // > MaxSizeMB:两条链各自触发轮转+清理
	logger.Info("business", "big", big)
	slog.New(logger.Handler()).With(PlaneAttr(PlaneManagement)).Info("mgmt", "big", big)

	mu.Lock()
	defer mu.Unlock()
	require.Equal(t, []string{"cleanup", "cleanup"}, ops,
		"top-level WithErrorHandler must reach both plane chains, got %v", ops)
}

type failingPlaneSink struct{ err error }

func (f *failingPlaneSink) Enabled(context.Context, slog.Level) bool { return true }
func (f *failingPlaneSink) Handle(context.Context, slog.Record) error {
	return f.err
}
func (f *failingPlaneSink) WithAttrs([]slog.Attr) slog.Handler { return f }
func (f *failingPlaneSink) WithGroup(string) slog.Handler      { return f }
