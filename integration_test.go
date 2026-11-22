package mebsuta

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"math"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/iuboy/mebsuta/filerotate"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// 黑盒集成测试 — 只使用公开 API，模拟用户调用
// =============================================================================

// captureLog 记录单条 slog.Record 的内容
type capturedLog struct {
	Level   slog.Level
	Message string
	Attrs   []slog.Attr
}

// integrationCtxKey is an unexported context key type to avoid collisions
// with other packages using the same key string (see SA1029).
type integrationCtxKey string

const requestIDKey integrationCtxKey = "request_id"

// captureSink 收集日志记录，用于测试断言
type captureSink struct {
	mu      sync.Mutex
	records []capturedLog
}

func (s *captureSink) add(r slog.Record) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var attrs []slog.Attr
	r.Attrs(func(a slog.Attr) bool {
		attrs = append(attrs, a)
		return true
	})
	s.records = append(s.records, capturedLog{Level: r.Level, Message: r.Message, Attrs: attrs})
}

func (s *captureSink) len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.records)
}

func (s *captureSink) message(i int) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.records[i].Message
}

func (s *captureSink) hasAttr(i int, key, val string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, a := range s.records[i].Attrs {
		if a.Key == key && a.Value.String() == val {
			return true
		}
	}
	return false
}

func (s *captureSink) reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records = nil
}

// captureHandler 是一个 slog.Handler，将记录收集到 captureSink
type captureHandler struct {
	sink   *captureSink
	level  slog.Level
	closed atomic.Bool
	preset []slog.Attr
}

func newCaptureHandler() *captureHandler {
	return &captureHandler{sink: &captureSink{}, level: slog.LevelDebug}
}

func (h *captureHandler) Enabled(_ context.Context, l slog.Level) bool { return l >= h.level }
func (h *captureHandler) Handle(_ context.Context, r slog.Record) error {
	if len(h.preset) == 0 {
		h.sink.add(r)
		return nil
	}
	merged := slog.NewRecord(r.Time, r.Level, r.Message, r.PC)
	merged.AddAttrs(append(slices.Clone(h.preset), rAttrs(r)...)...)
	h.sink.add(merged)
	return nil
}

func rAttrs(r slog.Record) []slog.Attr {
	var a []slog.Attr
	r.Attrs(func(attr slog.Attr) bool { a = append(a, attr); return true })
	return a
}
func (h *captureHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &captureHandler{sink: h.sink, level: h.level, preset: append(h.preset, attrs...)}
}
func (h *captureHandler) WithGroup(name string) slog.Handler { return h }
func (h *captureHandler) Close() error                       { h.closed.Store(true); return nil }

// =============================================================================
// 集成测试用例
// =============================================================================

// TestIntegration_New_DefaultLogger 验证 New() 零配置返回可用 logger
func TestIntegration_New_DefaultLogger(t *testing.T) {
	logger, err := New()
	require.NoError(t, err, "New() error")
	require.NotNil(t, logger, "New() returned nil logger")
	defer func() { _ = CloseAll(logger.Handler()) }()

	logger.Info("test message", "key", "value")
}

// TestIntegration_Init_SetsDefault 验证 Init() 设置 slog.Default()
func TestIntegration_Init_SetsDefault(t *testing.T) {
	logger, err := Init()
	require.NoError(t, err, "Init() error")
	defer func() { _ = CloseAll(logger.Handler()) }()

	require.Equal(t, logger, slog.Default(), "Init() did not set slog.Default()")
}

// TestIntegration_UseStdout 验证 stdout 输出不 panic
func TestIntegration_UseStdout(t *testing.T) {
	logger, err := New(UseStdout(StdoutConfig{}))
	require.NoError(t, err, "New(UseStdout) error")
	defer func() { _ = CloseAll(logger.Handler()) }()

	logger.Info("stdout test")
}

// TestIntegration_UseFile_WritesToDisk 验证文件写入和 JSON 格式契约
func TestIntegration_UseFile_WritesToDisk(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "test.log")

	logger, err := New(
		UseFile(filerotate.Config{Path: logPath}, FileConfig{Level: slog.LevelDebug}),
	)
	require.NoError(t, err, "New(UseFile) error")

	logger.Info("file test", "key", "value", "count", 42)
	_ = CloseAll(logger.Handler())

	data, err := os.ReadFile(logPath)
	require.NoError(t, err, "read log file")
	require.NotEmpty(t, data, "log file is empty")

	var record map[string]any
	require.NoError(t, json.Unmarshal(data, &record), "invalid JSON")

	for _, key := range []string{"time", "level", "message", "attributes"} {
		require.Contains(t, record, key, "missing required field")
	}
	require.Equal(t, "file test", record["message"], "message")
	require.Equal(t, "INFO", record["level"], "level")
}

// TestIntegration_UseFile_ConsoleFormat 验证 console 格式输出
func TestIntegration_UseFile_ConsoleFormat(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "console.log")

	logger, err := New(
		UseFile(filerotate.Config{Path: logPath}, FileConfig{
			Level:  slog.LevelInfo,
			Format: "console",
		}),
	)
	require.NoError(t, err, "New(UseFile console) error")

	logger.Info("console message", "status", "ok")
	_ = CloseAll(logger.Handler())

	data, err := os.ReadFile(logPath)
	require.NoError(t, err, "read log")
	require.Contains(t, string(data), "console message", "console output missing message")
}

// TestIntegration_LevelFiltering 验证级别过滤（用 capture handler）
func TestIntegration_LevelFiltering(t *testing.T) {
	ch := newCaptureHandler()
	ch.level = slog.LevelInfo

	logger, err := New(WithHandler(ch))
	require.NoError(t, err, "New() error")

	logger.Debug("filtered")
	logger.Info("passed")

	require.Equal(t, 1, ch.sink.len(), "captured records")
	require.Equal(t, "passed", ch.sink.message(0), "message")
}

// TestIntegration_MultipleOutputs 验证多输出扇出
func TestIntegration_MultipleOutputs(t *testing.T) {
	ch1 := newCaptureHandler()
	ch2 := newCaptureHandler()

	logger, err := New(WithHandler(ch1), WithHandler(ch2))
	require.NoError(t, err, "New() error")

	logger.Info("multi output", "key", "val")
	_ = CloseAll(logger.Handler())

	require.Equal(t, 1, ch1.sink.len(), "capture1")
	require.Equal(t, 1, ch2.sink.len(), "capture2")
}

// TestIntegration_AsyncHandler 验证异步写入最终到达 inner handler
func TestIntegration_AsyncHandler(t *testing.T) {
	ch := newCaptureHandler()
	logger, err := New(
		UseAsync(AsyncConfig{BufferSize: 64}),
		WithHandler(ch),
	)
	require.NoError(t, err, "New() error")

	const n = 50
	for i := range n {
		logger.Info("async message", "i", i)
	}
	_ = CloseAll(logger.Handler())

	require.GreaterOrEqual(t, ch.sink.len(), n, "captured records")
}

// TestIntegration_SamplingHandler 验证采样行为
func TestIntegration_SamplingHandler(t *testing.T) {
	ch := newCaptureHandler()
	logger, err := New(
		UseSampling(SamplingConfig{
			Enabled:    true,
			Initial:    10,
			Thereafter: 100,
			Window:     time.Minute,
		}),
		WithHandler(ch),
	)
	require.NoError(t, err, "New() error")

	for range 10 {
		logger.Info("sampled")
	}
	require.Equal(t, 10, ch.sink.len(), "initial")

	// Error 级别不受采样限制
	ch.sink.reset()
	logger.Error("always recorded")
	require.Equal(t, 1, ch.sink.len(), "error sampled")

	_ = CloseAll(logger.Handler())
}

// TestIntegration_ContextExtractor 验证上下文字段提取
func TestIntegration_ContextExtractor(t *testing.T) {
	ch := newCaptureHandler()
	logger, err := New(
		UseContextExtractor(func(ctx context.Context) []slog.Attr {
			if reqID, ok := ctx.Value(requestIDKey).(string); ok {
				return []slog.Attr{slog.String("request_id", reqID)}
			}
			return nil
		}),
		WithHandler(ch),
	)
	require.NoError(t, err, "New() error")

	ctx := context.WithValue(context.Background(), requestIDKey, "req-123")
	logger.InfoContext(ctx, "with context")
	_ = CloseAll(logger.Handler())

	require.Equal(t, 1, ch.sink.len(), "captured")
	require.True(t, ch.sink.hasAttr(0, "request_id", "req-123"), "missing request_id attribute")
}

// TestIntegration_MetricsDecorator 验证指标收集
func TestIntegration_MetricsDecorator(t *testing.T) {
	ch := newCaptureHandler()
	var handleCount atomic.Int64

	metrics := &integrationMetrics{
		onHandle:  func() { handleCount.Add(1) },
		onError:   func() {},
		onDropped: func() {},
	}

	logger, err := New(
		UseMetrics(metrics, "test"),
		WithHandler(ch),
	)
	require.NoError(t, err, "New() error")

	logger.Info("metric test")
	logger.Warn("another")
	_ = CloseAll(logger.Handler())

	require.Equal(t, int64(2), handleCount.Load(), "handle count")
	require.Equal(t, 2, ch.sink.len(), "captured")
}

// TestIntegration_ErrorHandler 验证自定义错误处理不 panic
func TestIntegration_ErrorHandler(t *testing.T) {
	logger, err := New(
		WithErrorHandler(func(he *HandlerError) {}),
		UseStdout(StdoutConfig{}),
	)
	require.NoError(t, err, "New() error")
	defer func() { _ = CloseAll(logger.Handler()) }()

	logger.Info("with error handler")
}

// TestIntegration_SilentErrorHandler 验证静默错误处理不 panic
func TestIntegration_SilentErrorHandler(t *testing.T) {
	logger, err := New(
		WithErrorHandler(SilentErrorHandler()),
		UseStdout(StdoutConfig{}),
	)
	require.NoError(t, err, "New() error")
	defer func() { _ = CloseAll(logger.Handler()) }()

	logger.Info("silent handler test")
}

// TestIntegration_FullChain 验证完整生产链：stdout + file + sampling + async
func TestIntegration_FullChain(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "chain.log")

	logger, err := New(
		UseStdout(StdoutConfig{}),
		UseFile(filerotate.Config{Path: logPath}, FileConfig{Level: slog.LevelDebug}),
		UseSampling(SamplingConfig{
			Enabled:    true,
			Initial:    100,
			Thereafter: 10,
			Window:     time.Second,
		}),
		UseAsync(AsyncConfig{BufferSize: 256}),
	)
	require.NoError(t, err, "New(full chain) error")

	slog.SetDefault(logger)
	for i := range 20 {
		slog.Info("chain test", "i", i)
	}

	require.NoError(t, CloseAll(logger.Handler()), "CloseAll error")

	data, err := os.ReadFile(logPath)
	require.NoError(t, err, "read log")
	require.NotEmpty(t, data, "chain log file is empty")

	// 验证每行都是有效 JSON
	lines := bytes.Split(bytes.TrimSpace(data), []byte("\n"))
	for i, line := range lines {
		var v map[string]any
		require.NoError(t, json.Unmarshal(line, &v), "line %d: invalid JSON", i)
	}
}

// TestIntegration_ConcurrentWrites 验证并发写入安全
func TestIntegration_ConcurrentWrites(t *testing.T) {
	ch := newCaptureHandler()
	logger, err := New(WithHandler(ch))
	require.NoError(t, err, "New() error")

	const goroutines = 50
	const perGoroutine = 10
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for g := range goroutines {
		go func() {
			defer wg.Done()
			for i := range perGoroutine {
				logger.Info("concurrent", "goroutine", g, "i", i)
			}
		}()
	}
	wg.Wait()

	require.Equal(t, goroutines*perGoroutine, ch.sink.len(), "captured")
	_ = CloseAll(logger.Handler())
}

// TestIntegration_CloseAll_Idempotent 验证 CloseAll 幂等性
func TestIntegration_CloseAll_Idempotent(t *testing.T) {
	ch := newCaptureHandler()
	logger, err := New(WithHandler(ch))
	require.NoError(t, err, "New() error")

	h := logger.Handler()
	require.NoError(t, CloseAll(h), "first CloseAll error")
	require.NoError(t, CloseAll(h), "second CloseAll error")
}

// TestIntegration_NonFiniteFloats 验证 NaN/Inf 产生有效 JSON
func TestIntegration_NonFiniteFloats(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "nan.log")

	logger, err := New(
		UseFile(filerotate.Config{Path: logPath}, FileConfig{}),
	)
	require.NoError(t, err, "New() error")

	logger.Info("nan test",
		"nan", math.NaN(),
		"pos_inf", math.Inf(1),
		"neg_inf", math.Inf(-1),
		"normal", 3.14,
	)
	_ = CloseAll(logger.Handler())

	data, err := os.ReadFile(logPath)
	require.NoError(t, err, "read log")

	var record map[string]any
	require.NoError(t, json.Unmarshal(data, &record), "invalid JSON (NaN/Inf handling failed), raw: %s", data)
}

// TestIntegration_FileRotation 验证文件大小轮转
func TestIntegration_FileRotation(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "rotate.log")

	logger, err := New(
		UseFile(filerotate.Config{
			Path:       logPath,
			MaxSizeMB:  1,
			MaxBackups: 2,
		}, FileConfig{Level: slog.LevelDebug}),
	)
	require.NoError(t, err, "New() error")

	for i := range 50000 {
		logger.Info("rotation pressure test", "data", "padding-content-to-trigger-rotation", "i", i)
	}
	_ = CloseAll(logger.Handler())

	entries, err := os.ReadDir(dir)
	require.NoError(t, err, "read dir")

	hasBackup := false
	for _, e := range entries {
		if e.Name() != "rotate.log" {
			hasBackup = true
			break
		}
	}
	require.True(t, hasBackup, "expected backup files after rotation, found none")
}

// TestIntegration_WithAttrsPropagation 验证 logger.With 属性传播
func TestIntegration_WithAttrsPropagation(t *testing.T) {
	ch := newCaptureHandler()
	logger, err := New(WithHandler(ch))
	require.NoError(t, err, "New() error")

	child := logger.With("request_id", "abc-123")
	child.Info("with attrs")

	require.Equal(t, 1, ch.sink.len(), "captured")
	require.True(t, ch.sink.hasAttr(0, "request_id", "abc-123"), "missing request_id attribute in child logger")
	_ = CloseAll(logger.Handler())
}

// TestIntegration_SlogDefaultInterop 验证与 slog.Default() 互操作
func TestIntegration_SlogDefaultInterop(t *testing.T) {
	ch := newCaptureHandler()
	logger, err := New(WithHandler(ch))
	require.NoError(t, err, "New() error")

	original := slog.Default()
	slog.SetDefault(logger)
	defer slog.SetDefault(original)

	slog.Info("via slog.Default()")
	slog.Warn("warn via default", "code", 404)

	require.Equal(t, 2, ch.sink.len(), "captured")
	require.Equal(t, "via slog.Default()", ch.sink.message(0), "message[0]")
	require.Equal(t, "warn via default", ch.sink.message(1), "message[1]")
	_ = CloseAll(logger.Handler())
}

// TestIntegration_Ptr 验证泛型 Ptr 辅助函数
func TestIntegration_Ptr(t *testing.T) {
	p := Ptr(true)
	require.NotNil(t, p, "Ptr(true) returned nil")
	require.True(t, *p, "Ptr(true) returned false")
	p2 := Ptr(false)
	require.NotNil(t, p2, "Ptr(false) returned nil")
	require.False(t, *p2, "Ptr(false) returned true")
	n := Ptr(42)
	require.Equal(t, 42, *n, "Ptr(42)")
}

// TestIntegration_AuditLevelInChain 验证审计级别在装饰器链中不受采样限制
func TestIntegration_AuditLevelInChain(t *testing.T) {
	ch := newCaptureHandler()
	logger, err := New(
		UseSampling(SamplingConfig{
			Enabled:    true,
			Initial:    0, // 0 initial，所有常规记录被采样
			Thereafter: 1000,
			Window:     time.Minute,
		}),
		WithHandler(ch),
	)
	require.NoError(t, err, "New() error")

	// Error 级别应始终通过采样
	logger.Error("must pass sampling")
	require.Equal(t, 1, ch.sink.len(), "error through sampling")

	_ = CloseAll(logger.Handler())
}

// integrationMetrics 实现 HandlerMetrics 接口
type integrationMetrics struct {
	onHandle  func()
	onError   func()
	onDropped func()
}

func (m *integrationMetrics) ObserveHandle(duration time.Duration)    { m.onHandle() }
func (m *integrationMetrics) IncError(handlerName string)             { m.onError() }
func (m *integrationMetrics) IncDroppedN(handlerName string, n int64) { m.onDropped() }

var _ HandlerMetrics = (*integrationMetrics)(nil)
