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
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	if logger == nil {
		t.Fatal("New() returned nil logger")
	}
	defer func() { _ = CloseAll(logger.Handler()) }()

	logger.Info("test message", "key", "value")
}

// TestIntegration_Init_SetsDefault 验证 Init() 设置 slog.Default()
func TestIntegration_Init_SetsDefault(t *testing.T) {
	logger, err := Init()
	if err != nil {
		t.Fatalf("Init() error: %v", err)
	}
	defer func() { _ = CloseAll(logger.Handler()) }()

	if slog.Default() != logger {
		t.Error("Init() did not set slog.Default()")
	}
}

// TestIntegration_UseStdout 验证 stdout 输出不 panic
func TestIntegration_UseStdout(t *testing.T) {
	logger, err := New(UseStdout(StdoutConfig{}))
	if err != nil {
		t.Fatalf("New(UseStdout) error: %v", err)
	}
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
	if err != nil {
		t.Fatalf("New(UseFile) error: %v", err)
	}

	logger.Info("file test", "key", "value", "count", 42)
	_ = CloseAll(logger.Handler())

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read log file: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("log file is empty")
	}

	var record map[string]any
	if err := json.Unmarshal(data, &record); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	for _, key := range []string{"time", "level", "message", "attributes"} {
		if _, ok := record[key]; !ok {
			t.Errorf("missing required field: %s", key)
		}
	}
	if record["message"] != "file test" {
		t.Errorf("message = %v, want 'file test'", record["message"])
	}
	if record["level"] != "INFO" {
		t.Errorf("level = %v, want INFO", record["level"])
	}
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
	if err != nil {
		t.Fatalf("New(UseFile console) error: %v", err)
	}

	logger.Info("console message", "status", "ok")
	_ = CloseAll(logger.Handler())

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	if !bytes.Contains(data, []byte("console message")) {
		t.Errorf("console output missing message, got: %s", data)
	}
}

// TestIntegration_LevelFiltering 验证级别过滤（用 capture handler）
func TestIntegration_LevelFiltering(t *testing.T) {
	ch := newCaptureHandler()
	ch.level = slog.LevelInfo

	logger, err := New(WithHandler(ch))
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	logger.Debug("filtered")
	logger.Info("passed")

	if got := ch.sink.len(); got != 1 {
		t.Fatalf("captured %d records, want 1", got)
	}
	if msg := ch.sink.message(0); msg != "passed" {
		t.Errorf("message = %q, want 'passed'", msg)
	}
}

// TestIntegration_MultipleOutputs 验证多输出扇出
func TestIntegration_MultipleOutputs(t *testing.T) {
	ch1 := newCaptureHandler()
	ch2 := newCaptureHandler()

	logger, err := New(WithHandler(ch1), WithHandler(ch2))
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	logger.Info("multi output", "key", "val")
	_ = CloseAll(logger.Handler())

	if ch1.sink.len() != 1 || ch2.sink.len() != 1 {
		t.Errorf("capture1=%d capture2=%d, both want 1", ch1.sink.len(), ch2.sink.len())
	}
}

// TestIntegration_AsyncHandler 验证异步写入最终到达 inner handler
func TestIntegration_AsyncHandler(t *testing.T) {
	ch := newCaptureHandler()
	logger, err := New(
		UseAsync(AsyncConfig{BufferSize: 64}),
		WithHandler(ch),
	)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	const n = 50
	for i := range n {
		logger.Info("async message", "i", i)
	}
	_ = CloseAll(logger.Handler())

	if got := ch.sink.len(); got < n {
		t.Errorf("captured %d records, want at least %d", got, n)
	}
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
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	for range 10 {
		logger.Info("sampled")
	}
	if got := ch.sink.len(); got != 10 {
		t.Errorf("initial %d, want 10", got)
	}

	// Error 级别不受采样限制
	ch.sink.reset()
	logger.Error("always recorded")
	if got := ch.sink.len(); got != 1 {
		t.Errorf("error sampled=%d, want 1", got)
	}

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
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	ctx := context.WithValue(context.Background(), requestIDKey, "req-123")
	logger.InfoContext(ctx, "with context")
	_ = CloseAll(logger.Handler())

	if got := ch.sink.len(); got != 1 {
		t.Fatalf("captured %d, want 1", got)
	}
	if !ch.sink.hasAttr(0, "request_id", "req-123") {
		t.Error("missing request_id attribute")
	}
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
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	logger.Info("metric test")
	logger.Warn("another")
	_ = CloseAll(logger.Handler())

	if got := handleCount.Load(); got != 2 {
		t.Errorf("handle count = %d, want 2", got)
	}
	if got := ch.sink.len(); got != 2 {
		t.Errorf("captured %d, want 2", got)
	}
}

// TestIntegration_ErrorHandler 验证自定义错误处理不 panic
func TestIntegration_ErrorHandler(t *testing.T) {
	logger, err := New(
		WithErrorHandler(func(he *HandlerError) {}),
		UseStdout(StdoutConfig{}),
	)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer func() { _ = CloseAll(logger.Handler()) }()

	logger.Info("with error handler")
}

// TestIntegration_SilentErrorHandler 验证静默错误处理不 panic
func TestIntegration_SilentErrorHandler(t *testing.T) {
	logger, err := New(
		WithErrorHandler(SilentErrorHandler()),
		UseStdout(StdoutConfig{}),
	)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
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
	if err != nil {
		t.Fatalf("New(full chain) error: %v", err)
	}

	slog.SetDefault(logger)
	for i := range 20 {
		slog.Info("chain test", "i", i)
	}

	if err := CloseAll(logger.Handler()); err != nil {
		t.Errorf("CloseAll error: %v", err)
	}

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("chain log file is empty")
	}

	// 验证每行都是有效 JSON
	lines := bytes.Split(bytes.TrimSpace(data), []byte("\n"))
	for i, line := range lines {
		var v map[string]any
		if err := json.Unmarshal(line, &v); err != nil {
			t.Errorf("line %d: invalid JSON: %v", i, err)
		}
	}
}

// TestIntegration_ConcurrentWrites 验证并发写入安全
func TestIntegration_ConcurrentWrites(t *testing.T) {
	ch := newCaptureHandler()
	logger, err := New(WithHandler(ch))
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

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

	if got := ch.sink.len(); got != goroutines*perGoroutine {
		t.Errorf("captured %d, want %d", got, goroutines*perGoroutine)
	}
	_ = CloseAll(logger.Handler())
}

// TestIntegration_CloseAll_Idempotent 验证 CloseAll 幂等性
func TestIntegration_CloseAll_Idempotent(t *testing.T) {
	ch := newCaptureHandler()
	logger, err := New(WithHandler(ch))
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	h := logger.Handler()
	if err := CloseAll(h); err != nil {
		t.Errorf("first CloseAll error: %v", err)
	}
	if err := CloseAll(h); err != nil {
		t.Errorf("second CloseAll error: %v", err)
	}
}

// TestIntegration_NonFiniteFloats 验证 NaN/Inf 产生有效 JSON
func TestIntegration_NonFiniteFloats(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "nan.log")

	logger, err := New(
		UseFile(filerotate.Config{Path: logPath}, FileConfig{}),
	)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	logger.Info("nan test",
		"nan", math.NaN(),
		"pos_inf", math.Inf(1),
		"neg_inf", math.Inf(-1),
		"normal", 3.14,
	)
	_ = CloseAll(logger.Handler())

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}

	var record map[string]any
	if err := json.Unmarshal(data, &record); err != nil {
		t.Fatalf("invalid JSON (NaN/Inf handling failed): %v\nraw: %s", err, data)
	}
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
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	for i := range 50000 {
		logger.Info("rotation pressure test", "data", "padding-content-to-trigger-rotation", "i", i)
	}
	_ = CloseAll(logger.Handler())

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}

	hasBackup := false
	for _, e := range entries {
		if e.Name() != "rotate.log" {
			hasBackup = true
			break
		}
	}
	if !hasBackup {
		t.Error("expected backup files after rotation, found none")
	}
}

// TestIntegration_WithAttrsPropagation 验证 logger.With 属性传播
func TestIntegration_WithAttrsPropagation(t *testing.T) {
	ch := newCaptureHandler()
	logger, err := New(WithHandler(ch))
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	child := logger.With("request_id", "abc-123")
	child.Info("with attrs")

	if got := ch.sink.len(); got != 1 {
		t.Fatalf("captured %d, want 1", got)
	}
	if !ch.sink.hasAttr(0, "request_id", "abc-123") {
		t.Error("missing request_id attribute in child logger")
	}
	_ = CloseAll(logger.Handler())
}

// TestIntegration_SlogDefaultInterop 验证与 slog.Default() 互操作
func TestIntegration_SlogDefaultInterop(t *testing.T) {
	ch := newCaptureHandler()
	logger, err := New(WithHandler(ch))
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	original := slog.Default()
	slog.SetDefault(logger)
	defer slog.SetDefault(original)

	slog.Info("via slog.Default()")
	slog.Warn("warn via default", "code", 404)

	if got := ch.sink.len(); got != 2 {
		t.Fatalf("captured %d, want 2", got)
	}
	if ch.sink.message(0) != "via slog.Default()" {
		t.Errorf("message[0] = %q, want 'via slog.Default()'", ch.sink.message(0))
	}
	if ch.sink.message(1) != "warn via default" {
		t.Errorf("message[1] = %q, want 'warn via default'", ch.sink.message(1))
	}
	_ = CloseAll(logger.Handler())
}

// TestIntegration_BoolPtr 验证 BoolPtr 辅助函数
func TestIntegration_BoolPtr(t *testing.T) {
	p := BoolPtr(true)
	if p == nil || !*p {
		t.Error("BoolPtr(true) returned nil or false")
	}
	p2 := BoolPtr(false)
	if p2 == nil || *p2 {
		t.Error("BoolPtr(false) returned nil or true")
	}
}

// TestIntegration_RecordToLogEntry 验证 RecordToLogEntry 转换
func TestIntegration_RecordToLogEntry(t *testing.T) {
	r := slog.NewRecord(time.Now(), slog.LevelInfo, "entry test", 0)
	r.AddAttrs(slog.String("key", "val"))

	entry := RecordToLogEntry(r)
	if entry.Message != "entry test" {
		t.Errorf("Message = %v, want 'entry test'", entry.Message)
	}
	if entry.Level != slog.LevelInfo {
		t.Errorf("Level = %v, want Info", entry.Level)
	}
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
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	// Error 级别应始终通过采样
	logger.Error("must pass sampling")
	if got := ch.sink.len(); got != 1 {
		t.Errorf("error through sampling=%d, want 1", got)
	}

	_ = CloseAll(logger.Handler())
}

// integrationMetrics 实现 HandlerMetrics 接口
type integrationMetrics struct {
	onHandle  func()
	onError   func()
	onDropped func()
}

func (m *integrationMetrics) ObserveHandle(duration time.Duration) { m.onHandle() }
func (m *integrationMetrics) IncError(handlerName string)          { m.onError() }
func (m *integrationMetrics) IncDropped(handlerName string)        { m.onDropped() }

var _ HandlerMetrics = (*integrationMetrics)(nil)
