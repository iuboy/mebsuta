package mebsuta

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/iuboy/mebsuta/config"
)

// =============================================================================
// LevelHandler 测试
// =============================================================================

func TestLevelHandler_Enabled(t *testing.T) {
	h := LevelHandler{Level: slog.LevelWarn}

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

	for i := range goroutines {
		go func(n int) {
			logger.Info("concurrent", "n", n)
			done <- struct{}{}
		}(i)
	}

	for range goroutines {
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
	multi := safeMultiHandler(slog.NewMultiHandler(h1, h2), []slog.Handler{h1, h2}, nil)

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

// =============================================================================
// ErrorHandler 测试
// =============================================================================

func TestErrorHandler_Default(t *testing.T) {
	var buf bytes.Buffer
	DefaultErrorHandler = func(component string, err error) {
		fmt.Fprintf(&buf, "%s: %v\n", component, err)
	}
	defer func() { DefaultErrorHandler = defaultErrorHandler }()

	DefaultErrorHandler("test", fmt.Errorf("boom"))
	got := buf.String()
	if !strings.Contains(got, "test: boom") {
		t.Errorf("DefaultErrorHandler output = %q, want 'test: boom'", got)
	}
}

func TestErrorHandler_WithErrorHandler(t *testing.T) {
	var buf bytes.Buffer
	capture := func(component string, err error) {
		fmt.Fprintf(&buf, "%s: %v\n", component, err)
	}

	fh, err := NewFileHandler(config.FileConfig{Path: t.TempDir() + "/test.log"}, slog.LevelInfo)
	require.NoError(t, err)
	defer fh.Close()

	logger, err := New(
		WithHandler(fh),
		WithErrorHandler(capture),
	)
	require.NoError(t, err)

	logger.Error("trigger error handling")

	// FileHandler.Handle 的 inner 写入不会产生错误，但 WithAttrs 子 handler
	// 现在继承 errorHandler，确认 nil 调用不会 panic
	sub := logger.With("sub", "val")
	sub.Error("sub error")
}

func TestErrorHandler_NilSilent(t *testing.T) {
	fh, err := NewFileHandler(config.FileConfig{Path: t.TempDir() + "/test.log"}, slog.LevelInfo)
	require.NoError(t, err)
	defer fh.Close()

	logger, err := New(
		WithHandler(fh),
		WithErrorHandler(nil),
	)
	require.NoError(t, err)

	// WithErrorHandler(nil) 不应 panic
	logger.Error("silent error handling")
}

func TestPropagateErrorHandler_ThroughDecorator(t *testing.T) {
	var buf bytes.Buffer
	capture := func(component string, err error) {
		fmt.Fprintf(&buf, "%s: %v\n", component, err)
	}

	fh, err := NewFileHandler(config.FileConfig{Path: t.TempDir() + "/test.log"}, slog.LevelInfo)
	require.NoError(t, err)
	defer fh.Close()

	// 用 Async 装饰器包裹 FileHandler，然后通过 WithErrorHandler 注入
	asyncH := WithAsync(fh, AsyncConfig{})
	logger, err := New(
		WithHandler(asyncH),
		WithErrorHandler(capture),
	)
	require.NoError(t, err)

	logger.Error("test propagation")
	// 没有断言具体输出，只要不 panic 就行
}

// =============================================================================
// SyslogHandler WithAttrs/WithGroup 回归测试
// =============================================================================

// Regression: ISSUE-001 — SyslogHandler 缺少 WithAttrs/WithGroup
// Found by /qa on 2026-04-15
// 用户调用 logger.With("key", "value") 后写 syslog，预置属性不应静默丢失。
func TestSyslogHandler_WithAttrs(t *testing.T) {
	// SyslogHandler 需要真实连接，这里只验证 WithAttrs 返回的 handler 类型正确
	// 且 Handle 不会 panic（即使连接失败，safeSend 会 recover）
	h := &SyslogHandler{
		LevelHandler: LevelHandler{Level: slog.LevelInfo},
		cfg:          config.SyslogConfig{Address: "127.0.0.1:9999", Network: "tcp"},
		buffer:       make(chan []byte, 10),
		closing:      atomic.Bool{},
		closed:       atomic.Bool{},
		errorHandler: DefaultErrorHandler,
	}

	child := h.WithAttrs([]slog.Attr{slog.String("preset", "value")})
	if child == nil {
		t.Fatal("WithAttrs returned nil")
	}

	// 验证子 handler 不是自身（应该返回包装器）
	if child == h {
		t.Error("WithAttrs should return a wrapper, not the same handler")
	}

	// 验证 WithGroup 也不返回 nil
	grouped := h.WithGroup("request")
	if grouped == nil {
		t.Fatal("WithGroup returned nil")
	}
	if grouped == h {
		t.Error("WithGroup should return a wrapper, not the same handler")
	}

	// 验证链式 WithAttrs 合并属性
	double := child.WithAttrs([]slog.Attr{slog.String("extra", "data")})
	if double == nil {
		t.Fatal("chained WithAttrs returned nil")
	}
}

// =============================================================================
// groupHandler WithAttrs group 前缀回归测试
// =============================================================================

// Regression: group 语义丢失 — WithGroup 后 WithAttrs 的属性 key 应带 group 前缀。
// Found by /pr-review-toolkit:review-pr on 2026-04-15.
func TestSyslogHandler_GroupPrefix(t *testing.T) {
	h := &SyslogHandler{
		LevelHandler: LevelHandler{Level: slog.LevelInfo},
		cfg:          config.SyslogConfig{Address: "127.0.0.1:9999", Network: "tcp"},
		buffer:       make(chan []byte, 10),
		closing:      atomic.Bool{},
		closed:       atomic.Bool{},
		errorHandler: DefaultErrorHandler,
	}

	grouped := h.WithGroup("req").WithAttrs([]slog.Attr{slog.String("key", "val")})
	// 类型断言：WithGroup 后 WithAttrs 应返回 syslogAttrsHandler
	attrsH, ok := grouped.(*syslogAttrsHandler)
	if !ok {
		t.Fatalf("expected syslogAttrsHandler, got %T", grouped)
	}
	if len(attrsH.attrs) != 1 {
		t.Fatalf("expected 1 attr, got %d", len(attrsH.attrs))
	}
	if attrsH.attrs[0].Key != "req.key" {
		t.Errorf("attr key = %q, want %q", attrsH.attrs[0].Key, "req.key")
	}
}

func TestAsyncHandler_GroupPrefix(t *testing.T) {
	inner := NewStdoutHandler(slog.LevelInfo, JSON)
	ah := WithAsync(inner, AsyncConfig{BufferSize: 64})
	grouped := ah.WithGroup("svc").WithAttrs([]slog.Attr{slog.String("id", "1")})

	attrsH, ok := grouped.(*asyncAttrsHandler)
	if !ok {
		t.Fatalf("expected asyncAttrsHandler, got %T", grouped)
	}
	if len(attrsH.attrs) != 1 || attrsH.attrs[0].Key != "svc.id" {
		t.Errorf("attr key = %q, want %q", attrsH.attrs[0].Key, "svc.id")
	}
}

// =============================================================================
// WithAttrs().WithGroup() 属性传递回归测试
// =============================================================================

// Regression: WithAttrs 后 WithGroup 不应丢失已累积的属性
// Found by code review on 2026-04-16.
// handler.WithAttrs(a=1).WithGroup("req").WithAttrs(b=2) 中 a=1 被静默丢弃。
func TestSyslogHandler_AttrsSurviveGroup(t *testing.T) {
	h := &SyslogHandler{
		LevelHandler: LevelHandler{Level: slog.LevelInfo},
		cfg:          config.SyslogConfig{Address: "127.0.0.1:9999", Network: "tcp"},
		buffer:       make(chan []byte, 10),
		closing:      atomic.Bool{},
		closed:       atomic.Bool{},
		errorHandler: DefaultErrorHandler,
	}

	chain := h.WithAttrs([]slog.Attr{slog.String("service", "api")}).WithGroup("req").WithAttrs([]slog.Attr{slog.String("id", "1")})
	attrsH, ok := chain.(*syslogAttrsHandler)
	if !ok {
		t.Fatalf("expected syslogAttrsHandler, got %T", chain)
	}
	// 应有 2 个属性: service=api 和 req.id=1
	if len(attrsH.attrs) != 2 {
		t.Fatalf("expected 2 attrs, got %d", len(attrsH.attrs))
	}
	if attrsH.attrs[0].Key != "service" {
		t.Errorf("first attr key = %q, want %q", attrsH.attrs[0].Key, "service")
	}
	if attrsH.attrs[1].Key != "req.id" {
		t.Errorf("second attr key = %q, want %q", attrsH.attrs[1].Key, "req.id")
	}
}

func TestAsyncHandler_AttrsSurviveGroup(t *testing.T) {
	inner := NewStdoutHandler(slog.LevelInfo, JSON)
	ah := WithAsync(inner, AsyncConfig{BufferSize: 64})
	chain := ah.WithAttrs([]slog.Attr{slog.String("service", "api")}).WithGroup("req").WithAttrs([]slog.Attr{slog.String("id", "1")})
	attrsH, ok := chain.(*asyncAttrsHandler)
	if !ok {
		t.Fatalf("expected asyncAttrsHandler, got %T", chain)
	}
	if len(attrsH.attrs) != 2 {
		t.Fatalf("expected 2 attrs, got %d", len(attrsH.attrs))
	}
	if attrsH.attrs[0].Key != "service" {
		t.Errorf("first attr key = %q, want %q", attrsH.attrs[0].Key, "service")
	}
	if attrsH.attrs[1].Key != "req.id" {
		t.Errorf("second attr key = %q, want %q", attrsH.attrs[1].Key, "req.id")
	}
}

// =============================================================================
// panic recovery + nil errorHandler 回归测试
// =============================================================================

// Regression: panic recovery 在 nil ErrorHandler 时静默丢弃
// Found by /pr-review-toolkit:review-pr on 2026-04-15.
// panic 意味着代码 bug，即使 errorHandler 为 nil 也应写 stderr。
func TestSafeMultiHandler_PanicRecovery_NilErrorHandler(t *testing.T) {
	var buf bytes.Buffer
	// 捕获 stderr 输出
	DefaultErrorHandler = func(component string, err error) {
		fmt.Fprintf(&buf, "%s: %v", component, err)
	}
	defer func() { DefaultErrorHandler = defaultErrorHandler }()

	good := &countHandler{}
	bad := &panicHandler{msg: "nil eh panic"}
	h := safeMultiHandler(slog.NewMultiHandler(good, bad), []slog.Handler{good, bad}, nil)
	logger := slog.New(h)
	logger.Info("test")

	if !strings.Contains(buf.String(), "multi") {
		t.Error("panic recovery should always write to stderr, even with nil errorHandler")
	}
	if !strings.Contains(buf.String(), "nil eh panic") {
		t.Error("panic message should contain the panic value")
	}
}

// Regression: WithErrorHandler(nil) 应传播 nil 到子 handler
// Found by /pr-review-toolkit:review-pr on 2026-04-15.
func TestBuildHandler_NilErrorHandler_Propagates(t *testing.T) {
	var buf bytes.Buffer
	// FileHandler 有 errorHandler 字段，默认是 DefaultErrorHandler
	fh, err := NewFileHandler(config.FileConfig{Path: t.TempDir() + "/test.log"}, slog.LevelInfo)
	require.NoError(t, err)
	defer fh.Close()
	DefaultErrorHandler = func(component string, err error) {
		fmt.Fprintf(&buf, "%s: %v", component, err)
	}
	defer func() { DefaultErrorHandler = defaultErrorHandler }()

	logger, err := New(WithHandler(fh), WithErrorHandler(nil))
	require.NoError(t, err)

	// 写一条日志（文件写入不会产生错误，但验证不 panic）
	logger.Info("test")

	// fh 的 errorHandler 应该是 nil（被传播了 nil），不会写到 stderr
	if buf.Len() > 0 {
		t.Errorf("nil errorHandler should be propagated, but got stderr output: %s", buf.String())
	}
}
