package mebsuta

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/iuboy/mebsuta/filerotate"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// StdoutHandler 测试
// =============================================================================

func newTestHandler(level slog.Level, format EncodingType) (*StdoutHandler, *bytes.Buffer) {
	var buf bytes.Buffer
	h, err := newStdoutHandlerWithWriter(&buf, StdoutConfig{Level: level, Format: string(format)})
	if err != nil {
		panic(err)
	}
	return h, &buf
}

func TestStdoutHandler_JSONFormat(t *testing.T) {
	h, buf := newTestHandler(slog.LevelInfo, JSON)
	logger := slog.New(h)

	logger.Info("hello", "key", "value")

	var result map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &result), "invalid JSON output: %s", buf.String())
	require.Equal(t, "hello", result["message"], "message")
	attrs, ok := result["attributes"].(map[string]any)
	require.True(t, ok, "attributes missing or invalid: %v", result["attributes"])
	require.Equal(t, "value", attrs["key"], "attributes.key")
	require.Equal(t, "INFO", result["level"], "level")
}

func TestStdoutHandler_TextFormat(t *testing.T) {
	h, buf := newTestHandler(slog.LevelInfo, Console)
	logger := slog.New(h)

	logger.Info("hello", "key", "value")

	output := buf.String()
	require.Contains(t, output, "hello")
	require.Contains(t, output, "key=value")
}

func TestStdoutHandler_LevelFilter(t *testing.T) {
	h, buf := newTestHandler(slog.LevelWarn, JSON)
	logger := slog.New(h)

	logger.Info("should be filtered")
	require.Empty(t, buf, "Info should be filtered at Warn level")

	logger.Warn("should pass")
	require.NotEmpty(t, buf, "Warn should pass at Warn level")
}

func TestStdoutHandler_WithAttrs(t *testing.T) {
	h, buf := newTestHandler(slog.LevelInfo, JSON)
	child := h.WithAttrs([]slog.Attr{slog.String("preset", "value")})
	logger := slog.New(child)

	logger.Info("test")

	var result map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &result), "invalid JSON")
	attrs := result["attributes"].(map[string]any)
	require.Equal(t, "value", attrs["preset"], "attributes.preset")
}

func TestStdoutHandler_WithGroup(t *testing.T) {
	h, buf := newTestHandler(slog.LevelInfo, JSON)
	child := h.WithGroup("request")
	logger := slog.New(child)

	logger.Info("test", "id", "123")

	var result map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &result), "invalid JSON")
	attrs := result["attributes"].(map[string]any)
	require.Equal(t, "123", attrs["request.id"], "attributes[request.id]")
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
	require.Equal(t, goroutines, lines, "expected lines")
}

func TestStdoutHandler_Close(t *testing.T) {
	h, _ := newTestHandler(slog.LevelInfo, JSON)
	// Close should be nop for stdout, not error
	require.NoError(t, h.Close(), "Close() returned error")
}

// =============================================================================
// New() 和 HandlerOption 测试
// =============================================================================

func TestNew_SingleHandler(t *testing.T) {
	handler, err := NewStdoutHandler(StdoutConfig{Level: slog.LevelInfo})
	require.NoError(t, err)
	logger, err := New(WithHandler(handler))
	require.NoError(t, err, "New() error")
	require.NotNil(t, logger, "New() returned nil logger")
}

func TestNew_MultipleHandlers(t *testing.T) {
	h1, err := NewStdoutHandler(StdoutConfig{Level: slog.LevelInfo})
	require.NoError(t, err)
	h2, err := NewStdoutHandler(StdoutConfig{Level: slog.LevelWarn})
	require.NoError(t, err)
	logger, err := New(WithHandler(h1), WithHandler(h2))
	require.NoError(t, err, "New() error")
	require.NotNil(t, logger, "New() returned nil logger")
}

func TestNew_NilHandler(t *testing.T) {
	_, err := New(WithHandler(nil))
	require.Error(t, err, "expected error for nil handler")
}

func TestNew_NoHandlers(t *testing.T) {
	logger, err := New()
	require.NoError(t, err, "New() with no options should return default logger")
	require.NotNil(t, logger, "New() returned nil logger")
	defer func() { _ = CloseAll(logger.Handler()) }()
}

// =============================================================================
// CloseAll 测试
// =============================================================================

func TestCloseAll_NilHandler(t *testing.T) {
	require.NoError(t, CloseAll(nil), "CloseAll(nil) returned error")
}

func TestCloseAll_StdoutHandler(t *testing.T) {
	h, err := NewStdoutHandler(StdoutConfig{Level: slog.LevelInfo})
	require.NoError(t, err)
	// StdoutHandler.Close is nop, should succeed
	require.NoError(t, CloseAll(h), "CloseAll() error")
}

func TestCloseAll_MultiHandler(t *testing.T) {
	h1, err := NewStdoutHandler(StdoutConfig{Level: slog.LevelInfo})
	require.NoError(t, err)
	h2, err := NewStdoutHandler(StdoutConfig{Level: slog.LevelWarn})
	require.NoError(t, err)
	multi := safeMultiHandler([]slog.Handler{h1, h2}, nil)

	// safeMulti 实现了 io.Closer，应递归关闭子 handler
	require.NoError(t, CloseAll(multi), "CloseAll(multi) error")
}

func TestCloseAll_DecoratorChain(t *testing.T) {
	inner, err := NewStdoutHandler(StdoutConfig{Level: slog.LevelInfo})
	require.NoError(t, err)
	sampling := WithSampling(inner, SamplingConfig{Enabled: true, Initial: 10, Thereafter: 1, Window: time.Second})

	// CloseAll 应通过 unwrapHandler 递归关闭 inner
	require.NoError(t, CloseAll(sampling), "CloseAll(sampling) error")
}

// =============================================================================
// ErrorHandler 测试
// =============================================================================

func TestErrorHandler_Default(t *testing.T) {
	var buf bytes.Buffer
	SetDefaultErrorHandler(func(he *HandlerError) {
		fmt.Fprintf(&buf, "%s/%s: %v\n", he.Component, he.Operation, he.Err)
	})
	defer SetDefaultErrorHandler(nil)

	DefaultErrorHandler()(&HandlerError{Component: "test", Operation: "write", Err: fmt.Errorf("boom")})
	require.Contains(t, buf.String(), "test/write: boom", "DefaultErrorHandler() output")
}

func TestErrorHandler_WithErrorHandler(t *testing.T) {
	var buf bytes.Buffer
	capture := func(he *HandlerError) {
		fmt.Fprintf(&buf, "%s/%s: %v\n", he.Component, he.Operation, he.Err)
	}

	cfg := FileConfig{}
	fh, err := NewFileHandler(filerotate.Config{Path: t.TempDir() + "/test.log"}, cfg)
	require.NoError(t, err)
	defer func() { _ = fh.Close() }()

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
	cfg := FileConfig{}
	fh, err := NewFileHandler(filerotate.Config{Path: t.TempDir() + "/test.log"}, cfg)
	require.NoError(t, err)
	defer func() { _ = fh.Close() }()

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
	capture := func(he *HandlerError) {
		fmt.Fprintf(&buf, "%s/%s: %v\n", he.Component, he.Operation, he.Err)
	}

	cfg := FileConfig{}
	fh, err := NewFileHandler(filerotate.Config{Path: t.TempDir() + "/test.log"}, cfg)
	require.NoError(t, err)
	defer func() { _ = fh.Close() }()

	// 用 Async 装饰器包裹 FileHandler，然后通过 WithErrorHandler 注入
	asyncH := WithAsync(fh, AsyncConfig{})
	defer func() {
		if closer, ok := asyncH.(interface{ Close() error }); ok {
			_ = closer.Close()
		}
	}()
	logger, err := New(
		WithHandler(asyncH),
		WithErrorHandler(capture),
	)
	require.NoError(t, err)

	logger.Error("test propagation")
	// 没有断言具体输出，只要不 panic 就行
}

func TestAsyncHandler_GroupPrefix(t *testing.T) {
	inner, err := NewStdoutHandler(StdoutConfig{Level: slog.LevelInfo})
	require.NoError(t, err)
	ah := WithAsync(inner, AsyncConfig{BufferSize: 64})
	grouped := ah.WithGroup("svc").WithAttrs([]slog.Attr{slog.String("id", "1")})

	attrsH, ok := grouped.(*asyncAttrsHandler)
	require.True(t, ok, "expected asyncAttrsHandler, got %T", grouped)
	require.Len(t, attrsH.attrs, 1, "attrs")
	require.Equal(t, "svc.id", attrsH.attrs[0].Key, "attr key")
}

func TestAsyncHandler_AttrsSurviveGroup(t *testing.T) {
	inner, err := NewStdoutHandler(StdoutConfig{Level: slog.LevelInfo})
	require.NoError(t, err)
	ah := WithAsync(inner, AsyncConfig{BufferSize: 64})
	chain := ah.WithAttrs([]slog.Attr{slog.String("service", "api")}).WithGroup("req").WithAttrs([]slog.Attr{slog.String("id", "1")})
	attrsH, ok := chain.(*asyncAttrsHandler)
	require.True(t, ok, "expected asyncAttrsHandler, got %T", chain)
	require.Len(t, attrsH.attrs, 2, "expected 2 attrs")
	require.Equal(t, "service", attrsH.attrs[0].Key, "first attr key")
	require.Equal(t, "req.id", attrsH.attrs[1].Key, "second attr key")
}

// =============================================================================
// panic recovery + nil errorHandler 回归测试
// =============================================================================

// Regression: panic recovery 在 nil ErrorHandler 时静默丢弃
// Found by /pr-review-toolkit:review-pr on 2026-04-15.
// nil errorHandler 时 panic 应静默丢弃，不写 stderr。
func TestSafeMultiHandler_PanicRecovery_NilErrorHandler(t *testing.T) {
	var buf bytes.Buffer
	SetDefaultErrorHandler(func(he *HandlerError) {
		fmt.Fprintf(&buf, "%s/%s: %v", he.Component, he.Operation, he.Err)
	})
	defer SetDefaultErrorHandler(nil)

	good := &countHandler{}
	bad := &panicHandler{msg: "nil eh panic"}
	h := safeMultiHandler([]slog.Handler{good, bad}, nil)
	logger := slog.New(h)
	logger.Info("test")

	// nil errorHandler 时应静默丢弃 panic，不写 stderr
	require.Empty(t, buf, "nil errorHandler should silently discard panic")
}

// Regression: WithErrorHandler(nil) 应传播 nil 到子 handler
// Found by /pr-review-toolkit:review-pr on 2026-04-15.
func TestBuildHandler_NilErrorHandler_Propagates(t *testing.T) {
	var buf bytes.Buffer
	// FileHandler 有 errorHandler 字段，默认是 DefaultErrorHandler()
	cfg := FileConfig{}
	fh, err := NewFileHandler(filerotate.Config{Path: t.TempDir() + "/test.log"}, cfg)
	require.NoError(t, err)
	defer func() { _ = fh.Close() }()
	SetDefaultErrorHandler(func(he *HandlerError) {
		fmt.Fprintf(&buf, "%s/%s: %v", he.Component, he.Operation, he.Err)
	})
	defer SetDefaultErrorHandler(nil)

	logger, err := New(WithHandler(fh), WithErrorHandler(nil))
	require.NoError(t, err)

	// 写一条日志（文件写入不会产生错误，但验证不 panic）
	logger.Info("test")

	// fh 的 errorHandler 应该是 nil（被传播了 nil），不会写到 stderr
	require.Empty(t, buf, "nil errorHandler should be propagated, but got stderr output")
}

// =============================================================================
// SPEC: LevelAudit — 审计级别通过 JSON handler 输出 "AUDIT"
// =============================================================================

func TestLevelAudit_JSONLevelString(t *testing.T) {
	h, buf := newTestHandler(slog.LevelInfo, JSON)
	logger := slog.New(h)

	logger.Log(context.Background(), slog.LevelError+4, "audit test", "actor", "admin", "success", true)

	var result map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &result), "invalid JSON")
	require.Equal(t, "AUDIT", result["level"], "level")
}

// =============================================================================
// SPEC: Multi Handler — 并发写无竞态
// =============================================================================

func TestSafeMulti_ConcurrentNoRace(t *testing.T) {
	h1, err := NewStdoutHandler(StdoutConfig{Level: slog.LevelInfo})
	require.NoError(t, err)
	h2, err := NewStdoutHandler(StdoutConfig{Level: slog.LevelInfo})
	require.NoError(t, err)
	multi := safeMultiHandler([]slog.Handler{h1, h2}, nil)
	logger := slog.New(multi)

	var wg sync.WaitGroup
	for range 100 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			logger.Info("race test", "ts", time.Now().UnixNano())
		}()
	}
	wg.Wait()
}

// =============================================================================
// MetricsHandler 测试
// =============================================================================

type mockMetrics struct {
	handleLatency time.Duration
	errors        []string
	dropped       []string
	mu            sync.Mutex
}

func (m *mockMetrics) ObserveHandle(d time.Duration) {
	m.mu.Lock()
	m.handleLatency = d
	m.mu.Unlock()
}

func (m *mockMetrics) IncError(name string) {
	m.mu.Lock()
	m.errors = append(m.errors, name)
	m.mu.Unlock()
}

func (m *mockMetrics) IncDroppedN(name string, n int64) {
	m.mu.Lock()
	for range n {
		m.dropped = append(m.dropped, name)
	}
	m.mu.Unlock()
}

func TestMetricsHandler_Handle(t *testing.T) {
	var buf bytes.Buffer
	inner, err := newStdoutHandlerWithWriter(&buf, StdoutConfig{Level: slog.LevelInfo})
	require.NoError(t, err)
	mm := &mockMetrics{}
	h := WithMetrics(inner, mm, "test")

	logger := slog.New(h)
	logger.Info("hello")

	require.NotZero(t, mm.handleLatency, "ObserveHandle should have been called with non-zero duration")
}

func TestMetricsHandler_WithAttrs(t *testing.T) {
	inner, err := NewStdoutHandler(StdoutConfig{Level: slog.LevelInfo})
	require.NoError(t, err)
	mm := &mockMetrics{}
	h := WithMetrics(inner, mm, "test")
	child := h.WithAttrs([]slog.Attr{slog.String("k", "v")})
	require.NotNil(t, child, "WithAttrs returned nil")
}

func TestMetricsHandler_WithGroup(t *testing.T) {
	inner, err := NewStdoutHandler(StdoutConfig{Level: slog.LevelInfo})
	require.NoError(t, err)
	mm := &mockMetrics{}
	h := WithMetrics(inner, mm, "test")
	child := h.WithGroup("request")
	require.NotNil(t, child, "WithGroup returned nil")
}

func TestMetricsHandler_Unwrap(t *testing.T) {
	inner, err := NewStdoutHandler(StdoutConfig{Level: slog.LevelInfo})
	require.NoError(t, err)
	mm := &mockMetrics{}
	h := WithMetrics(inner, mm, "test").(*MetricsHandler)
	require.Equal(t, inner, h.unwrapHandler(), "unwrapHandler should return inner")
}

func TestMetricsHandler_NilInner(t *testing.T) {
	mm := &mockMetrics{}
	h := WithMetrics(nil, mm, "test")
	require.Nil(t, h, "WithMetrics(nil, ...) should return nil")
}

// =============================================================================
// safeMulti WithAttrs/WithGroup 测试
// =============================================================================

func TestSafeMulti_WithAttrs(t *testing.T) {
	h1, err := NewStdoutHandler(StdoutConfig{Level: slog.LevelInfo})
	require.NoError(t, err)
	h2, err := NewStdoutHandler(StdoutConfig{Level: slog.LevelInfo})
	require.NoError(t, err)
	multi := safeMultiHandler([]slog.Handler{h1, h2}, nil)
	child := multi.WithAttrs([]slog.Attr{slog.String("preset", "val")})
	require.NotNil(t, child, "WithAttrs returned nil")

	sm := child.(*safeMulti)
	require.Len(t, sm.handlers, 2, "expected 2 handlers")
}

func TestSafeMulti_WithGroup(t *testing.T) {
	h1, err := NewStdoutHandler(StdoutConfig{Level: slog.LevelInfo})
	require.NoError(t, err)
	h2, err := NewStdoutHandler(StdoutConfig{Level: slog.LevelInfo})
	require.NoError(t, err)
	multi := safeMultiHandler([]slog.Handler{h1, h2}, nil)
	child := multi.WithGroup("request")
	require.NotNil(t, child, "WithGroup returned nil")

	sm := child.(*safeMulti)
	require.Len(t, sm.handlers, 2, "expected 2 handlers")
}

func TestSafeMulti_SingleHandlerFastPath(t *testing.T) {
	var buf bytes.Buffer
	inner, err := newStdoutHandlerWithWriter(&buf, StdoutConfig{Level: slog.LevelInfo})
	require.NoError(t, err)
	multi := safeMultiHandler([]slog.Handler{inner}, nil)
	logger := slog.New(multi)
	logger.Info("single handler fast path")
	require.NotEmpty(t, buf, "single handler should write output")
}
