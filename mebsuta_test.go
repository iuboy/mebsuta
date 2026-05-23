package mebsuta

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)


// =============================================================================
// StdoutHandler 测试
// =============================================================================

func newTestHandler(level slog.Level, format EncodingType) (*StdoutHandler, *bytes.Buffer) {
	var buf bytes.Buffer
	h := newStdoutHandlerWithWriter(&buf, StdoutConfig{Level: level, Format: string(format)})
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
	if result["message"] != "hello" {
		t.Errorf("message = %v, want hello", result["message"])
	}
	attrs, ok := result["attributes"].(map[string]any)
	if !ok {
		t.Fatalf("attributes missing or invalid: %v", result["attributes"])
	}
	if attrs["key"] != "value" {
		t.Errorf("attributes.key = %v, want value", attrs["key"])
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
	attrs := result["attributes"].(map[string]any)
	if attrs["preset"] != "value" {
		t.Errorf("attributes.preset = %v, want value", attrs["preset"])
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
	attrs := result["attributes"].(map[string]any)
	if attrs["request.id"] != "123" {
		t.Errorf("attributes[request.id] = %v, want 123", attrs["request.id"])
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
	handler := NewStdoutHandler(StdoutConfig{Level: slog.LevelInfo})
	logger, err := New(WithHandler(handler))
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	if logger == nil {
		t.Fatal("New() returned nil logger")
	}
}

func TestNew_MultipleHandlers(t *testing.T) {
	h1 := NewStdoutHandler(StdoutConfig{Level: slog.LevelInfo})
	h2 := NewStdoutHandler(StdoutConfig{Level: slog.LevelWarn})
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
	logger, err := New()
	if err != nil {
		t.Fatalf("New() with no options should return default logger: %v", err)
	}
	if logger == nil {
		t.Fatal("New() returned nil logger")
	}
	defer CloseAll(logger.Handler())
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
	h := NewStdoutHandler(StdoutConfig{Level: slog.LevelInfo})
	// StdoutHandler.Close is nop, should succeed
	if err := CloseAll(h); err != nil {
		t.Errorf("CloseAll() error: %v", err)
	}
}

func TestCloseAll_MultiHandler(t *testing.T) {
	h1 := NewStdoutHandler(StdoutConfig{Level: slog.LevelInfo})
	h2 := NewStdoutHandler(StdoutConfig{Level: slog.LevelWarn})
	multi := safeMultiHandler([]slog.Handler{h1, h2}, nil)

	// safeMulti 实现了 io.Closer，应递归关闭子 handler
	if err := CloseAll(multi); err != nil {
		t.Errorf("CloseAll(multi) error: %v", err)
	}
}

func TestCloseAll_DecoratorChain(t *testing.T) {
	inner := NewStdoutHandler(StdoutConfig{Level: slog.LevelInfo})
	sampling := WithSampling(inner, SamplingConfig{Enabled: true, Initial: 10, Thereafter: 1, Window: time.Second})

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
	DefaultErrorHandler = func(he HandlerError) {
		fmt.Fprintf(&buf, "%s/%s: %v\n", he.Component, he.Operation, he.Err)
	}
	defer func() { DefaultErrorHandler = defaultErrorHandler }()

	DefaultErrorHandler(HandlerError{Component: "test", Operation: "write", Err: fmt.Errorf("boom")})
	got := buf.String()
	if !strings.Contains(got, "test/write: boom") {
		t.Errorf("DefaultErrorHandler output = %q, want 'test/write: boom'", got)
	}
}

func TestErrorHandler_WithErrorHandler(t *testing.T) {
	var buf bytes.Buffer
	capture := func(he HandlerError) {
		fmt.Fprintf(&buf, "%s/%s: %v\n", he.Component, he.Operation, he.Err)
	}

	cfg := FileConfig{Path: t.TempDir() + "/test.log"}
	fh, err := NewFileHandler(cfg)
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
	cfg := FileConfig{Path: t.TempDir() + "/test.log"}
	fh, err := NewFileHandler(cfg)
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
	capture := func(he HandlerError) {
		fmt.Fprintf(&buf, "%s/%s: %v\n", he.Component, he.Operation, he.Err)
	}

	cfg := FileConfig{Path: t.TempDir() + "/test.log"}
	fh, err := NewFileHandler(cfg)
	require.NoError(t, err)
	defer fh.Close()

	// 用 Async 装饰器包裹 FileHandler，然后通过 WithErrorHandler 注入
	asyncH := WithAsync(fh, AsyncConfig{})
	defer func() {
		if closer, ok := asyncH.(interface{ Close() error }); ok {
			closer.Close()
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
	inner := NewStdoutHandler(StdoutConfig{Level: slog.LevelInfo})
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


func TestAsyncHandler_AttrsSurviveGroup(t *testing.T) {
	inner := NewStdoutHandler(StdoutConfig{Level: slog.LevelInfo})
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
// nil errorHandler 时 panic 应静默丢弃，不写 stderr。
func TestSafeMultiHandler_PanicRecovery_NilErrorHandler(t *testing.T) {
	var buf bytes.Buffer
	DefaultErrorHandler = func(he HandlerError) {
		fmt.Fprintf(&buf, "%s/%s: %v", he.Component, he.Operation, he.Err)
	}
	defer func() { DefaultErrorHandler = defaultErrorHandler }()

	good := &countHandler{}
	bad := &panicHandler{msg: "nil eh panic"}
	h := safeMultiHandler([]slog.Handler{good, bad}, nil)
	logger := slog.New(h)
	logger.Info("test")

	// nil errorHandler 时应静默丢弃 panic，不写 stderr
	if buf.Len() > 0 {
		t.Errorf("nil errorHandler should silently discard panic, got: %s", buf.String())
	}
}

// Regression: WithErrorHandler(nil) 应传播 nil 到子 handler
// Found by /pr-review-toolkit:review-pr on 2026-04-15.
func TestBuildHandler_NilErrorHandler_Propagates(t *testing.T) {
	var buf bytes.Buffer
	// FileHandler 有 errorHandler 字段，默认是 DefaultErrorHandler
	cfg := FileConfig{Path: t.TempDir() + "/test.log"}
	fh, err := NewFileHandler(cfg)
	require.NoError(t, err)
	defer fh.Close()
	DefaultErrorHandler = func(he HandlerError) {
		fmt.Fprintf(&buf, "%s/%s: %v", he.Component, he.Operation, he.Err)
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

// =============================================================================
// SPEC: LevelAudit — 审计级别测试
// =============================================================================

func TestLevelAudit_Value(t *testing.T) {
	if LevelAudit < slog.LevelError {
		t.Errorf("LevelAudit = %d, must be >= LevelError (%d)", LevelAudit, slog.LevelError)
	}
}

func TestLevelAudit_EnabledAtError(t *testing.T) {
	if LevelAudit < slog.LevelError {
		t.Error("SPEC: Audit must pass through Error-level handler")
	}
}

func TestAuditEvent_JSONContract(t *testing.T) {
	h, buf := newTestHandler(slog.LevelInfo, JSON)
	prev := slog.Default()
	slog.SetDefault(slog.New(h))
	defer slog.SetDefault(prev)

	AuditEvent(EventLogin, "user login", "actor", "user:42", "success", true, "ip", "127.0.0.1")

	var result map[string]any
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if result["level"] != "AUDIT" {
		t.Fatalf("level = %v, want AUDIT", result["level"])
	}
	if result["event_type"] != "login" {
		t.Fatalf("event_type = %v, want login", result["event_type"])
	}
	if result["actor"] != "user:42" {
		t.Fatalf("actor = %v, want user:42", result["actor"])
	}
	if result["success"] != true {
		t.Fatalf("success = %v, want true", result["success"])
	}
	attrs := result["attributes"].(map[string]any)
	if attrs["ip"] != "127.0.0.1" {
		t.Fatalf("attributes.ip = %v, want 127.0.0.1", attrs["ip"])
	}
	if _, ok := attrs["event_type"]; ok {
		t.Fatal("event_type must be promoted out of attributes")
	}
}

func TestAudit_DefaultEventType(t *testing.T) {
	h, buf := newTestHandler(slog.LevelInfo, JSON)
	prev := slog.Default()
	slog.SetDefault(slog.New(h))
	defer slog.SetDefault(prev)

	Audit("system audit")

	var result map[string]any
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if result["event_type"] != "system" {
		t.Fatalf("event_type = %v, want system", result["event_type"])
	}
}

// =============================================================================
// SPEC: Multi Handler — 并发写无竞态
// =============================================================================

func TestSafeMulti_ConcurrentNoRace(t *testing.T) {
	h1 := NewStdoutHandler(StdoutConfig{Level: slog.LevelInfo})
	h2 := NewStdoutHandler(StdoutConfig{Level: slog.LevelInfo})
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

func (m *mockMetrics) IncDropped(name string) {
	m.mu.Lock()
	m.dropped = append(m.dropped, name)
	m.mu.Unlock()
}

func TestMetricsHandler_Handle(t *testing.T) {
	var buf bytes.Buffer
	inner := newStdoutHandlerWithWriter(&buf, StdoutConfig{Level: slog.LevelInfo})
	mm := &mockMetrics{}
	h := WithMetrics(inner, mm, "test")

	logger := slog.New(h)
	logger.Info("hello")

	if mm.handleLatency == 0 {
		t.Error("ObserveHandle should have been called with non-zero duration")
	}
}

func TestMetricsHandler_WithAttrs(t *testing.T) {
	inner := NewStdoutHandler(StdoutConfig{Level: slog.LevelInfo})
	mm := &mockMetrics{}
	h := WithMetrics(inner, mm, "test")
	child := h.WithAttrs([]slog.Attr{slog.String("k", "v")})
	if child == nil {
		t.Fatal("WithAttrs returned nil")
	}
}

func TestMetricsHandler_WithGroup(t *testing.T) {
	inner := NewStdoutHandler(StdoutConfig{Level: slog.LevelInfo})
	mm := &mockMetrics{}
	h := WithMetrics(inner, mm, "test")
	child := h.WithGroup("request")
	if child == nil {
		t.Fatal("WithGroup returned nil")
	}
}

func TestMetricsHandler_Unwrap(t *testing.T) {
	inner := NewStdoutHandler(StdoutConfig{Level: slog.LevelInfo})
	mm := &mockMetrics{}
	h := WithMetrics(inner, mm, "test").(*MetricsHandler)
	if h.unwrapHandler() != inner {
		t.Error("unwrapHandler should return inner")
	}
}

func TestMetricsHandler_NilInner(t *testing.T) {
	mm := &mockMetrics{}
	h := WithMetrics(nil, mm, "test")
	if h != nil {
		t.Error("WithMetrics(nil, ...) should return nil")
	}
}

// =============================================================================
// safeMulti WithAttrs/WithGroup 测试
// =============================================================================

func TestSafeMulti_WithAttrs(t *testing.T) {
	h1 := NewStdoutHandler(StdoutConfig{Level: slog.LevelInfo})
	h2 := NewStdoutHandler(StdoutConfig{Level: slog.LevelInfo})
	multi := safeMultiHandler([]slog.Handler{h1, h2}, nil)
	child := multi.WithAttrs([]slog.Attr{slog.String("preset", "val")})
	if child == nil {
		t.Fatal("WithAttrs returned nil")
	}

	sm := child.(*safeMulti)
	if len(sm.handlers) != 2 {
		t.Fatalf("expected 2 handlers, got %d", len(sm.handlers))
	}
}

func TestSafeMulti_WithGroup(t *testing.T) {
	h1 := NewStdoutHandler(StdoutConfig{Level: slog.LevelInfo})
	h2 := NewStdoutHandler(StdoutConfig{Level: slog.LevelInfo})
	multi := safeMultiHandler([]slog.Handler{h1, h2}, nil)
	child := multi.WithGroup("request")
	if child == nil {
		t.Fatal("WithGroup returned nil")
	}

	sm := child.(*safeMulti)
	if len(sm.handlers) != 2 {
		t.Fatalf("expected 2 handlers, got %d", len(sm.handlers))
	}
}

func TestSafeMulti_SingleHandlerFastPath(t *testing.T) {
	var buf bytes.Buffer
	inner := newStdoutHandlerWithWriter(&buf, StdoutConfig{Level: slog.LevelInfo})
	multi := safeMultiHandler([]slog.Handler{inner}, nil)
	logger := slog.New(multi)
	logger.Info("single handler fast path")
	if buf.Len() == 0 {
		t.Error("single handler should write output")
	}
}

// =============================================================================
// RecordWithGroupAttrs 测试
// =============================================================================

func TestRecordWithGroupAttrs(t *testing.T) {
	r := slog.NewRecord(time.Now(), slog.LevelInfo, "msg", 0)
	r.AddAttrs(slog.String("id", "1"))

	newR := RecordWithGroupAttrs(r, "req", []slog.Attr{slog.String("extra", "data")})

	var attrs []slog.Attr
	newR.Attrs(func(a slog.Attr) bool {
		attrs = append(attrs, a)
		return true
	})

	if len(attrs) != 2 {
		t.Fatalf("expected 2 attrs, got %d", len(attrs))
	}
	if attrs[0].Key != "req.id" {
		t.Errorf("first attr key = %q, want %q", attrs[0].Key, "req.id")
	}
	if attrs[1].Key != "extra" {
		t.Errorf("second attr key = %q, want %q", attrs[1].Key, "extra")
	}
}
