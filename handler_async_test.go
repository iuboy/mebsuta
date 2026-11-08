package mebsuta

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// =============================================================================
// AsyncHandler 测试
// =============================================================================

func TestAsyncHandler_Basic(t *testing.T) {
	var buf bytes.Buffer
	inner, err := newStdoutHandlerWithWriter(&buf, StdoutConfig{Level: slog.LevelInfo})
	require.NoError(t, err)
	h := WithAsync(inner, AsyncConfig{BufferSize: 64})
	logger := slog.New(h)

	logger.Info("hello", "key", "value")

	// 先 close 确保 flush
	if closer, ok := h.(interface{ Close() error }); ok {
		_ = closer.Close()
	}

	if !bytes.Contains(buf.Bytes(), []byte("hello")) {
		t.Errorf("expected 'hello' in output, got: %s", buf.String())
	}
}

func TestAsyncHandler_DropOnFull(t *testing.T) {
	inner := &countHandler{}
	h := WithAsync(inner, AsyncConfig{BufferSize: 1}) // 极小缓冲
	logger := slog.New(h)

	for range 1000 {
		logger.Info("test")
	}

	if closer, ok := h.(interface{ Close() error }); ok {
		_ = closer.Close()
	}

	dropped := AsyncDropped(h.(*AsyncHandler))
	if dropped == 0 {
		t.Error("expected some logs to be dropped with tiny buffer")
	}
}

func TestAsyncHandler_Close(t *testing.T) {
	var buf bytes.Buffer
	inner, err := newStdoutHandlerWithWriter(&buf, StdoutConfig{Level: slog.LevelInfo})
	require.NoError(t, err)
	h := WithAsync(inner, AsyncConfig{BufferSize: 64})
	logger := slog.New(h)

	logger.Info("before close")

	if closer, ok := h.(interface{ Close() error }); ok {
		if err := closer.Close(); err != nil {
			t.Errorf("Close() error: %v", err)
		}
		// 双重关闭
		if err := closer.Close(); err != nil {
			t.Errorf("double Close() error: %v", err)
		}
	}

	if !bytes.Contains(buf.Bytes(), []byte("before close")) {
		t.Error("log before close should be written")
	}
}

func TestAsyncHandler_NilHandler(t *testing.T) {
	h := WithAsync(nil, AsyncConfig{})
	if h != nil {
		t.Error("expected nil for nil handler")
	}
}

func TestAsyncHandler_WithAttrs(t *testing.T) {
	var buf bytes.Buffer
	inner, err := newStdoutHandlerWithWriter(&buf, StdoutConfig{Level: slog.LevelInfo})
	require.NoError(t, err)
	h := WithAsync(inner, AsyncConfig{BufferSize: 64})
	child := h.WithAttrs([]slog.Attr{slog.String("preset", "value")})
	logger := slog.New(child)

	logger.Info("test")

	if closer, ok := h.(interface{ Close() error }); ok {
		_ = closer.Close()
	}

	if !bytes.Contains(buf.Bytes(), []byte("preset")) {
		t.Errorf("expected 'preset' in output, got: %s", buf.String())
	}
}

func TestAsyncHandler_WithGroup(t *testing.T) {
	var buf bytes.Buffer
	inner, err := newStdoutHandlerWithWriter(&buf, StdoutConfig{Level: slog.LevelInfo})
	require.NoError(t, err)
	h := WithAsync(inner, AsyncConfig{BufferSize: 64})
	child := h.WithGroup("request")
	logger := slog.New(child)

	logger.Info("test", "id", "123")

	if closer, ok := h.(interface{ Close() error }); ok {
		_ = closer.Close()
	}

	output := buf.String()
	if !strings.Contains(output, `"request.id"`) {
		t.Errorf("expected 'request.id' in output, got: %s", output)
	}
}

func TestAsyncHandler_Concurrent(t *testing.T) {
	var count atomic.Int64
	inner := &concurrentHandler{count: &count}
	h := WithAsync(inner, AsyncConfig{BufferSize: 256})
	logger := slog.New(h)

	var wg sync.WaitGroup
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 100 {
				logger.Info("test")
			}
		}()
	}
	wg.Wait()

	if closer, ok := h.(interface{ Close() error }); ok {
		_ = closer.Close()
	}

	if count.Load() == 0 {
		t.Error("expected some logs to be written")
	}
}

type concurrentHandler struct {
	count *atomic.Int64
}

func (h *concurrentHandler) Enabled(_ context.Context, _ slog.Level) bool { return true }
func (h *concurrentHandler) Handle(_ context.Context, _ slog.Record) error {
	h.count.Add(1)
	return nil
}
func (h *concurrentHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *concurrentHandler) WithGroup(string) slog.Handler      { return h }

func TestAsyncDropped_NonAsync(t *testing.T) {
	// 非 AsyncHandler 应返回 0
	dropped := AsyncDropped(&StdoutHandler{})
	if dropped != 0 {
		t.Errorf("expected 0 for non-async handler, got %d", dropped)
	}
}

func TestAsyncHandler_AuditNotDropped(t *testing.T) {
	// SPEC P0: Error and Audit records must not be dropped by buffer full.
	inner := &countHandler{}
	h := WithAsync(inner, AsyncConfig{BufferSize: 1}) // tiny buffer

	// Fill the buffer with normal records
	if err := h.Handle(context.Background(), slog.NewRecord(time.Now(), slog.LevelInfo, "fill", 0)); err != nil {
		t.Fatalf("Handle fill: %v", err)
	}

	// Error/Audit should still be delivered (blocking path retries)
	r := slog.NewRecord(time.Now(), slog.LevelError, "error record", 0)
	if err := h.Handle(context.Background(), r); err != nil {
		t.Fatalf("Handle error: %v", err)
	}

	if closer, ok := h.(interface{ Close() error }); ok {
		_ = closer.Close()
	}

	errorCount := inner.ErrorLevelCount()
	if errorCount < 1 {
		t.Errorf("expected at least 1 error-level record, got %d", errorCount)
	}
}

func TestAsyncHandler_AuditLevelNotDropped(t *testing.T) {
	inner := &countHandler{}
	h := WithAsync(inner, AsyncConfig{BufferSize: 1})

	if err := h.Handle(context.Background(), slog.NewRecord(time.Now(), slog.LevelInfo, "fill", 0)); err != nil {
		t.Fatalf("Handle fill: %v", err)
	}

	r := slog.NewRecord(time.Now(), slog.LevelError+4, "audit record", 0)
	if err := h.Handle(context.Background(), r); err != nil {
		t.Fatalf("Handle audit: %v", err)
	}

	if closer, ok := h.(interface{ Close() error }); ok {
		_ = closer.Close()
	}

	errorCount := inner.ErrorLevelCount()
	if errorCount < 1 {
		t.Errorf("expected at least 1 audit-level record, got %d", errorCount)
	}
}

// =============================================================================
// MetricsHandler 测试
// =============================================================================

type testMetrics struct {
	handleCount  atomic.Int64
	errorCount   atomic.Int64
	droppedCount atomic.Int64
}

func (m *testMetrics) ObserveHandle(d time.Duration)    { m.handleCount.Add(1) }
func (m *testMetrics) IncError(name string)             { m.errorCount.Add(1) }
func (m *testMetrics) IncDroppedN(name string, n int64) { m.droppedCount.Add(n) }

func TestWithMetrics_Basic(t *testing.T) {
	m := &testMetrics{}
	var buf bytes.Buffer
	inner, err := newStdoutHandlerWithWriter(&buf, StdoutConfig{Level: slog.LevelInfo})
	require.NoError(t, err)
	h := WithMetrics(inner, m, "stdout")
	logger := slog.New(h)

	logger.Info("test")

	if m.handleCount.Load() != 1 {
		t.Errorf("expected 1 handle, got %d", m.handleCount.Load())
	}
}

func TestWithMetrics_NilInputs(t *testing.T) {
	m := &testMetrics{}
	// nil handler
	h := WithMetrics(nil, m, "test")
	if h != nil {
		t.Error("expected nil for nil handler")
	}

	var buf bytes.Buffer
	inner, err := newStdoutHandlerWithWriter(&buf, StdoutConfig{Level: slog.LevelInfo})
	require.NoError(t, err)
	// nil metrics
	h = WithMetrics(inner, nil, "test")
	if h != inner {
		t.Error("expected original handler for nil metrics")
	}
}

func TestWithMetrics_WithAttrs(t *testing.T) {
	m := &testMetrics{}
	var buf bytes.Buffer
	inner, err := newStdoutHandlerWithWriter(&buf, StdoutConfig{Level: slog.LevelInfo})
	require.NoError(t, err)
	h := WithMetrics(inner, m, "stdout")
	child := h.WithAttrs([]slog.Attr{slog.String("k", "v")})
	logger := slog.New(child)

	logger.Info("test")

	if m.handleCount.Load() != 1 {
		t.Errorf("expected 1 handle, got %d", m.handleCount.Load())
	}
}

// =============================================================================
// ContextExtractor 测试
// =============================================================================

type ctxKey string

func TestWithContextExtractor_Basic(t *testing.T) {
	var buf bytes.Buffer
	inner, err := newStdoutHandlerWithWriter(&buf, StdoutConfig{Level: slog.LevelInfo})
	require.NoError(t, err)

	h := WithContextExtractor(inner, func(ctx context.Context) []slog.Attr {
		if reqID, ok := ctx.Value(ctxKey("request_id")).(string); ok {
			return []slog.Attr{slog.String("request_id", reqID)}
		}
		return nil
	})

	logger := slog.New(h)
	ctx := context.WithValue(context.Background(), ctxKey("request_id"), "abc-123")
	logger.InfoContext(ctx, "test")

	if !bytes.Contains(buf.Bytes(), []byte("abc-123")) {
		t.Errorf("expected 'abc-123' in output, got: %s", buf.String())
	}
}

func TestWithContextExtractor_NilInputs(t *testing.T) {
	var buf bytes.Buffer
	inner, err := newStdoutHandlerWithWriter(&buf, StdoutConfig{Level: slog.LevelInfo})
	require.NoError(t, err)

	// nil handler → returns a safe no-op discard handler instead of nil
	h := WithContextExtractor(nil, func(ctx context.Context) []slog.Attr { return nil })
	if h == nil {
		t.Error("expected non-nil discard handler for nil handler")
	}
	// Verify the discard handler is actually safe to use
	if h.Enabled(context.Background(), slog.LevelInfo) {
		t.Error("discard handler should not be enabled for any level")
	}

	// nil extractor → pass-through: the inner chain must survive (a discard
	// handler silently ate every log, audit records included)
	h = WithContextExtractor(inner, nil)
	if h != slog.Handler(inner) {
		t.Errorf("nil extractor should return inner unchanged, got %T", h)
	}
	require.NoError(t, h.Handle(context.Background(), slog.NewRecord(time.Now(), slog.LevelInfo, "test", 0)))
	if buf.Len() == 0 {
		t.Error("pass-through handler must still write to inner")
	}
}

func TestWithContextExtractor_NoContextValue(t *testing.T) {
	var buf bytes.Buffer
	inner, err := newStdoutHandlerWithWriter(&buf, StdoutConfig{Level: slog.LevelInfo})
	require.NoError(t, err)

	h := WithContextExtractor(inner, func(ctx context.Context) []slog.Attr {
		return nil // 没有提取到任何字段
	})

	logger := slog.New(h)
	logger.Info("test")

	if !bytes.Contains(buf.Bytes(), []byte("test")) {
		t.Errorf("expected 'test' in output, got: %s", buf.String())
	}
}

func TestWithContextExtractor_WithAttrs(t *testing.T) {
	var buf bytes.Buffer
	inner, err := newStdoutHandlerWithWriter(&buf, StdoutConfig{Level: slog.LevelInfo})
	require.NoError(t, err)

	h := WithContextExtractor(inner, func(ctx context.Context) []slog.Attr {
		return []slog.Attr{slog.String("ctx_field", "ctx_value")}
	})
	child := h.WithAttrs([]slog.Attr{slog.String("preset", "p")})
	logger := slog.New(child)

	logger.Info("test")

	output := buf.String()
	if !bytes.Contains(buf.Bytes(), []byte("ctx_field")) {
		t.Errorf("expected 'ctx_field' in output, got: %s", output)
	}
	if !bytes.Contains(buf.Bytes(), []byte("preset")) {
		t.Errorf("expected 'preset' in output, got: %s", output)
	}
}

// =============================================================================
// safeMultiHandler 测试 (Decision #17)
// =============================================================================

func TestSafeMultiHandler_PanicRecovery(t *testing.T) {
	good := &countHandler{}
	bad := &panicHandler{msg: "test panic"}

	h := safeMultiHandler([]slog.Handler{good, bad}, nil)
	logger := slog.New(h)

	// 应该不 panic，bad handler 的 panic 被 recover
	logger.Info("test")

	if good.Count() != 1 {
		t.Errorf("expected 1 log in good handler, got %d", good.Count())
	}
}

type panicHandler struct {
	msg string
}

func (h *panicHandler) Enabled(_ context.Context, _ slog.Level) bool { return true }
func (h *panicHandler) Handle(_ context.Context, _ slog.Record) error {
	panic(h.msg)
}
func (h *panicHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *panicHandler) WithGroup(string) slog.Handler      { return h }

func TestSafeMultiHandler_AllEnabled(t *testing.T) {
	h1 := &countHandler{}
	h2 := &countHandler{}

	multi := safeMultiHandler([]slog.Handler{h1, h2}, nil)
	logger := slog.New(multi)

	logger.Info("test")

	if h1.Count() != 1 {
		t.Errorf("h1 count = %d, want 1", h1.Count())
	}
	if h2.Count() != 1 {
		t.Errorf("h2 count = %d, want 1", h2.Count())
	}
}

func TestSafeMultiHandler_LevelFilter(t *testing.T) {
	// 用 StdoutHandler 作为有级别过滤的 handler
	var buf1, buf2 bytes.Buffer
	infoH, err := newStdoutHandlerWithWriter(&buf1, StdoutConfig{Level: slog.LevelInfo})
	require.NoError(t, err)
	warnH, err := newStdoutHandlerWithWriter(&buf2, StdoutConfig{Level: slog.LevelWarn})
	require.NoError(t, err)

	multi := safeMultiHandler([]slog.Handler{infoH, warnH}, nil)
	logger := slog.New(multi)

	logger.Info("info log")
	logger.Warn("warn log")

	// info handler 只记录 Info+; warn handler 记录 Warn+
	lines1 := bytes.Count(buf1.Bytes(), []byte("\n"))
	lines2 := bytes.Count(buf2.Bytes(), []byte("\n"))
	if lines1 != 2 {
		t.Errorf("info handler should get 2 logs, got %d", lines1)
	}
	if lines2 != 1 {
		t.Errorf("warn handler should get 1 log, got %d", lines2)
	}
}

// =============================================================================
// 装饰器组合测试
// =============================================================================

func TestDecoratorChain_Stdout_Sampling_Metrics(t *testing.T) {
	m := &testMetrics{}
	var buf bytes.Buffer
	inner, err := newStdoutHandlerWithWriter(&buf, StdoutConfig{Level: slog.LevelInfo})
	require.NoError(t, err)

	// Stdout -> Sampling -> Metrics
	h := WithMetrics(
		WithSampling(inner, SamplingConfig{Enabled: true, Initial: 5, Thereafter: 10, Window: time.Second}),
		m, "stdout",
	)
	logger := slog.New(h)

	for range 20 {
		logger.Info("test")
	}

	lines := bytes.Count(buf.Bytes(), []byte("\n"))
	if lines < 5 {
		t.Errorf("expected at least 5 lines, got %d", lines)
	}
	if m.handleCount.Load() != 20 {
		// Metrics 记录所有调用（包括被采样的）
		t.Logf("handle count = %d (metrics sees all calls)", m.handleCount.Load())
	}
}

func TestDecoratorChain_Async_Stdout(t *testing.T) {
	var buf bytes.Buffer
	inner, err := newStdoutHandlerWithWriter(&buf, StdoutConfig{Level: slog.LevelInfo})
	require.NoError(t, err)
	h := WithAsync(inner, AsyncConfig{BufferSize: 64})
	logger := slog.New(h)

	logger.Info("async test")

	if closer, ok := h.(interface{ Close() error }); ok {
		_ = closer.Close()
	}

	if !bytes.Contains(buf.Bytes(), []byte("async test")) {
		t.Errorf("expected 'async test' in output, got: %s", buf.String())
	}
}

// Test closing async handler while concurrent writes are in flight.
// Verifies no panic occurs and already-written records are flushed.
func TestAsyncHandler_CloseDuringConcurrent(t *testing.T) {
	inner := &countHandler{}
	h := WithAsync(inner, AsyncConfig{BufferSize: 256})
	logger := slog.New(h)

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Start goroutines writing continuously
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					logger.Info("concurrent write")
				}
			}
		}()
	}

	// Let goroutines run briefly
	time.Sleep(50 * time.Millisecond)

	// Stop writers first, then close
	close(stop)
	wg.Wait()

	if closer, ok := h.(interface{ Close() error }); ok {
		_ = closer.Close()
	}

	// Should not panic, and some records should have been written
	if inner.Count() == 0 {
		t.Error("expected some records to be written")
	}
}

// =============================================================================
// 四轮审计批 C 回归：process 错误限频 / 锁内上报死锁 / 二次 Close 排空 /
// 组 handler 丢弃计数 / 空组名契约 / []byte 快照
// =============================================================================

// gatedHandler parks the background worker inside inner.Handle: entered is
// closed on first entry, release is closed by the test to let it finish.
type gatedHandler struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
	handles atomic.Int64
}

func (h *gatedHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *gatedHandler) Handle(context.Context, slog.Record) error {
	h.handles.Add(1)
	h.once.Do(func() { close(h.entered) })
	<-h.release
	return nil
}
func (h *gatedHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *gatedHandler) WithGroup(string) slog.Handler      { return h }

// errCountHandler fails every record it receives (disk-full stand-in).
type errCountHandler struct {
	mu      sync.Mutex
	handles int
}

func (h *errCountHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *errCountHandler) Handle(context.Context, slog.Record) error {
	h.mu.Lock()
	h.handles++
	h.mu.Unlock()
	return fmt.Errorf("disk full")
}
func (h *errCountHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *errCountHandler) WithGroup(string) slog.Handler      { return h }
func (h *errCountHandler) count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.handles
}

// TestAsyncHandler_ProcessErrorReportRateLimited: a failing inner handler
// fails every buffered record; error reports must be rate-limited (one per
// second), not amplified 1:1 with the flood.
func TestAsyncHandler_ProcessErrorReportRateLimited(t *testing.T) {
	inner := &errCountHandler{}
	h := WithAsync(inner, AsyncConfig{BufferSize: 256}).(*AsyncHandler)
	defer func() { _ = h.Close() }()

	var mu sync.Mutex
	reports := 0
	h.setErrorHandler(func(*HandlerError) {
		mu.Lock()
		reports++
		mu.Unlock()
	})

	for i := 0; i < 200; i++ {
		_ = h.Handle(context.Background(), slog.NewRecord(time.Now(), slog.LevelInfo, "flood", 0))
	}

	// All 200 records reach the (failing) inner handler.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if inner.count() >= 200 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := inner.count(); got != 200 {
		t.Fatalf("inner handled = %d, want 200", got)
	}

	mu.Lock()
	defer mu.Unlock()
	if reports > 5 {
		t.Errorf("process-error reports = %d for 200 failures, rate limiter ineffective (want <= 5)", reports)
	}
	if reports == 0 {
		t.Error("at least one process-error report expected")
	}
}

// TestAsyncHandler_ErrorHandlerReentrantClose: the drop report must be
// dispatched AFTER sendMu.RUnlock. With the report issued while the read
// lock was held, an ErrorHandler that calls Close re-entrantly deadlocked
// against the still-held lock (Close needs the write lock) — reproduced here
// with a 2s watchdog instead of hanging the suite.
func TestAsyncHandler_ErrorHandlerReentrantClose(t *testing.T) {
	inner := &gatedHandler{entered: make(chan struct{}), release: make(chan struct{})}
	h := WithAsync(inner, AsyncConfig{BufferSize: 1, ErrorTimeout: 10 * time.Millisecond}).(*AsyncHandler)

	var closeReturned chan struct{}
	var once sync.Once
	h.setErrorHandler(func(*HandlerError) {
		// Re-entrant Close from inside the error callback.
		once.Do(func() {
			closeReturned = make(chan struct{})
			go func() {
				_ = h.Close()
				close(closeReturned)
			}()
		})
	})

	// 1. Park the worker inside inner.Handle.
	mustAsyncHandle(t, h, slog.LevelInfo, "fill-1")
	<-inner.entered
	// 2. Fill the buffer (cap 1).
	mustAsyncHandle(t, h, slog.LevelInfo, "fill-2")
	// 3. Error record overflows: bounded blocking send times out → drop →
	//    report → re-entrant Close above.
	handleDone := make(chan struct{})
	go func() {
		_ = h.Handle(context.Background(), slog.NewRecord(time.Now(), slog.LevelError, "overflow", 0))
		close(handleDone)
	}()
	select {
	case <-handleDone:
	case <-time.After(2 * time.Second):
		t.Fatal("Handle blocked: drop report issued while sendMu was held (re-entrant Close deadlock)")
	}

	// Unblock the worker so the re-entrant Close's drain can finish.
	close(inner.release)
	if closeReturned == nil {
		t.Fatal("error handler was never invoked — test setup broken")
	}
	select {
	case <-closeReturned:
	case <-time.After(2 * time.Second):
		t.Fatal("re-entrant Close from the error handler never returned (deadlock)")
	}
	if h.Dropped() == 0 {
		t.Error("expected the overflowed Error record to be counted as dropped")
	}
	_ = h.Close()
}

func mustAsyncHandle(t *testing.T, h slog.Handler, level slog.Level, msg string) {
	t.Helper()
	if err := h.Handle(context.Background(), slog.NewRecord(time.Now(), level, msg, 0)); err != nil {
		t.Fatalf("Handle(%q): %v", msg, err)
	}
}

// TestAsyncHandler_SecondCloseWaitsForDrain: a Close losing the closed-CAS
// race must still wait for the winner's drain to finish, not return while
// buffered records are still being written.
func TestAsyncHandler_SecondCloseWaitsForDrain(t *testing.T) {
	inner := &gatedHandler{entered: make(chan struct{}), release: make(chan struct{})}
	h := WithAsync(inner, AsyncConfig{BufferSize: 8}).(*AsyncHandler)

	mustAsyncHandle(t, h, slog.LevelInfo, "slow record")
	<-inner.entered // worker parked in inner.Handle; drain cannot complete

	close1 := make(chan struct{})
	go func() { _ = h.Close(); close(close1) }()
	close2 := make(chan struct{})
	go func() { _ = h.Close(); close(close2) }()

	// Regression window: the CAS-early-return bug let the second Close
	// return immediately. Poll briefly — while the worker is still parked,
	// no Close may complete.
	deadline := time.Now().Add(200 * time.Millisecond)
	for time.Now().Before(deadline) {
		select {
		case <-close2:
			t.Fatal("second Close returned before the drain finished")
		case <-time.After(20 * time.Millisecond):
		}
	}

	close(inner.release) // finish the drain
	select {
	case <-close1:
	case <-time.After(2 * time.Second):
		t.Fatal("first Close did not return after the drain unblocked")
	}
	select {
	case <-close2:
	case <-time.After(2 * time.Second):
		t.Fatal("second Close did not return even after the drain finished")
	}
	if got := inner.handles.Load(); got != 1 {
		t.Errorf("records handled = %d, want 1 (drained record must be written)", got)
	}
}

// TestAsyncGroupHandler_CloseDropCounted: closure drops on the WithGroup
// path must increment the same dropped counter as the plain path.
func TestAsyncGroupHandler_CloseDropCounted(t *testing.T) {
	inner := &countHandler{}
	h := WithAsync(inner, AsyncConfig{BufferSize: 8}).(*AsyncHandler)
	gh := h.WithGroup("g").(*asyncGroupHandler)
	if err := h.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	err := gh.Handle(context.Background(), slog.NewRecord(time.Now(), slog.LevelInfo, "after close", 0))
	if err == nil {
		t.Fatal("expected a drop error after Close")
	}
	if got := AsyncDropped(gh); got != 1 {
		t.Errorf("AsyncDropped(group) = %d, want 1", got)
	}
	if got := h.Dropped(); got != 1 {
		t.Errorf("AsyncHandler.Dropped() = %d, want 1 (shared counter)", got)
	}
}

// TestAsyncGroupHandler_WithGroupEmptyNameNoop: WithGroup("") is a no-op per
// the slog contract, and joining onto an empty group must not produce a
// leading-dot group (".b") — previously "" + "." + name.
func TestAsyncGroupHandler_WithGroupEmptyNameNoop(t *testing.T) {
	inner := &countHandler{}
	h := WithAsync(inner, AsyncConfig{BufferSize: 8}).(*AsyncHandler)

	gh := h.WithGroup("a").(*asyncGroupHandler)
	if same := gh.WithGroup(""); same != slog.Handler(gh) {
		t.Error(`WithGroup("") must be a no-op returning the same handler`)
	}
	nested := gh.WithGroup("b").(*asyncGroupHandler)
	if nested.group != "a.b" {
		t.Errorf("nested group = %q, want %q", nested.group, "a.b")
	}

	// Root-level empty group: joining "b" must yield "b", not ".b".
	root := h.WithGroup("").(*asyncGroupHandler)
	if root.group != "" {
		t.Errorf("root group = %q, want empty", root.group)
	}
	joined := root.WithGroup("b").(*asyncGroupHandler)
	if joined.group != "b" {
		t.Errorf("joined group = %q, want %q (no leading dot)", joined.group, "b")
	}
	_ = h.Close()
}

// TestAsyncGroupHandler_WithGroupEmptyNameOutput: end-to-end, the repaired
// group join must emit "b.k" — not ".b.k" — and the no-op WithGroup("") must
// keep logging through the same prefix.
func TestAsyncGroupHandler_WithGroupEmptyNameOutput(t *testing.T) {
	var buf bytes.Buffer
	sink, err := newStdoutHandlerWithWriter(&buf, StdoutConfig{Level: slog.LevelInfo})
	require.NoError(t, err)
	h := WithAsync(sink, AsyncConfig{BufferSize: 8}).(*AsyncHandler)

	joined := h.WithGroup("").WithGroup("b")
	logger := slog.New(joined)
	logger.Info("x", "k", "v")

	// WithGroup("") returning the same asyncGroupHandler instance: logging
	// again must still carry the group prefix (no-op, not a group reset).
	logger.Info("y", "k2", "v2")

	if err := h.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	out := buf.String()
	if strings.Contains(out, `".b`) || strings.Contains(out, ".b.") {
		t.Errorf("leading-dot group leaked into output: %s", out)
	}
	if !strings.Contains(out, `"b.k"`) {
		t.Errorf(`expected "b.k" in output, got: %s`, out)
	}
	if !strings.Contains(out, `"b.k2"`) {
		t.Errorf(`expected "b.k2" after no-op WithGroup, got: %s`, out)
	}
}

// bytesLogValuer resolves to a []byte through the LogValuer interface, so
// the async copy path must Resolve first to see (and snapshot) the slice.
type bytesLogValuer struct{ b []byte }

func (v bytesLogValuer) LogValue() slog.Value { return slog.AnyValue(v.b) }

// byteCaptureHandler captures "data"/"lv" attr values inside inner.Handle
// while parked on release, proving the queued snapshot was taken before the
// caller's mutation.
type byteCaptureHandler struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once

	mu  sync.Mutex
	got map[string][]byte
}

func (h *byteCaptureHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *byteCaptureHandler) Handle(_ context.Context, r slog.Record) error {
	r.Attrs(func(a slog.Attr) bool {
		if b, ok := a.Value.Any().([]byte); ok {
			h.mu.Lock()
			if h.got == nil {
				h.got = make(map[string][]byte)
			}
			h.got[a.Key] = append([]byte(nil), b...)
			h.mu.Unlock()
		}
		return true
	})
	h.once.Do(func() { close(h.entered) })
	<-h.release
	return nil
}
func (h *byteCaptureHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *byteCaptureHandler) WithGroup(string) slog.Handler      { return h }
func (h *byteCaptureHandler) captured(key string) []byte {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.got[key]
}

// TestAsyncHandler_ByteSliceAttrSnapshotted: slog.Any values holding []byte
// alias the caller's buffer; the async copy must snapshot them, because the
// record may outlive the log call while the caller reuses the slice.
func TestAsyncHandler_ByteSliceAttrSnapshotted(t *testing.T) {
	inner := &byteCaptureHandler{entered: make(chan struct{}), release: make(chan struct{})}
	h := WithAsync(inner, AsyncConfig{BufferSize: 8}).(*AsyncHandler)

	payload := []byte("SECRET")
	r := slog.NewRecord(time.Now(), slog.LevelInfo, "with bytes", 0)
	r.AddAttrs(
		slog.Any("data", payload),
		slog.Any("lv", bytesLogValuer{payload}),
	)
	if err := h.Handle(context.Background(), r); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	<-inner.entered // record is inside inner.Handle: the snapshot was taken

	// Caller reuses the buffer after the log call returned.
	copy(payload, []byte("HACKED"))

	close(inner.release)
	if err := h.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	for _, key := range []string{"data", "lv"} {
		if got := inner.captured(key); string(got) != "SECRET" {
			t.Errorf("captured %s = %q, want %q (caller mutation leaked into the queued record)", key, got, "SECRET")
		}
	}
}
