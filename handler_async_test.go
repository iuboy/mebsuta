package mebsuta

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
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

	require.Contains(t, buf.String(), "hello")
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

	dropped := Dropped(h.(*AsyncHandler))
	require.NotZero(t, dropped, "expected some logs to be dropped with tiny buffer")
}

func TestAsyncHandler_Close(t *testing.T) {
	var buf bytes.Buffer
	inner, err := newStdoutHandlerWithWriter(&buf, StdoutConfig{Level: slog.LevelInfo})
	require.NoError(t, err)
	h := WithAsync(inner, AsyncConfig{BufferSize: 64})
	logger := slog.New(h)

	logger.Info("before close")

	if closer, ok := h.(interface{ Close() error }); ok {
		require.NoError(t, closer.Close(), "Close() error")
		// 双重关闭
		require.NoError(t, closer.Close(), "double Close() error")
	}

	require.Contains(t, buf.String(), "before close", "log before close should be written")
}

func TestAsyncHandler_NilHandler(t *testing.T) {
	h := WithAsync(nil, AsyncConfig{})
	require.Nil(t, h, "expected nil for nil handler")
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

	require.Contains(t, buf.String(), "preset")
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
	require.Contains(t, output, `"request.id"`)
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

	require.NotZero(t, count.Load(), "expected some logs to be written")
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
	dropped := Dropped(&StdoutHandler{})
	require.Zero(t, dropped, "expected 0 for non-async handler")
}

func TestAsyncHandler_AuditNotDropped(t *testing.T) {
	// SPEC P0: Error and Audit records must not be dropped by buffer full.
	inner := &countHandler{}
	h := WithAsync(inner, AsyncConfig{BufferSize: 1}) // tiny buffer

	// Fill the buffer with normal records
	require.NoError(t, h.Handle(context.Background(), slog.NewRecord(time.Now(), slog.LevelInfo, "fill", 0)), "Handle fill")

	// Error/Audit should still be delivered (blocking path retries)
	r := slog.NewRecord(time.Now(), slog.LevelError, "error record", 0)
	require.NoError(t, h.Handle(context.Background(), r), "Handle error")

	if closer, ok := h.(interface{ Close() error }); ok {
		_ = closer.Close()
	}

	errorCount := inner.ErrorLevelCount()
	require.GreaterOrEqual(t, errorCount, int64(1), "expected at least 1 error-level record")
}

func TestAsyncHandler_AuditLevelNotDropped(t *testing.T) {
	inner := &countHandler{}
	h := WithAsync(inner, AsyncConfig{BufferSize: 1})

	require.NoError(t, h.Handle(context.Background(), slog.NewRecord(time.Now(), slog.LevelInfo, "fill", 0)), "Handle fill")

	r := slog.NewRecord(time.Now(), slog.LevelError+4, "audit record", 0)
	require.NoError(t, h.Handle(context.Background(), r), "Handle audit")

	if closer, ok := h.(interface{ Close() error }); ok {
		_ = closer.Close()
	}

	errorCount := inner.ErrorLevelCount()
	require.GreaterOrEqual(t, errorCount, int64(1), "expected at least 1 audit-level record")
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

	require.Equal(t, int64(1), m.handleCount.Load(), "expected 1 handle")
}

func TestWithMetrics_NilInputs(t *testing.T) {
	m := &testMetrics{}
	// nil handler
	h := WithMetrics(nil, m, "test")
	require.Nil(t, h, "expected nil for nil handler")

	var buf bytes.Buffer
	inner, err := newStdoutHandlerWithWriter(&buf, StdoutConfig{Level: slog.LevelInfo})
	require.NoError(t, err)
	// nil metrics
	h = WithMetrics(inner, nil, "test")
	require.Equal(t, inner, h, "expected original handler for nil metrics")
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

	require.Equal(t, int64(1), m.handleCount.Load(), "expected 1 handle")
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

	require.Contains(t, buf.String(), "abc-123")
}

func TestWithContextExtractor_NilInputs(t *testing.T) {
	var buf bytes.Buffer
	inner, err := newStdoutHandlerWithWriter(&buf, StdoutConfig{Level: slog.LevelInfo})
	require.NoError(t, err)

	// nil handler → returns a safe no-op discard handler instead of nil
	h := WithContextExtractor(nil, func(ctx context.Context) []slog.Attr { return nil })
	require.NotNil(t, h, "expected non-nil discard handler for nil handler")
	// Verify the discard handler is actually safe to use
	require.False(t, h.Enabled(context.Background(), slog.LevelInfo), "discard handler should not be enabled for any level")

	// nil extractor → pass-through: the inner chain must survive (a discard
	// handler silently ate every log, audit records included)
	h = WithContextExtractor(inner, nil)
	require.Equal(t, slog.Handler(inner), h, "nil extractor should return inner unchanged, got %T", h)
	require.NoError(t, h.Handle(context.Background(), slog.NewRecord(time.Now(), slog.LevelInfo, "test", 0)))
	require.NotEmpty(t, buf, "pass-through handler must still write to inner")
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

	require.Contains(t, buf.String(), "test")
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
	require.Contains(t, output, "ctx_field")
	require.Contains(t, output, "preset")
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

	require.Equal(t, 1, good.Count(), "expected 1 log in good handler")
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

	require.Equal(t, 1, h1.Count(), "h1 count")
	require.Equal(t, 1, h2.Count(), "h2 count")
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
	require.Equal(t, 2, lines1, "info handler should get 2 logs")
	require.Equal(t, 1, lines2, "warn handler should get 1 log")
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
	require.GreaterOrEqual(t, lines, 5, "expected at least 5 lines")
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

	require.Contains(t, buf.String(), "async test")
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
	require.NotZero(t, inner.Count(), "expected some records to be written")
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
	h.SetErrorHandler(func(*HandlerError) {
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
	require.Equal(t, 200, inner.count(), "inner handled")

	mu.Lock()
	defer mu.Unlock()
	require.LessOrEqual(t, reports, 5, "process-error reports for 200 failures, rate limiter ineffective")
	require.NotZero(t, reports, "at least one process-error report expected")
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
	h.SetErrorHandler(func(*HandlerError) {
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
		require.FailNow(t, "Handle blocked: drop report issued while sendMu was held (re-entrant Close deadlock)")
	}

	// Unblock the worker so the re-entrant Close's drain can finish.
	close(inner.release)
	require.NotNil(t, closeReturned, "error handler was never invoked — test setup broken")
	select {
	case <-closeReturned:
	case <-time.After(2 * time.Second):
		require.FailNow(t, "re-entrant Close from the error handler never returned (deadlock)")
	}
	require.NotZero(t, h.Dropped(), "expected the overflowed Error record to be counted as dropped")
	_ = h.Close()
}

func mustAsyncHandle(t *testing.T, h slog.Handler, level slog.Level, msg string) {
	t.Helper()
	require.NoError(t, h.Handle(context.Background(), slog.NewRecord(time.Now(), level, msg, 0)), "Handle(%q)", msg)
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
			require.FailNow(t, "second Close returned before the drain finished")
		case <-time.After(20 * time.Millisecond):
		}
	}

	close(inner.release) // finish the drain
	select {
	case <-close1:
	case <-time.After(2 * time.Second):
		require.FailNow(t, "first Close did not return after the drain unblocked")
	}
	select {
	case <-close2:
	case <-time.After(2 * time.Second):
		require.FailNow(t, "second Close did not return even after the drain finished")
	}
	require.Equal(t, int64(1), inner.handles.Load(), "records handled (drained record must be written)")
}

// TestAsyncGroupHandler_CloseDropCounted: closure drops on the WithGroup
// path must increment the same dropped counter as the plain path.
func TestAsyncGroupHandler_CloseDropCounted(t *testing.T) {
	inner := &countHandler{}
	h := WithAsync(inner, AsyncConfig{BufferSize: 8}).(*AsyncHandler)
	gh := h.WithGroup("g").(*asyncGroupHandler)
	require.NoError(t, h.Close(), "Close")

	err := gh.Handle(context.Background(), slog.NewRecord(time.Now(), slog.LevelInfo, "after close", 0))
	require.Error(t, err, "expected a drop error after Close")
	require.Equal(t, int64(1), Dropped(gh), "Dropped(group)")
	require.Equal(t, int64(1), h.Dropped(), "AsyncHandler.Dropped() (shared counter)")
}

// TestAsyncGroupHandler_WithGroupEmptyNameNoop: WithGroup("") is a no-op per
// the slog contract, and joining onto an empty group must not produce a
// leading-dot group (".b") — previously "" + "." + name.
func TestAsyncGroupHandler_WithGroupEmptyNameNoop(t *testing.T) {
	inner := &countHandler{}
	h := WithAsync(inner, AsyncConfig{BufferSize: 8}).(*AsyncHandler)

	gh := h.WithGroup("a").(*asyncGroupHandler)
	require.Equal(t, slog.Handler(gh), gh.WithGroup(""), `WithGroup("") must be a no-op returning the same handler`)
	nested := gh.WithGroup("b").(*asyncGroupHandler)
	require.Equal(t, "a.b", nested.group, "nested group")

	// Root-level empty group: joining "b" must yield "b", not ".b".
	root := h.WithGroup("").(*asyncGroupHandler)
	require.Equal(t, "", root.group, "root group")
	joined := root.WithGroup("b").(*asyncGroupHandler)
	require.Equal(t, "b", joined.group, "joined group (no leading dot)")
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

	require.NoError(t, h.Close(), "Close")

	out := buf.String()
	require.NotContains(t, out, `".b`, "leading-dot group leaked into output")
	require.NotContains(t, out, ".b.", "leading-dot group leaked into output")
	require.Contains(t, out, `"b.k"`)
	require.Contains(t, out, `"b.k2"`, `expected "b.k2" after no-op WithGroup`)
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
	require.NoError(t, h.Handle(context.Background(), r), "Handle")
	<-inner.entered // record is inside inner.Handle: the snapshot was taken

	// Caller reuses the buffer after the log call returned.
	copy(payload, []byte("HACKED"))

	close(inner.release)
	require.NoError(t, h.Close(), "Close")

	for _, key := range []string{"data", "lv"} {
		require.Equal(t, "SECRET", string(inner.captured(key)), "captured %s (caller mutation leaked into the queued record)", key)
	}
}

// TestAsyncHandler_InnerPanicRecovered: a panicking third-party inner handler
// must not kill the background goroutine (and the process).
func TestAsyncHandler_InnerPanicRecovered(t *testing.T) {
	var mu sync.Mutex
	handled := 0
	inner := regressPanicHandler{onHandle: func() { mu.Lock(); handled++; mu.Unlock() }}

	h := WithAsync(inner, AsyncConfig{BufferSize: 4}).(*AsyncHandler)
	defer func() { _ = h.Close() }() // best-effort drain; the assertion above already checked the count

	logger := slog.New(h)
	logger.Info("before")
	logger.Info("boom") // panics in inner
	logger.Info("after")

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := handled
		mu.Unlock()
		if n == 3 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	require.Equal(t, 3, handled, "records handled (panic must not stop the worker)")
}

type regressPanicHandler struct{ onHandle func() }

func (p regressPanicHandler) Enabled(context.Context, slog.Level) bool { return true }

func (p regressPanicHandler) Handle(_ context.Context, r slog.Record) error {
	p.onHandle()
	if r.Message == "boom" {
		panic("inner handler exploded")
	}
	return nil
}

func (p regressPanicHandler) WithAttrs([]slog.Attr) slog.Handler { return p }
func (p regressPanicHandler) WithGroup(string) slog.Handler      { return p }

// TestAsyncHandler_CloseDrainsWithLiveContext is the regression test for the
// Close ordering bug: Close previously cancelled the context before draining,
// so ctx-aware inner handlers dropped the final batch. The drained records
// must now observe a live (non-cancelled) context.
func TestAsyncHandler_CloseDrainsWithLiveContext(t *testing.T) {
	var mu sync.Mutex
	var gotErrs []error
	inner := ctxProbeHandler{onHandle: func(err error) {
		mu.Lock()
		defer mu.Unlock()
		gotErrs = append(gotErrs, err)
	}}

	h := WithAsync(inner, AsyncConfig{BufferSize: 8}).(*AsyncHandler)
	logger := slog.New(h)
	for i := range 5 {
		logger.Info(fmt.Sprintf("record %d", i))
	}

	require.NoError(t, h.Close(), "Close")

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, gotErrs, 5, "drained records")
	for i, err := range gotErrs {
		require.NoError(t, err, "record %d saw cancelled context during Close drain", i)
	}
}

type ctxProbeHandler struct{ onHandle func(error) }

func (c ctxProbeHandler) Enabled(context.Context, slog.Level) bool { return true }
func (c ctxProbeHandler) Handle(ctx context.Context, _ slog.Record) error {
	c.onHandle(ctx.Err())
	return nil
}
func (c ctxProbeHandler) WithAttrs([]slog.Attr) slog.Handler { return c }
func (c ctxProbeHandler) WithGroup(string) slog.Handler      { return c }

// TestAsyncHandler_DropReportRateLimited: a flood that overflows the buffer
// must not produce one error-handler invocation per dropped record.
func TestAsyncHandler_DropReportRateLimited(t *testing.T) {
	block := make(chan struct{})
	inner := blockingHandler{block: block}

	h := WithAsync(inner, AsyncConfig{BufferSize: 2}).(*AsyncHandler)
	// Unblock the worker BEFORE Close (defers run LIFO: h.Close would wait
	// forever on a worker parked on block).
	defer func() { close(block); _ = h.Close() }()

	var mu sync.Mutex
	reports := 0
	h.SetErrorHandler(func(*HandlerError) {
		mu.Lock()
		defer mu.Unlock()
		reports++
	})

	logger := slog.New(h)
	// Fill the buffer (worker blocked), then overflow heavily.
	for i := 0; i < 200; i++ {
		logger.Info("flood")
	}

	mu.Lock()
	defer mu.Unlock()
	require.LessOrEqual(t, reports, 2, "drop reports for ~198 drops, rate limiter not effective")
	require.GreaterOrEqual(t, h.Dropped(), int64(190), "dropped counter, want the flood losses counted")
}

type blockingHandler struct{ block chan struct{} }

func (b blockingHandler) Enabled(context.Context, slog.Level) bool { return true }
func (b blockingHandler) Handle(context.Context, slog.Record) error {
	<-b.block
	return nil
}
func (b blockingHandler) WithAttrs([]slog.Attr) slog.Handler { return b }
func (b blockingHandler) WithGroup(string) slog.Handler      { return b }

// TestAsyncGroupHandler_CloseDrainsWithLiveContext is the regression test for
// the fix gap: the WithoutCancel change initially covered only the plain
// path — the WithGroup path still forwarded the raw request ctx, so ctx-aware
// inner handlers dropped records queued during Close's drain.
func TestAsyncGroupHandler_CloseDrainsWithLiveContext(t *testing.T) {
	var mu sync.Mutex
	var gotErrs []error
	inner := ctxProbeHandler2{onHandle: func(err error) {
		mu.Lock()
		defer mu.Unlock()
		gotErrs = append(gotErrs, err)
	}}

	h := WithAsync(inner, AsyncConfig{BufferSize: 8}).(*AsyncHandler)
	grouped := h.WithGroup("audit")
	for i := 0; i < 5; i++ {
		// Cancelled request contexts must not leak cancellation into the
		// drained records.
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		r := slog.NewRecord(time.Now(), slog.LevelInfo, "g", 0)
		require.NoError(t, grouped.Handle(ctx, r), "Handle")
	}

	require.NoError(t, h.Close(), "Close")

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, gotErrs, 5, "drained records")
	for i, err := range gotErrs {
		require.NoError(t, err, "record %d saw cancelled context during Close drain", i)
	}
}

type traceKey struct{}

// TestAsyncHandler_ConcurrentCloseSendRace exercises the sendMu design: close
// racing with in-flight sends must be race-detector-clean (the previous
// close+recover design reported DATA RACE under -race).
func TestAsyncHandler_ConcurrentCloseSendRace(t *testing.T) {
	for range 20 {
		inner := ctxProbeHandler2{onHandle: func(error) {}}
		h := WithAsync(inner, AsyncConfig{BufferSize: 4}).(*AsyncHandler)
		var wg sync.WaitGroup
		for i := 0; i < 4; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := 0; j < 50; j++ {
					r := slog.NewRecord(time.Now(), slog.LevelInfo, "m", 0)
					_ = h.Handle(context.Background(), r)
				}
			}()
		}
		_ = h.Close()
		wg.Wait()
	}
}
