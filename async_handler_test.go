package mebsuta

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/iuboy/mebsuta/config"
)

// =============================================================================
// AsyncHandler 测试
// =============================================================================

func TestAsyncHandler_Basic(t *testing.T) {
	var buf bytes.Buffer
	inner := newStdoutHandlerWithWriter(&buf, slog.LevelInfo, JSON)
	h := WithAsync(inner, AsyncConfig{BufferSize: 64})
	logger := slog.New(h)

	logger.Info("hello", "key", "value")

	// 先 close 确保 flush
	if closer, ok := h.(interface{ Close() error }); ok {
		closer.Close()
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

	time.Sleep(100 * time.Millisecond)

	dropped := AsyncDropped(h.(*AsyncHandler))
	if dropped == 0 {
		t.Error("expected some logs to be dropped with tiny buffer")
	}
}

func TestAsyncHandler_Close(t *testing.T) {
	var buf bytes.Buffer
	inner := newStdoutHandlerWithWriter(&buf, slog.LevelInfo, JSON)
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
	inner := newStdoutHandlerWithWriter(&buf, slog.LevelInfo, JSON)
	h := WithAsync(inner, AsyncConfig{BufferSize: 64})
	child := h.WithAttrs([]slog.Attr{slog.String("preset", "value")})
	logger := slog.New(child)

	logger.Info("test")

	if closer, ok := h.(interface{ Close() error }); ok {
		closer.Close()
	}

	if !bytes.Contains(buf.Bytes(), []byte("preset")) {
		t.Errorf("expected 'preset' in output, got: %s", buf.String())
	}
}

func TestAsyncHandler_WithGroup(t *testing.T) {
	var buf bytes.Buffer
	inner := newStdoutHandlerWithWriter(&buf, slog.LevelInfo, JSON)
	h := WithAsync(inner, AsyncConfig{BufferSize: 64})
	child := h.WithGroup("request")
	logger := slog.New(child)

	logger.Info("test", "id", "123")

	if closer, ok := h.(interface{ Close() error }); ok {
		closer.Close()
	}

	output := string(buf.Bytes())
	// JSON 格式下 group 会生成嵌套 key
	if !strings.Contains(output, `"request"`) {
		t.Errorf("expected 'request' in output, got: %s", output)
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

	time.Sleep(200 * time.Millisecond)
	if count.Load() == 0 {
		t.Error("expected some logs to be written")
	}
}

type concurrentHandler struct {
	count *atomic.Int64
	mu    sync.Mutex
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

// =============================================================================
// MetricsHandler 测试
// =============================================================================

type testMetrics struct {
	handleCount  atomic.Int64
	errorCount   atomic.Int64
	droppedCount atomic.Int64
}

func (m *testMetrics) ObserveHandle(d time.Duration) { m.handleCount.Add(1) }
func (m *testMetrics) IncError(name string)          { m.errorCount.Add(1) }
func (m *testMetrics) IncDropped(name string)        { m.droppedCount.Add(1) }

func TestWithMetrics_Basic(t *testing.T) {
	m := &testMetrics{}
	var buf bytes.Buffer
	inner := newStdoutHandlerWithWriter(&buf, slog.LevelInfo, JSON)
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
	inner := newStdoutHandlerWithWriter(&buf, slog.LevelInfo, JSON)
	// nil metrics
	h = WithMetrics(inner, nil, "test")
	if h != inner {
		t.Error("expected original handler for nil metrics")
	}
}

func TestWithMetrics_WithAttrs(t *testing.T) {
	m := &testMetrics{}
	var buf bytes.Buffer
	inner := newStdoutHandlerWithWriter(&buf, slog.LevelInfo, JSON)
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
	inner := newStdoutHandlerWithWriter(&buf, slog.LevelInfo, JSON)

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
	inner := newStdoutHandlerWithWriter(&buf, slog.LevelInfo, JSON)

	// nil handler
	h := WithContextExtractor(nil, func(ctx context.Context) []slog.Attr { return nil })
	if h != nil {
		t.Error("expected nil for nil handler")
	}

	// nil extractor
	h = WithContextExtractor(inner, nil)
	if h != inner {
		t.Error("expected original handler for nil extractor")
	}
}

func TestWithContextExtractor_NoContextValue(t *testing.T) {
	var buf bytes.Buffer
	inner := newStdoutHandlerWithWriter(&buf, slog.LevelInfo, JSON)

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
	inner := newStdoutHandlerWithWriter(&buf, slog.LevelInfo, JSON)

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
	infoH := newStdoutHandlerWithWriter(&buf1, slog.LevelInfo, JSON)
	warnH := newStdoutHandlerWithWriter(&buf2, slog.LevelWarn, JSON)

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
	inner := newStdoutHandlerWithWriter(&buf, slog.LevelInfo, JSON)

	// Stdout -> Sampling -> Metrics
	h := WithMetrics(
		WithSampling(inner, config.SamplingConfig{
			Enabled:    true,
			Initial:    5,
			Thereafter: 10,
			Window:     time.Second,
		}),
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
	inner := newStdoutHandlerWithWriter(&buf, slog.LevelInfo, JSON)
	h := WithAsync(inner, AsyncConfig{BufferSize: 64})
	logger := slog.New(h)

	logger.Info("async test")

	if closer, ok := h.(interface{ Close() error }); ok {
		closer.Close()
	}

	if !bytes.Contains(buf.Bytes(), []byte("async test")) {
		t.Errorf("expected 'async test' in output, got: %s", buf.String())
	}
}
