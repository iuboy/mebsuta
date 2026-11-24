package mebsuta

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/iuboy/mebsuta/filerotate"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Handler Chain Integration Tests
// =============================================================================

// chainBuf wraps a bytes.Buffer with mutex for safe concurrent access in tests.
type chainBuf struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *chainBuf) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *chainBuf) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func (b *chainBuf) Lines() []string {
	raw := b.String()
	if raw == "" {
		return nil
	}
	result := splitLines(raw)
	return result
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			line := s[start:i]
			if line != "" {
				lines = append(lines, line)
			}
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

// parseJSONLines parses each line as JSON, returning a slice of maps.
func parseJSONLines(t *testing.T, lines []string) []map[string]any {
	t.Helper()
	result := make([]map[string]any, 0, len(lines))
	for _, line := range lines {
		var m map[string]any
		require.NoError(t, json.Unmarshal([]byte(line), &m), "invalid JSON line: %q", line)
		result = append(result, m)
	}
	return result
}

// TestChain_SamplingAsyncStdout verifies Sampling -> Async -> Stdout produces
// correctly sampled output with async buffering.
func TestChain_SamplingAsyncStdout(t *testing.T) {
	var buf chainBuf
	stdout, err := newStdoutHandlerWithWriter(&buf, StdoutConfig{Level: slog.LevelInfo})
	require.NoError(t, err)
	sampled := WithSampling(stdout, SamplingConfig{Enabled: true, Initial: 5, Thereafter: 3, Window: time.Second})
	async := WithAsync(sampled, AsyncConfig{BufferSize: 64})
	logger := slog.New(async)

	for i := range 20 {
		logger.Info("msg", "i", i)
	}

	require.NoError(t, CloseAll(logger.Handler()))

	lines := buf.Lines()
	entries := parseJSONLines(t, lines)

	// First 5 should all pass (Initial=5)
	var initialCount int
	for _, e := range entries {
		msg, _ := e["message"].(string)
		if msg == "msg" {
			attrs := e["attributes"].(map[string]any)
			i := int(attrs["i"].(float64))
			if i < 5 {
				initialCount++
			}
		}
	}
	require.Equal(t, 5, initialCount, "expected 5 initial records")

	// After initial, only every 3rd should pass (Thereafter=3)
	// Total expected: 5 (initial) + ~5 (sampled from remaining 15) = ~10
	require.LessOrEqual(t, len(entries), 15, "sampling should reduce output")
}

// TestChain_SamplingAsyncFile verifies Sampling -> Async -> File writes
// correctly to a file with sampling applied.
func TestChain_SamplingAsyncFile(t *testing.T) {
	dir := t.TempDir()
	fileH, err := NewFileHandler(filerotate.Config{Path: filepath.Join(dir, "test.log"), MaxSizeMB: 10}, FileConfig{})
	require.NoError(t, err)

	sampled := WithSampling(fileH, SamplingConfig{Enabled: true, Initial: 100, Thereafter: 10, Window: time.Second})
	async := WithAsync(sampled, AsyncConfig{BufferSize: 64})
	logger := slog.New(async)

	for i := range 50 {
		logger.Info("msg", "i", i)
	}

	require.NoError(t, CloseAll(logger.Handler()))

	data, err := os.ReadFile(filepath.Join(dir, "test.log"))
	require.NoError(t, err)
	lines := splitLines(string(data))
	require.Equal(t, 50, len(lines), "Initial=100 means all 50 should pass")
}

// TestChain_MetricsSamplingAsync verifies Metrics -> Sampling -> Async
// records metrics correctly through the chain.
func TestChain_MetricsSamplingAsync(t *testing.T) {
	var buf chainBuf
	stdout, err := newStdoutHandlerWithWriter(&buf, StdoutConfig{Level: slog.LevelInfo})
	require.NoError(t, err)
	mm := &mockMetrics{}

	sampled := WithSampling(stdout, SamplingConfig{Enabled: true, Initial: 100, Thereafter: 1, Window: time.Second})
	async := WithAsync(sampled, AsyncConfig{BufferSize: 64})
	metrics := WithMetrics(async, mm, "chain-test")

	logger := slog.New(metrics)
	for i := range 5 {
		logger.Info("metric msg", "i", i)
	}
	require.NoError(t, CloseAll(logger.Handler()))

	require.NotZero(t, mm.handleLatency, "MetricsHandler should have recorded handle latency")

	lines := buf.Lines()
	require.Equal(t, 5, len(lines), "expected 5 output lines")
}

// TestChain_MultiStdoutFile verifies Multi([Stdout, File]) fans out correctly.
func TestChain_MultiStdoutFile(t *testing.T) {
	var buf chainBuf
	stdout, err := newStdoutHandlerWithWriter(&buf, StdoutConfig{Level: slog.LevelInfo})
	require.NoError(t, err)

	dir := t.TempDir()
	fileH, err := NewFileHandler(filerotate.Config{Path: filepath.Join(dir, "test.log"), MaxSizeMB: 10}, FileConfig{})
	require.NoError(t, err)

	logger, err := New(
		WithHandler(stdout),
		WithHandler(fileH),
	)
	require.NoError(t, err)

	logger.Info("fanout test", "key", "value")
	require.NoError(t, CloseAll(logger.Handler()))

	// Stdout should have the message
	stdoutLines := buf.Lines()
	require.Len(t, stdoutLines, 1, "stdout: expected 1 line")
	entry := parseJSONLines(t, stdoutLines)
	require.Equal(t, "fanout test", entry[0]["message"], "stdout message")

	// File should also have the message
	data, err := os.ReadFile(filepath.Join(dir, "test.log"))
	require.NoError(t, err)
	fileLines := splitLines(string(data))
	require.Len(t, fileLines, 1, "file: expected 1 line")
}

// TestChain_ReverseOrderAsyncSampling verifies Async -> Sampling (reversed order)
// still works correctly, though behavior differs from Sampling -> Async.
func TestChain_ReverseOrderAsyncSampling(t *testing.T) {
	var buf chainBuf
	stdout, err := newStdoutHandlerWithWriter(&buf, StdoutConfig{Level: slog.LevelInfo})
	require.NoError(t, err)

	async := WithAsync(stdout, AsyncConfig{BufferSize: 64})
	sampled := WithSampling(async, SamplingConfig{Enabled: true, Initial: 3, Thereafter: 100, Window: time.Second})

	logger := slog.New(sampled)
	for i := range 10 {
		logger.Info("reverse", "i", i)
	}
	require.NoError(t, CloseAll(logger.Handler()))

	lines := buf.Lines()
	// With reversed order, sampling happens before async buffering.
	// Initial=3 means first 3 pass, rest are sampled away.
	require.Len(t, lines, 3, "expected 3 lines (Initial=3)")
}

// TestChain_AuditLevelNotDropped verifies Audit records pass through
// all decorator types without being dropped or sampled.
func TestChain_AuditLevelNotDropped(t *testing.T) {
	var buf chainBuf
	stdout, err := newStdoutHandlerWithWriter(&buf, StdoutConfig{Level: slog.LevelDebug})
	require.NoError(t, err)

	sampled := WithSampling(stdout, SamplingConfig{Enabled: true, Initial: 3, Thereafter: 1000, Window: time.Second})
	async := WithAsync(sampled, AsyncConfig{BufferSize: 64})

	logger := slog.New(async)

	// These should be sampled: only first 3 (Initial=3) pass
	for i := range 10 {
		logger.Info("normal msg", "i", i)
	}

	// Audit should bypass sampling (Level >= Error always passes)
	AuditFunc(logger, "audit event", "action", "login")

	require.NoError(t, CloseAll(logger.Handler()))

	lines := buf.Lines()
	entries := parseJSONLines(t, lines)

	// Audit must be present
	found := false
	for _, e := range entries {
		if e["message"] == "audit event" {
			found = true
			require.Equal(t, "AUDIT", e["level"], "audit level")
		}
	}
	require.True(t, found, "audit record not found in %d entries", len(entries))

	// Only 3 normal (Initial=3) + 1 audit = 4 total
	require.Len(t, entries, 4, "expected 4 entries (3 normal + 1 audit)")
}

// AuditFunc logs at Audit level using the provided logger directly.
func AuditFunc(logger *slog.Logger, msg string, args ...any) {
	logger.Log(context.Background(), slog.LevelError+4, msg, args...)
}

// TestChain_CloseAllPropagation verifies CloseAll propagates through
// the full decorator chain and closes all resources.
func TestChain_CloseAllPropagation(t *testing.T) {
	dir := t.TempDir()
	fileH, err := NewFileHandler(filerotate.Config{Path: filepath.Join(dir, "test.log"), MaxSizeMB: 10}, FileConfig{})
	require.NoError(t, err)

	sampled := WithSampling(fileH, SamplingConfig{Enabled: true, Initial: 100, Thereafter: 1, Window: time.Second})
	async := WithAsync(sampled, AsyncConfig{BufferSize: 64})

	logger := slog.New(async)
	logger.Info("before close")

	// CloseAll should: close Async (drain buffer) -> close Sampling (stop ticker) -> close File
	require.NoError(t, CloseAll(logger.Handler()))

	// Verify file was written before close
	data, err := os.ReadFile(filepath.Join(dir, "test.log"))
	require.NoError(t, err)
	require.NotEmpty(t, data, "file should have data after CloseAll")
}

// TestChain_AuditBypassesAsyncBuffer verifies that Error/Audit level records
// use blocking send in Async, not the non-blocking fast path.
func TestChain_AuditBypassesAsyncBuffer(t *testing.T) {
	var buf chainBuf
	stdout, err := newStdoutHandlerWithWriter(&buf, StdoutConfig{Level: slog.LevelDebug})
	require.NoError(t, err)

	// Tiny buffer to increase chance of drops for normal records
	async := WithAsync(stdout, AsyncConfig{BufferSize: 1})

	logger := slog.New(async)

	// Flood with normal records to fill the tiny buffer
	var wg sync.WaitGroup
	for i := range 100 {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			logger.Info("flood", "i", n)
		}(i)
	}
	wg.Wait()

	// Audit should still get through (blocking send with 5s timeout)
	AuditFunc(logger, "critical audit")

	require.NoError(t, CloseAll(logger.Handler()))

	lines := buf.Lines()
	// At minimum, the audit record must be present
	found := false
	for _, line := range lines {
		var m map[string]any
		if json.Unmarshal([]byte(line), &m) == nil {
			if m["message"] == "critical audit" {
				found = true
				break
			}
		}
	}
	require.True(t, found, "audit record not found in %d output lines", len(lines))
}

// mockSelfBuffered is a minimal handler implementing SelfBufferedHandler,
// used to test the generic rejection logic in WithAsync.
type mockSelfBuffered struct{}

func (h *mockSelfBuffered) Enabled(_ context.Context, _ slog.Level) bool { return true }
func (*mockSelfBuffered) SelfBuffered()                                  {}
func (*mockSelfBuffered) Handle(_ context.Context, _ slog.Record) error  { return nil }
func (h *mockSelfBuffered) WithAttrs(attrs []slog.Attr) slog.Handler     { return h }
func (h *mockSelfBuffered) WithGroup(name string) slog.Handler           { return h }

// TestChain_AsyncWrappingSelfBufferedRejected verifies WithAsync rejects any
// handler implementing SelfBufferedHandler.
func TestChain_AsyncWrappingSelfBufferedRejected(t *testing.T) {
	inner := &mockSelfBuffered{}
	result := WithAsync(inner, AsyncConfig{BufferSize: 64})

	_, isAsync := result.(*AsyncHandler)
	require.False(t, isAsync, "WithAsync should not wrap SelfBufferedHandler")
	require.Same(t, inner, result, "should return the original handler")
}

// TestChain_CloseAllThroughDecorators verifies CloseAll properly closes
// the inner handler through AttrsSub and GroupSub decorators.
func TestChain_CloseAllThroughDecorators(t *testing.T) {
	dir := t.TempDir()
	fileH, err := NewFileHandler(filerotate.Config{Path: filepath.Join(dir, "test.log"), MaxSizeMB: 10}, FileConfig{})
	require.NoError(t, err)

	// Wrap in WithAttrs and WithGroup
	withAttrs := fileH.WithAttrs([]slog.Attr{slog.String("key", "value")})
	withGroup := withAttrs.WithGroup("mygroup")

	logger := slog.New(withGroup)
	logger.Info("test message")

	// CloseAll should propagate through WithGroup -> WithAttrs -> FileHandler
	require.NoError(t, CloseAll(logger.Handler()))

	// Verify file was written and closed
	data, err := os.ReadFile(filepath.Join(dir, "test.log"))
	require.NoError(t, err)
	require.NotEmpty(t, data, "file should have data after CloseAll through decorators")
}

// closeCountHandler tracks how many times Close was called. It embeds handlerCore
// to opt into CloseAll deduplication (the contract built-in handlers satisfy).
type closeCountHandler struct {
	handlerCore
	closeCount atomic.Int32
	inner      slog.Handler
}

func (h *closeCountHandler) Enabled(ctx context.Context, lv slog.Level) bool {
	return h.inner.Enabled(ctx, lv)
}
func (h *closeCountHandler) Handle(ctx context.Context, r slog.Record) error {
	return h.inner.Handle(ctx, r)
}
func (h *closeCountHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &closeCountHandler{handlerCore: newHandlerCore(), inner: h.inner.WithAttrs(attrs)}
}
func (h *closeCountHandler) WithGroup(name string) slog.Handler {
	return &closeCountHandler{handlerCore: newHandlerCore(), inner: h.inner.WithGroup(name)}
}
func (h *closeCountHandler) Close() error {
	h.closeCount.Add(1)
	return nil
}

// TestCloseAll_SharedHandler_Dedup verifies that when fanout branches share the same
// terminal handler that opts into deduplication (handlerIdentifier), CloseAll calls
// Close only once.
func TestCloseAll_SharedHandler_Dedup(t *testing.T) {
	inner, err := NewStdoutHandler(StdoutConfig{})
	require.NoError(t, err)
	shared := &closeCountHandler{handlerCore: newHandlerCore(), inner: inner}

	// Build: safeMulti([shared, shared])
	multi := safeMultiHandler([]slog.Handler{shared, shared}, nil)

	err = CloseAll(multi)
	require.NoError(t, err)
	require.Equal(t, int32(1), shared.closeCount.Load(),
		"shared handler should be closed exactly once, got %d", shared.closeCount.Load())
}

// selfRefHandler implements handlerUnwrapper but returns itself from unwrapHandler.
// It deliberately does NOT implement handlerIdentifier, modeling a third-party
// handler. Termination is guaranteed by maxUnwrapDepth (not identity), and repeated
// Close calls are absorbed by idempotent Close — the documented contract for
// handlers that do not opt into deduplication.
type selfRefHandler struct {
	closed atomic.Bool
	count  atomic.Int32
}

func (h *selfRefHandler) Enabled(context.Context, slog.Level) bool  { return false }
func (h *selfRefHandler) Handle(context.Context, slog.Record) error { return nil }
func (h *selfRefHandler) WithAttrs(attrs []slog.Attr) slog.Handler  { return h }
func (h *selfRefHandler) WithGroup(name string) slog.Handler        { return h }
func (h *selfRefHandler) Close() error {
	if h.closed.CompareAndSwap(false, true) {
		h.count.Add(1)
	}
	return nil
}
func (h *selfRefHandler) unwrapHandler() slog.Handler { return h } // returns self!

// TestCloseAll_SelfReferencingHandler verifies that a handler whose unwrapHandler
// returns itself does not cause infinite recursion (terminated by maxUnwrapDepth),
// and that idempotent Close absorbs the repeated calls.
func TestCloseAll_SelfReferencingHandler(t *testing.T) {
	h := &selfRefHandler{}
	err := CloseAll(h)
	require.NoError(t, err)
	require.Equal(t, int32(1), h.count.Load(), "idempotent Close should record exactly one effective close")
}

// errorOnCloseHandler returns an error on Close for testing error aggregation.
type errorOnCloseHandler struct {
	err error
}

func (h *errorOnCloseHandler) Enabled(context.Context, slog.Level) bool  { return false }
func (h *errorOnCloseHandler) Handle(context.Context, slog.Record) error { return nil }
func (h *errorOnCloseHandler) WithAttrs(attrs []slog.Attr) slog.Handler  { return h }
func (h *errorOnCloseHandler) WithGroup(name string) slog.Handler        { return h }
func (h *errorOnCloseHandler) Close() error                              { return h.err }

// TestCloseAll_ErrorAggregation verifies CloseAll collects errors from all layers.
func TestCloseAll_ErrorAggregation(t *testing.T) {
	err1 := errors.New("close error 1")
	err2 := errors.New("close error 2")

	h1 := &errorOnCloseHandler{err: err1}
	h2 := &errorOnCloseHandler{err: err2}
	multi := safeMultiHandler([]slog.Handler{h1, h2}, nil)

	err := CloseAll(multi)
	require.Error(t, err)
	require.Contains(t, err.Error(), "close error 1")
	require.Contains(t, err.Error(), "close error 2")
}

// unwrapSpy tracks whether unwrapHandler was called.
type unwrapSpy struct {
	inner     slog.Handler
	unwrapped atomic.Int32
}

func (h *unwrapSpy) Enabled(ctx context.Context, lv slog.Level) bool { return h.inner.Enabled(ctx, lv) }
func (h *unwrapSpy) Handle(ctx context.Context, r slog.Record) error { return h.inner.Handle(ctx, r) }
func (h *unwrapSpy) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &unwrapSpy{inner: h.inner.WithAttrs(attrs)}
}
func (h *unwrapSpy) WithGroup(name string) slog.Handler {
	return &unwrapSpy{inner: h.inner.WithGroup(name)}
}
func (h *unwrapSpy) unwrapHandler() slog.Handler {
	h.unwrapped.Add(1)
	return h.inner
}

// TestCloseAll_UnwrapsMiddlewareChain verifies CloseAll recursively unwraps
// each middleware layer.
func TestCloseAll_UnwrapsMiddlewareChain(t *testing.T) {
	cfg := FileConfig{}
	fileH, err := NewFileHandler(filerotate.Config{Path: t.TempDir() + "/test.log"}, cfg)
	require.NoError(t, err)

	// Build: unwrapSpy -> Async -> File
	spy := &unwrapSpy{inner: fileH}

	err = CloseAll(spy)
	require.NoError(t, err)
	require.Equal(t, int32(1), spy.unwrapped.Load(), "unwrapHandler should be called once")
}

// plainHandler implements slog.Handler but neither handlerIdentifier nor
// handlerUnwrapper, modeling a third-party handler that does not opt into
// CloseAll deduplication.
type plainHandler struct{ _ int }

func (h *plainHandler) Enabled(context.Context, slog.Level) bool  { return false }
func (h *plainHandler) Handle(context.Context, slog.Record) error { return nil }
func (h *plainHandler) WithAttrs([]slog.Attr) slog.Handler        { return h }
func (h *plainHandler) WithGroup(string) slog.Handler             { return h }

// TestHandlerIdentity_NoFallbackForThirdParty verifies that a handler without
// handlerIdentifier yields no identity — closeAll does not attempt any unsafe
// or reflect-based probing. Such handlers are not deduplicated; cycle protection
// comes from maxUnwrapDepth and repeated Close is absorbed by idempotent Close.
func TestHandlerIdentity_NoFallbackForThirdParty(t *testing.T) {
	h := &plainHandler{}
	_, ok := handlerIdentity(h)
	require.False(t, ok, "third-party handler without handlerIdentifier must not get an identity")
}

// panickingSink 是 Handle 必 panic 的第三方 handler(B5)。
type panickingSink struct{}

func (panickingSink) Enabled(context.Context, slog.Level) bool  { return true }
func (panickingSink) Handle(context.Context, slog.Record) error { panic("sink boom") }
func (h panickingSink) WithAttrs([]slog.Attr) slog.Handler      { return h }
func (h panickingSink) WithGroup(string) slog.Handler           { return h }

type panickingError struct{}

func (panickingError) Error() string { panic("error boom") }

// TestNew_SingleHandlerPanicContained:默认形态的单 handler 链同样
// 获得 panic 遏制(B5)——此前 safeMulti 只在多输出链启用,会 panic 的
// 第三方 handler 直达调用方。
func TestNew_SingleHandlerPanicContained(t *testing.T) {
	var mu sync.Mutex
	var reported []string
	logger, err := New(WithHandler(panickingSink{}),
		WithErrorHandler(func(he *HandlerError) {
			mu.Lock()
			reported = append(reported, he.Err.Error())
			mu.Unlock()
		}))
	require.NoError(t, err)

	require.NotPanics(t, func() { logger.Info("x") }, "panic must be contained")
	mu.Lock()
	defer mu.Unlock()
	require.Len(t, reported, 1, "panic reported via ErrorHandler")
	require.Contains(t, reported[0], "sink boom")
}

// TestNew_SingleChainPanickingErrorValueContained:Error() 会 panic 的
// 属性值在单链(默认形态)下同样不得打穿调用方(B5)。
func TestNew_SingleChainPanickingErrorValueContained(t *testing.T) {
	var buf bytes.Buffer
	quiet, err := newStdoutHandlerWithWriter(&buf, StdoutConfig{})
	require.NoError(t, err)
	logger, err := New(WithHandler(quiet))
	require.NoError(t, err)

	require.NotPanics(t, func() { logger.Info("x", "err", panickingError{}) },
		"panicking error value must be contained")
}
