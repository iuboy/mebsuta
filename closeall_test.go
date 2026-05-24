package mebsuta

import (
	"context"
	"errors"
	"log/slog"
	"sync/atomic"
	"testing"

	"github.com/iuboy/mebsuta/filerotate"
	"github.com/stretchr/testify/require"
)

// closeCountHandler tracks how many times Close was called.
type closeCountHandler struct {
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
	return &closeCountHandler{inner: h.inner.WithAttrs(attrs)}
}
func (h *closeCountHandler) WithGroup(name string) slog.Handler {
	return &closeCountHandler{inner: h.inner.WithGroup(name)}
}
func (h *closeCountHandler) Close() error {
	h.closeCount.Add(1)
	return nil
}

// TestCloseAll_SharedHandler_Dedup verifies that when fanout branches share the same
// terminal handler, CloseAll calls Close only once (visited map dedup).
func TestCloseAll_SharedHandler_Dedup(t *testing.T) {
	inner, err := NewStdoutHandler(StdoutConfig{})
	require.NoError(t, err)
	shared := &closeCountHandler{inner: inner}

	// Build: safeMulti([shared, shared])
	multi := safeMultiHandler([]slog.Handler{shared, shared}, nil)

	err = CloseAll(multi)
	require.NoError(t, err)
	require.Equal(t, int32(1), shared.closeCount.Load(),
		"shared handler should be closed exactly once, got %d", shared.closeCount.Load())
}

// selfRefHandler implements handlerUnwrapper but returns itself from unwrapHandler,
// which would cause infinite recursion without visited map protection.
type selfRefHandler struct {
	closed atomic.Int32
}

func (h *selfRefHandler) Enabled(context.Context, slog.Level) bool  { return false }
func (h *selfRefHandler) Handle(context.Context, slog.Record) error { return nil }
func (h *selfRefHandler) WithAttrs(attrs []slog.Attr) slog.Handler  { return h }
func (h *selfRefHandler) WithGroup(name string) slog.Handler        { return h }
func (h *selfRefHandler) Close() error {
	h.closed.Add(1)
	return nil
}
func (h *selfRefHandler) unwrapHandler() slog.Handler { return h } // returns self!

// TestCloseAll_SelfReferencingHandler verifies that a handler whose unwrapHandler
// returns itself does not cause infinite recursion.
func TestCloseAll_SelfReferencingHandler(t *testing.T) {
	h := &selfRefHandler{}
	err := CloseAll(h)
	require.NoError(t, err)
	require.Equal(t, int32(1), h.closed.Load(), "should close exactly once")
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
