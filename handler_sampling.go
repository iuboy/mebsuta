package mebsuta

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"sync/atomic"
	"time"
)

// samplingState tracks per-window counters for sampling decisions using atomic operations.
// Eliminates the need for a background goroutine by checking window expiry lazily in Handle.
type samplingState struct {
	count       atomic.Int64
	windowEnd   atomic.Int64 // unix nano timestamp of current window end
	windowNanos int64        // window duration in nanoseconds (immutable after init)
}

// SamplingHandler is a slog.Handler decorator that samples log records within a time window.
// Error and above are always recorded. The first Initial records per window pass through; thereafter 1 in Thereafter is kept.
type SamplingHandler struct {
	handlerCore
	inner        slog.Handler
	cfg          SamplingConfig
	state        *samplingState
	errorHandler atomic.Pointer[ErrorHandler]
}

// WithSampling wraps inner in a SamplingHandler that drops log records according to the given SamplingConfig.
func WithSampling(inner slog.Handler, cfg SamplingConfig) slog.Handler {
	if !cfg.Enabled || inner == nil {
		return inner
	}
	cfg, err := cfg.Validate()
	if err != nil {
		ReportError(DefaultErrorHandler, &HandlerError{Component: "sampling", Operation: "init", Err: fmt.Errorf("invalid config: %w", err)})
	}

	s := &samplingState{
		windowNanos: int64(cfg.Window),
	}
	s.windowEnd.Store(time.Now().Add(cfg.Window).UnixNano())

	return &SamplingHandler{
		handlerCore: newHandlerCore(),
		inner:       inner,
		cfg:         cfg,
		state:       s,
	}
}

// Enabled implements slog.Handler.
func (h *SamplingHandler) Enabled(ctx context.Context, level slog.Level) bool {
	// Error and Audit (LevelAudit > LevelError) records are never sampled.
	if level >= slog.LevelError {
		return true
	}
	return h.inner.Enabled(ctx, level)
}

// Handle implements slog.Handler.
func (h *SamplingHandler) Handle(ctx context.Context, r slog.Record) error {
	// Error and Audit (LevelAudit > LevelError) records are never sampled.
	if r.Level >= slog.LevelError {
		return h.inner.Handle(ctx, r)
	}

	// Check if window has expired and reset if needed.
	now := time.Now().UnixNano()
	windowEnd := h.state.windowEnd.Load()
	if now >= windowEnd {
		// CAS ensures only one goroutine advances the window and resets the counter.
		// Other goroutines that also see the expired window will pass their record
		// through (correct: the first record in a new window should always be logged).
		newEnd := now + h.state.windowNanos
		if h.state.windowEnd.CompareAndSwap(windowEnd, newEnd) {
			h.state.count.Store(0)
		}
		h.state.count.Add(1)
		return h.inner.Handle(ctx, r)
	}

	count := h.state.count.Add(1)
	if count <= int64(h.cfg.Initial) {
		return h.inner.Handle(ctx, r)
	}
	if (count-int64(h.cfg.Initial))%int64(h.cfg.Thereafter) == 0 {
		return h.inner.Handle(ctx, r)
	}
	return nil
}

// WithAttrs implements slog.Handler.
func (h *SamplingHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &SamplingHandler{
		handlerCore: newHandlerCore(),
		inner:       h.inner.WithAttrs(attrs),
		cfg:         h.cfg,
		state:       h.state,
	}
}

// WithGroup implements slog.Handler.
func (h *SamplingHandler) WithGroup(name string) slog.Handler {
	return &SamplingHandler{
		handlerCore: newHandlerCore(),
		inner:       h.inner.WithGroup(name),
		cfg:         h.cfg,
		state:       h.state,
	}
}

// Close implements io.Closer.
// The sampler owns no resources of its own, but the wrapped handler may
// (e.g. file/syslog/database). Delegate Close to the inner handler when it
// implements io.Closer so those resources are released; otherwise no-op.
func (h *SamplingHandler) Close() error {
	if c, ok := h.inner.(io.Closer); ok {
		return c.Close()
	}
	return nil
}

func (h *SamplingHandler) unwrapHandler() slog.Handler {
	return h.inner
}

func (h *SamplingHandler) setErrorHandler(fn ErrorHandler) {
	h.errorHandler.Store(&fn)
}

var (
	_ slog.Handler     = (*SamplingHandler)(nil)
	_ io.Closer        = (*SamplingHandler)(nil)
	_ handlerUnwrapper = (*SamplingHandler)(nil)
)
