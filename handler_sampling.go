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
		ReportError(DefaultErrorHandler, HandlerError{Component: "sampling", Operation: "init", Err: fmt.Errorf("invalid config: %w", err)})
	}

	s := &samplingState{
		windowNanos: int64(cfg.Window),
	}
	s.windowEnd.Store(time.Now().Add(cfg.Window).UnixNano())

	return &SamplingHandler{
		inner: inner,
		cfg:   cfg,
		state: s,
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

	count := h.state.count.Add(1)

	// Check if window has expired and reset if needed.
	now := time.Now().UnixNano()
	if now >= h.state.windowEnd.Load() {
		// Reset counter and advance window. CAS loop avoids double-reset on contention.
		h.state.count.Store(1)
		h.state.windowEnd.Store(now + h.state.windowNanos)
		return h.inner.Handle(ctx, r)
	}

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
		inner: h.inner.WithAttrs(attrs),
		cfg:   h.cfg,
		state: h.state,
	}
}

// WithGroup implements slog.Handler.
func (h *SamplingHandler) WithGroup(name string) slog.Handler {
	return &SamplingHandler{
		inner: h.inner.WithGroup(name),
		cfg:   h.cfg,
		state: h.state,
	}
}

// Close implements io.Closer.
// No-op: no background goroutine to stop (window reset is done lazily in Handle).
func (h *SamplingHandler) Close() error {
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
