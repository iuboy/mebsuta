package mebsuta

import (
	"context"
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
//
// The sampling budget is shared across every logger derived from the same
// sampling chain (WithAttrs/WithGroup clones reuse one counter). A high-
// volume component can therefore consume the budget and suppress other
// components' sub-Error logs in the same window — that is inherent to the
// sampling semantics. Error and Audit records are exempt and always pass.
type SamplingHandler struct {
	handlerCore
	inner slog.Handler
	cfg   SamplingConfig
	state *samplingState
}

// WithSampling wraps inner in a SamplingHandler that drops log records according to the given SamplingConfig.
func WithSampling(inner slog.Handler, cfg SamplingConfig) slog.Handler {
	if !cfg.Enabled || inner == nil {
		return inner
	}
	// Validate always succeeds for SamplingConfig (it only applies defaults,
	// never returns errors), so we can safely ignore the error return.
	cfg, _ = cfg.Validate()

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
		newEnd := now + h.state.windowNanos
		if h.state.windowEnd.CompareAndSwap(windowEnd, newEnd) {
			h.state.count.Store(0)
		} else {
			// CAS lost: another goroutine advanced the window. If extreme clock
			// skew caused the new window end to also be in the past, try again.
			// This is best-effort — during clock anomalies it's safer to let all
			// records through than to silently drop them.
			advanced := h.state.windowEnd.Load()
			if now >= advanced {
				retryEnd := now + h.state.windowNanos
				h.state.windowEnd.CompareAndSwap(advanced, retryEnd)
			}
		}
		// Re-read count after potential reset: if we lost the CAS race, the
		// winner already reset the counter. Our Add(1) returns the post-increment
		// value, which will be ≤ concurrent goroutines that missed CAS, well
		// within the Initial budget.
		count := h.state.count.Add(1)
		if count <= int64(h.cfg.Initial) {
			return h.inner.Handle(ctx, r)
		}
		// Apply Thereafter consistently with the steady-state path so records
		// during the window-reset transition are sampled the same way.
		if (count-int64(h.cfg.Initial))%int64(h.cfg.Thereafter) == 0 {
			return h.inner.Handle(ctx, r)
		}
		return nil
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
// No-op: no background goroutine to stop (window reset is done lazily in Handle).
func (h *SamplingHandler) Close() error {
	return nil
}

func (h *SamplingHandler) unwrapHandler() slog.Handler {
	return h.inner
}

var (
	_ slog.Handler     = (*SamplingHandler)(nil)
	_ io.Closer        = (*SamplingHandler)(nil)
	_ handlerUnwrapper = (*SamplingHandler)(nil)
)
