package mebsuta

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// samplingState tracks per-window counters for sampling decisions.
type samplingState struct {
	count   atomic.Int64
	ticker  *time.Ticker
	stopCh  chan struct{}
	wg      sync.WaitGroup
	stopped atomic.Bool
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
		ticker: time.NewTicker(cfg.Window),
		stopCh: make(chan struct{}),
	}
	s.wg.Add(1)
	go s.resetLoop()

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
func (h *SamplingHandler) Close() error {
	if !h.state.stopped.CompareAndSwap(false, true) {
		return nil
	}
	h.state.ticker.Stop()
	close(h.state.stopCh)
	h.state.wg.Wait()
	return nil
}

func (h *SamplingHandler) unwrapHandler() slog.Handler {
	return h.inner
}

func (h *SamplingHandler) setErrorHandler(fn ErrorHandler) {
	h.errorHandler.Store(&fn)
}

func (s *samplingState) resetLoop() {
	defer s.wg.Done()
	for {
		select {
		case <-s.ticker.C:
			s.count.Store(0)
		case <-s.stopCh:
			return
		}
	}
}

var (
	_ slog.Handler     = (*SamplingHandler)(nil)
	_ io.Closer        = (*SamplingHandler)(nil)
	_ handlerUnwrapper = (*SamplingHandler)(nil)
)
