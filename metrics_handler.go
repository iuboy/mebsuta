package mebsuta

import (
	"context"
	"log/slog"
	"time"
)

// HandlerMetrics defines the interface for collecting handler-level metrics such as latency, errors, and drops.
type HandlerMetrics interface {
	// ObserveHandle records the latency of a single Handle call.
	ObserveHandle(duration time.Duration)

	// IncError increments the error counter.
	IncError(handlerName string)

	// IncDropped increments the dropped-record counter.
	IncDropped(handlerName string)
}

// MetricsHandler is a slog.Handler decorator that records write latency and error counts via the HandlerMetrics interface.
type MetricsHandler struct {
	inner       slog.Handler
	metrics     HandlerMetrics
	handlerName string
}

// WithMetrics wraps inner in a MetricsHandler that observes latency and errors for the named handler.
func WithMetrics(inner slog.Handler, m HandlerMetrics, handlerName string) slog.Handler {
	if inner == nil || m == nil {
		return inner
	}
	return &MetricsHandler{
		inner:       inner,
		metrics:     m,
		handlerName: handlerName,
	}
}

func (h *MetricsHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.inner.Enabled(ctx, level)
}

func (h *MetricsHandler) Handle(ctx context.Context, r slog.Record) error {
	start := time.Now()
	err := h.inner.Handle(ctx, r)
	h.metrics.ObserveHandle(time.Since(start))
	if err != nil {
		h.metrics.IncError(h.handlerName)
	}
	return err
}

func (h *MetricsHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &MetricsHandler{
		inner:       h.inner.WithAttrs(attrs),
		metrics:     h.metrics,
		handlerName: h.handlerName,
	}
}

func (h *MetricsHandler) WithGroup(name string) slog.Handler {
	return &MetricsHandler{
		inner:       h.inner.WithGroup(name),
		metrics:     h.metrics,
		handlerName: h.handlerName,
	}
}

func (h *MetricsHandler) unwrapHandler() slog.Handler {
	return h.inner
}

func (h *MetricsHandler) setErrorHandler(fn ErrorHandler) {
	// MetricsHandler delegates error handling to its inner handler
}

var _ slog.Handler = (*MetricsHandler)(nil)
