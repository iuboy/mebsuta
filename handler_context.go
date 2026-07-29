package mebsuta

import (
	"context"
	"log/slog"
)

// ContextExtractor extracts slog.Attr values from a context.Context.
type ContextExtractor func(ctx context.Context) []slog.Attr

// contextExtractorHandler is a slog.Handler decorator that injects context-derived
// attrs into each record. It uses a fully-delegating model: WithGroup/WithAttrs are
// forwarded to inner, and extracted attrs are injected as ordinary record attrs.
// The inner handler owns all group prefixing, so record attrs, WithAttrs attrs,
// and extracted attrs all receive the group prefix exactly once.
type contextExtractorHandler struct {
	inner   slog.Handler
	extract ContextExtractor
}

// WithContextExtractor wraps inner and injects attributes extracted from context into each log record.
// If inner is nil, a no-op discard handler is returned to avoid nil pointer panics.
func WithContextExtractor(inner slog.Handler, extract ContextExtractor) slog.Handler {
	if inner == nil || extract == nil {
		// Return a safe discard handler instead of nil to prevent panics
		// when callers invoke Handler methods on the result.
		return discardHandler{}
	}
	return &contextExtractorHandler{
		inner:   inner,
		extract: extract,
	}
}

func (h *contextExtractorHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.inner.Enabled(ctx, level)
}

func (h *contextExtractorHandler) Handle(ctx context.Context, r slog.Record) error {
	attrs := h.extract(ctx)
	if len(attrs) == 0 {
		return h.inner.Handle(ctx, r)
	}
	// Clone before AddAttrs to avoid mutating the caller's record (slog contract).
	// The inner handler applies group prefixing uniformly to all attrs — record,
	// extracted, and WithAttrs — so we don't need any local group tracking.
	newR := r.Clone()
	newR.AddAttrs(attrs...)
	return h.inner.Handle(ctx, newR)
}

func (h *contextExtractorHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &contextExtractorHandler{
		inner:   h.inner.WithAttrs(attrs),
		extract: h.extract,
	}
}

func (h *contextExtractorHandler) WithGroup(name string) slog.Handler {
	return &contextExtractorHandler{
		inner:   h.inner.WithGroup(name),
		extract: h.extract,
	}
}

func (h *contextExtractorHandler) unwrapHandler() slog.Handler {
	return h.inner
}

func (h *contextExtractorHandler) setErrorHandler(fn ErrorHandler) {
	// No-op: propagateErrorHandler recurses via unwrapHandler to reach the inner handler.
}

// discardHandler is a slog.Handler that silently discards all records.
// It is used as a safe default when a nil handler is passed to a constructor.
type discardHandler struct{}

func (discardHandler) Enabled(context.Context, slog.Level) bool  { return false }
func (discardHandler) Handle(context.Context, slog.Record) error { return nil }
func (d discardHandler) WithAttrs([]slog.Attr) slog.Handler      { return d }
func (d discardHandler) WithGroup(string) slog.Handler           { return d }

var (
	_ slog.Handler     = (*contextExtractorHandler)(nil)
	_ handlerUnwrapper = (*contextExtractorHandler)(nil)
)
