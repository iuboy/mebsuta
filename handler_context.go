package mebsuta

import (
	"context"
	"log/slog"
)

// ContextExtractor extracts slog.Attr values from a context.Context.
type ContextExtractor func(ctx context.Context) []slog.Attr

// contextExtractorHandler is a slog.Handler decorator that injects context-derived attrs into each record.
type contextExtractorHandler struct {
	inner   slog.Handler
	extract ContextExtractor
	group   string
}

// WithContextExtractor wraps inner and injects attributes extracted from context into each log record.
func WithContextExtractor(inner slog.Handler, extract ContextExtractor) slog.Handler {
	if inner == nil || extract == nil {
		return inner
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
	if len(attrs) > 0 {
		if h.group != "" {
			return h.inner.Handle(ctx, RecordWithGroupAttrs(r, h.group, attrs))
		}
		// slog handlers must not mutate the Record they receive — it is shared
		// with the caller and any sibling handlers (e.g. in a multi-output
		// fan-out). Clone before AddAttrs so injected attrs stay local.
		r2 := r.Clone()
		r2.AddAttrs(attrs...)
		return h.inner.Handle(ctx, r2)
	}
	return h.inner.Handle(ctx, r)
}

func (h *contextExtractorHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &contextExtractorHandler{
		inner:   h.inner.WithAttrs(attrs),
		extract: h.extract,
		group:   h.group,
	}
}

func (h *contextExtractorHandler) WithGroup(name string) slog.Handler {
	return &contextExtractorHandler{
		inner:   h.inner.WithGroup(name),
		extract: h.extract,
		group:   joinGroup(h.group, name),
	}
}

func (h *contextExtractorHandler) unwrapHandler() slog.Handler {
	return h.inner
}

func (h *contextExtractorHandler) setErrorHandler(fn ErrorHandler) {
	// No-op: propagateErrorHandler recurses via unwrapHandler to reach the inner handler.
}

// joinGroup joins two group names with a dot, returning the non-empty one if either is empty.
func joinGroup(parent, child string) string {
	if parent == "" {
		return child
	}
	if child == "" {
		return parent
	}
	return parent + "." + child
}

var (
	_ slog.Handler     = (*contextExtractorHandler)(nil)
	_ handlerUnwrapper = (*contextExtractorHandler)(nil)
)
