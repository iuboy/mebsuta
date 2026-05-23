package mebsuta

import (
	"context"
	"log/slog"
)

// ContextExtractor extracts slog.Attr values from a context.Context.
type ContextExtractor func(ctx context.Context) []slog.Attr

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
		r.AddAttrs(attrs...)
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
