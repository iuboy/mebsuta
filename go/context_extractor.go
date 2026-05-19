package mebsuta

import (
	"context"
	"log/slog"
)

// ContextExtractor 从 context 提取 slog.Attr 列表。
type ContextExtractor func(ctx context.Context) []slog.Attr

type contextExtractorHandler struct {
	inner   slog.Handler
	extract ContextExtractor
}

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
		r.AddAttrs(attrs...)
	}
	return h.inner.Handle(ctx, r)
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

var _ slog.Handler = (*contextExtractorHandler)(nil)
