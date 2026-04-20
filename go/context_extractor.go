package mebsuta

import (
	"context"
	"log/slog"
)

// =============================================================================
// WithContextExtractor — Context 字段提取装饰器
// =============================================================================

// ContextExtractor 从 context 提取 slog.Attr 列表。
type ContextExtractor func(ctx context.Context) []slog.Attr

// contextExtractorHandler 是 slog.Handler 装饰器，从 context 提取字段附加到日志。
type contextExtractorHandler struct {
	inner   slog.Handler
	extract ContextExtractor
}

// WithContextExtractor 返回一个装饰器，在每次 Handle 时从 context 提取字段。
func WithContextExtractor(inner slog.Handler, extract ContextExtractor) slog.Handler {
	if inner == nil || extract == nil {
		return inner
	}
	return &contextExtractorHandler{
		inner:   inner,
		extract: extract,
	}
}

// Enabled 代理到内层 handler。
func (h *contextExtractorHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.inner.Enabled(ctx, level)
}

// Handle 从 context 提取字段，附加到 record 后传递给内层 handler。
func (h *contextExtractorHandler) Handle(ctx context.Context, r slog.Record) error {
	attrs := h.extract(ctx)
	if len(attrs) > 0 {
		r.AddAttrs(attrs...)
	}
	return h.inner.Handle(ctx, r)
}

// WithAttrs 链式传播到内层。
func (h *contextExtractorHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &contextExtractorHandler{
		inner:   h.inner.WithAttrs(attrs),
		extract: h.extract,
	}
}

// WithGroup 链式传播到内层。
func (h *contextExtractorHandler) WithGroup(name string) slog.Handler {
	return &contextExtractorHandler{
		inner:   h.inner.WithGroup(name),
		extract: h.extract,
	}
}

// unwrapHandler 返回内层 handler，供 CloseAll 递归关闭。
func (h *contextExtractorHandler) unwrapHandler() slog.Handler {
	return h.inner
}

// 编译期断言
var _ slog.Handler = (*contextExtractorHandler)(nil)
