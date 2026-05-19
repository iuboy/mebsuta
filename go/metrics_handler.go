package mebsuta

import (
	"context"
	"log/slog"
	"time"
)

// HandlerMetrics 定义日志 Handler 的指标收集接口，用户可注入 Prometheus 等后端。
type HandlerMetrics interface {
	// ObserveHandle 记录一次 Handle 调用的延迟。
	ObserveHandle(duration time.Duration)

	// IncError 增加错误计数。
	IncError(handlerName string)

	// IncDropped 增加丢弃计数。
	IncDropped(handlerName string)
}

// MetricsHandler 是 slog.Handler 装饰器，记录写入延迟和错误。
type MetricsHandler struct {
	inner       slog.Handler
	metrics     HandlerMetrics
	handlerName string
}

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

var _ slog.Handler = (*MetricsHandler)(nil)
