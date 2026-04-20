package mebsuta

import (
	"context"
	"log/slog"
	"time"
)

// =============================================================================
// HandlerMetrics — 指标收集接口
// =============================================================================

// HandlerMetrics 定义日志 Handler 需要的指标收集接口。
// 用户可以注入 Prometheus 实现或其他后端。
type HandlerMetrics interface {
	// ObserveHandle 记录一次 Handle 调用的延迟。
	ObserveHandle(duration time.Duration)

	// IncError 增加错误计数。
	IncError(handlerName string)

	// IncDropped 增加丢弃计数。
	IncDropped(handlerName string)
}

// =============================================================================
// MetricsHandler — 指标装饰器
// =============================================================================

// MetricsHandler 是 slog.Handler 装饰器，记录写入延迟和错误。
type MetricsHandler struct {
	inner       slog.Handler
	metrics     HandlerMetrics
	handlerName string
}

// WithMetrics 返回一个指标装饰器，包裹给定的 handler。
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

// Enabled 代理到内层 handler。
func (h *MetricsHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.inner.Enabled(ctx, level)
}

// Handle 记录延迟指标后代理到内层 handler。
func (h *MetricsHandler) Handle(ctx context.Context, r slog.Record) error {
	start := time.Now()
	err := h.inner.Handle(ctx, r)
	h.metrics.ObserveHandle(time.Since(start))
	if err != nil {
		h.metrics.IncError(h.handlerName)
	}
	return err
}

// WithAttrs 链式传播到内层。
func (h *MetricsHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &MetricsHandler{
		inner:       h.inner.WithAttrs(attrs),
		metrics:     h.metrics,
		handlerName: h.handlerName,
	}
}

// WithGroup 链式传播到内层。
func (h *MetricsHandler) WithGroup(name string) slog.Handler {
	return &MetricsHandler{
		inner:       h.inner.WithGroup(name),
		metrics:     h.metrics,
		handlerName: h.handlerName,
	}
}

// unwrapHandler 返回内层 handler，供 CloseAll 递归关闭。
func (h *MetricsHandler) unwrapHandler() slog.Handler {
	return h.inner
}

// 编译期断言
var _ slog.Handler = (*MetricsHandler)(nil)
