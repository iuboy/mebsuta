package mebsuta

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/iuboy/mebsuta/internal/handlerkit"
)

// ContextExtractor 从 context.Context 提取 slog.Attr 值。
//
// 提取器运行在日志调用路径上。panic 的提取器（如未检查的 ctx.Value
// 类型断言）会被恢复并经 ErrorHandler 上报；记录仍会写出，只是不带
// 提取的属性。
type ContextExtractor func(ctx context.Context) []slog.Attr

// contextExtractorHandler 是一个 slog.Handler 装饰器，向每条记录注入
// 从 context 提取的属性。它采用全委托模型：WithGroup/WithAttrs 转发给
// inner，提取的属性作为普通记录属性注入。group 前缀完全由内层 handler
// 负责，因此记录属性、WithAttrs 属性与提取属性都恰好获得一次 group
// 前缀。
type contextExtractorHandler struct {
	errorHandler *handlerkit.ErrorSlot // 克隆间共享
	inner        slog.Handler
	extract      ContextExtractor
}

// WithContextExtractor 包裹 inner，把从 context 提取的属性注入每条日志记录。
//
// nil 提取器是 no-op：原样返回 inner 而非换成丢弃 handler——因为一个
// nil 回调就静默丢弃整条输出链（包括审计记录）远比跳过注入糟糕。
// 若 inner 为 nil，返回 no-op 丢弃 handler。
func WithContextExtractor(inner slog.Handler, extract ContextExtractor) slog.Handler {
	if inner == nil {
		// 返回安全的丢弃 handler 而非 nil，防止调用方对结果调用
		// Handler 方法时 panic。
		return discardHandler{}
	}
	if extract == nil {
		return inner
	}
	return &contextExtractorHandler{
		errorHandler: handlerkit.NewErrorSlot(DefaultErrorHandler),
		inner:        inner,
		extract:      extract,
	}
}

func (h *contextExtractorHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.inner.Enabled(ctx, level)
}

// extractSafe 带 panic 恢复地运行用户提取器。提取器运行在调用方
// goroutine（本中间件在最外层时）还是异步 worker（提取器在 WithAsync
// 内层时）上，不应决定 panic 是否杀死进程——safeMulti 与异步 worker
// 都能遏制 handler panic，因此同步路径上唯一的用户回调获得同样的
// 遏制。
func (h *contextExtractorHandler) extractSafe(ctx context.Context) (attrs []slog.Attr) {
	defer func() {
		if p := recover(); p != nil {
			attrs = nil
			h.errorHandler.Report(&HandlerError{
				Component: "context", Operation: "extract",
				Err: fmt.Errorf("context extractor panic recovered, record logged without context attrs: %v", p),
			})
		}
	}()
	return h.extract(ctx)
}

func (h *contextExtractorHandler) Handle(ctx context.Context, r slog.Record) error {
	attrs := h.extractSafe(ctx)
	if len(attrs) == 0 {
		return h.inner.Handle(ctx, r)
	}
	// AddAttrs 前先克隆，避免修改调用方的记录（slog 契约）。
	// 内层 handler 对所有属性——记录属性、提取属性、WithAttrs 属性——
	// 统一应用 group 前缀，因此本地无需任何 group 跟踪。
	newR := r.Clone()
	newR.AddAttrs(attrs...)
	return h.inner.Handle(ctx, newR)
}

func (h *contextExtractorHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &contextExtractorHandler{
		errorHandler: h.errorHandler,
		inner:        h.inner.WithAttrs(attrs),
		extract:      h.extract,
	}
}

func (h *contextExtractorHandler) WithGroup(name string) slog.Handler {
	return &contextExtractorHandler{
		errorHandler: h.errorHandler,
		inner:        h.inner.WithGroup(name),
		extract:      h.extract,
	}
}

func (h *contextExtractorHandler) unwrapHandler() slog.Handler {
	return h.inner
}

func (h *contextExtractorHandler) setErrorHandler(fn ErrorHandler) {
	h.errorHandler.Store(fn)
	// propagateErrorHandler 也会经 unwrapHandler 递归触达 inner。
}

// discardHandler 是静默丢弃所有记录的 slog.Handler。
// 当 nil handler 被传给构造函数时，它作为安全默认值使用。
type discardHandler struct{}

func (discardHandler) Enabled(context.Context, slog.Level) bool  { return false }
func (discardHandler) Handle(context.Context, slog.Record) error { return nil }
func (d discardHandler) WithAttrs([]slog.Attr) slog.Handler      { return d }
func (d discardHandler) WithGroup(string) slog.Handler           { return d }

var (
	_ slog.Handler     = (*contextExtractorHandler)(nil)
	_ handlerUnwrapper = (*contextExtractorHandler)(nil)
)
