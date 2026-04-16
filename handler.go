package mebsuta

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
)

// LevelHandler 提供所有 adapter Handler 共享的 Enabled 逻辑。
// 各 Handler 通过嵌入 LevelHandler 获得 level 过滤能力。
type LevelHandler struct {
	Level slog.Level
}

// Enabled 报告给定级别是否应该被记录。
func (h *LevelHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.Level
}

// =============================================================================
// HandlerOption — Handler 构造的函数式选项
// =============================================================================

// HandlerOption 配置 New() 的 Handler 组装。
type HandlerOption func(*handlerOptions) error

type handlerOptions struct {
	handlers     []slog.Handler
	errorHandler ErrorHandler
}

// WithHandler 添加一个 slog.Handler 到 multi-handler。
func WithHandler(h slog.Handler) HandlerOption {
	return func(o *handlerOptions) error {
		if h == nil {
			return fmt.Errorf("mebsuta: handler cannot be nil")
		}
		o.handlers = append(o.handlers, h)
		return nil
	}
}

// WithErrorHandler 设置 Handler 内部错误的处理函数。
// 默认写入 os.Stderr。设为 nil 则静默丢弃内部错误。
// nil 会传播到所有子 handler，使其内部错误也被静默丢弃。
func WithErrorHandler(fn ErrorHandler) HandlerOption {
	return func(o *handlerOptions) error {
		o.errorHandler = fn
		return nil
	}
}

// ReportError 安全调用 ErrorHandler，nil 时静默丢弃。
func ReportError(eh ErrorHandler, component string, err error) {
	if eh != nil {
		eh(component, err)
	}
}

// buildHandler 从选项构建 slog.Handler。
// 0 个 handler 返回 error。1 个直接返回。多个用 safeMultiHandler（带 panic recovery）。
func buildHandler(opts ...HandlerOption) (slog.Handler, error) {
	o := &handlerOptions{}
	for _, opt := range opts {
		if err := opt(o); err != nil {
			return nil, err
		}
	}
	if len(o.handlers) == 0 {
		return nil, fmt.Errorf("mebsuta: at least one handler is required")
	}

	// 传播 errorHandler 到所有支持它的 handler（包括 nil，实现全局静默）
	for _, h := range o.handlers {
		propagateErrorHandler(h, o.errorHandler)
	}

	if len(o.handlers) == 1 {
		return o.handlers[0], nil
	}
	return safeMultiHandler(o.handlers, o.errorHandler), nil
}

// safeMultiHandler 包装多个子 Handler，每个调用时加 panic recover。
// 防止单个 Handler panic 导致整个日志调用崩溃。(Decision #17)
func safeMultiHandler(handlers []slog.Handler, eh ErrorHandler) slog.Handler {
	return &safeMulti{
		handlers:     handlers,
		errorHandler: eh,
	}
}

type safeMulti struct {
	handlers     []slog.Handler
	errorHandler ErrorHandler
}

// Close 递归关闭所有实现 io.Closer 的子 handler。
func (h *safeMulti) Close() error {
	var errs []error
	for _, hh := range h.handlers {
		if closer, ok := hh.(io.Closer); ok {
			if err := closer.Close(); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

func (h *safeMulti) Enabled(ctx context.Context, level slog.Level) bool {
	for _, hh := range h.handlers {
		if hh.Enabled(ctx, level) {
			return true
		}
	}
	return false
}

func (h *safeMulti) Handle(ctx context.Context, r slog.Record) error {
	if len(h.handlers) == 1 {
		// 单 handler 直接串行调用，避免 goroutine 开销
		hh := h.handlers[0]
		if !hh.Enabled(ctx, r.Level) {
			return nil
		}
		defer func() {
			if r := recover(); r != nil {
				ReportError(h.errorHandler, "multi", fmt.Errorf("handler panic recovered: %v", r))
			}
		}()
		return hh.Handle(ctx, r)
	}

	var firstErr error
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, handler := range h.handlers {
		if !handler.Enabled(ctx, r.Level) {
			continue
		}
		wg.Add(1)
		go func(hh slog.Handler) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					ReportError(h.errorHandler, "multi", fmt.Errorf("handler panic recovered: %v", r))
				}
			}()
			if err := hh.Handle(ctx, r.Clone()); err != nil {
				mu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				mu.Unlock()
			}
		}(handler)
	}
	wg.Wait()
	return firstErr
}

func (h *safeMulti) WithAttrs(attrs []slog.Attr) slog.Handler {
	propagated := make([]slog.Handler, len(h.handlers))
	for i, hh := range h.handlers {
		propagated[i] = hh.WithAttrs(attrs)
	}
	return &safeMulti{
		handlers:     propagated,
		errorHandler: h.errorHandler,
	}
}

func (h *safeMulti) WithGroup(name string) slog.Handler {
	propagated := make([]slog.Handler, len(h.handlers))
	for i, hh := range h.handlers {
		propagated[i] = hh.WithGroup(name)
	}
	return &safeMulti{
		handlers:     propagated,
		errorHandler: h.errorHandler,
	}
}

// =============================================================================
// errorHandlerSetter — ErrorHandler 传播接口
// =============================================================================

// errorHandlerSetter 是支持自定义错误处理的 Handler 的内部接口。
type errorHandlerSetter interface {
	setErrorHandler(fn ErrorHandler)
}

// propagateErrorHandler 递归解包装饰器链，向所有支持 errorHandlerSetter 的 handler 注入 errorHandler。
func propagateErrorHandler(h slog.Handler, fn ErrorHandler) {
	if s, ok := h.(errorHandlerSetter); ok {
		s.setErrorHandler(fn)
	}
	if uw, ok := h.(handlerUnwrapper); ok {
		propagateErrorHandler(uw.unwrapHandler(), fn)
	}
}

// =============================================================================
// CloseAll — 递归关闭所有实现 io.Closer 的 Handler
// =============================================================================

// handlerUnwrapper 是装饰器实现的内部接口，用于 CloseAll 递归解包。
type handlerUnwrapper interface {
	unwrapHandler() slog.Handler
}

// CloseAll 递归关闭 handler 及其子 handler 中所有实现 io.Closer 的资源。
// 支持装饰器链解包（Sampling、Async、Metrics 等）。
// 用于进程退出前 flush 缓冲区、关闭文件和网络连接。
func CloseAll(handler slog.Handler) error {
	if handler == nil {
		return nil
	}
	var errs []error

	// 先关闭自身
	if closer, ok := handler.(io.Closer); ok {
		if err := closer.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	// 递归关闭内层 handler（装饰器链）
	if uw, ok := handler.(handlerUnwrapper); ok {
		if err := CloseAll(uw.unwrapHandler()); err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}
