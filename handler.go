package mebsuta

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"reflect"
	"sync"
	"sync/atomic"
	"time"
)

// HandlerOption is a functional option for configuring the handler chain built by New.
type HandlerOption func(*handlerOptions) error

type handlerOptions struct {
	handlers     []slog.Handler
	middlewares  []func(slog.Handler) slog.Handler
	errorHandler ErrorHandler
}

// WithHandler adds a slog.Handler to the multi-handler chain.
func WithHandler(h slog.Handler) HandlerOption {
	return func(o *handlerOptions) error {
		if h == nil {
			return fmt.Errorf("mebsuta: handler cannot be nil")
		}
		o.handlers = append(o.handlers, h)
		return nil
	}
}

// UseStdout adds a StdoutHandler with the given config.
func UseStdout(cfg StdoutConfig) HandlerOption {
	return func(o *handlerOptions) error {
		o.handlers = append(o.handlers, NewStdoutHandler(cfg))
		return nil
	}
}

// UseFile adds a FileHandler with the given config.
func UseFile(cfg FileConfig) HandlerOption {
	return func(o *handlerOptions) error {
		h, err := NewFileHandler(cfg)
		if err != nil {
			return err
		}
		o.handlers = append(o.handlers, h)
		return nil
	}
}

// UseAsync wraps the handler chain with async buffering.
func UseAsync(cfg AsyncConfig) HandlerOption {
	return func(o *handlerOptions) error {
		o.middlewares = append(o.middlewares, func(inner slog.Handler) slog.Handler {
			return WithAsync(inner, cfg)
		})
		return nil
	}
}

// UseSampling wraps the handler chain with time-window sampling.
func UseSampling(cfg SamplingConfig) HandlerOption {
	return func(o *handlerOptions) error {
		o.middlewares = append(o.middlewares, func(inner slog.Handler) slog.Handler {
			return WithSampling(inner, cfg)
		})
		return nil
	}
}

// UseMetrics wraps the handler chain with Prometheus metrics collection.
func UseMetrics(m HandlerMetrics, name string) HandlerOption {
	return func(o *handlerOptions) error {
		o.middlewares = append(o.middlewares, func(inner slog.Handler) slog.Handler {
			return WithMetrics(inner, m, name)
		})
		return nil
	}
}

// UseContextExtractor injects context-derived attributes into each log record.
func UseContextExtractor(extract ContextExtractor) HandlerOption {
	return func(o *handlerOptions) error {
		o.middlewares = append(o.middlewares, func(inner slog.Handler) slog.Handler {
			return WithContextExtractor(inner, extract)
		})
		return nil
	}
}

// WithErrorHandler 设置 Handler 内部错误的处理函数。默认写入 os.Stderr。
// 设为 nil 则静默丢弃内部错误，nil 会传播到所有子 handler。
func WithErrorHandler(fn ErrorHandler) HandlerOption {
	return func(o *handlerOptions) error {
		o.errorHandler = fn
		return nil
	}
}

// ReportError invokes the ErrorHandler if non-nil.
func ReportError(eh ErrorHandler, he HandlerError) {
	if eh != nil {
		if he.Time.IsZero() {
			he.Time = time.Now()
		}
		eh(he)
	}
}

func loadErrorHandler(p *atomic.Pointer[ErrorHandler]) ErrorHandler {
	v := p.Load()
	if v == nil {
		return nil
	}
	return *v
}

// buildHandler 从选项构建 slog.Handler。0 个 handler 使用默认 stdout JSON logger。
func buildHandler(opts ...HandlerOption) (slog.Handler, error) {
	o := &handlerOptions{}
	for _, opt := range opts {
		if err := opt(o); err != nil {
			return nil, err
		}
	}
	if len(o.handlers) == 0 {
		o.handlers = append(o.handlers, NewStdoutHandler(StdoutConfig{}))
	}

	// Build terminal: single handler or fanout
	var handler slog.Handler
	if len(o.handlers) == 1 {
		handler = o.handlers[0]
	} else {
		handler = safeMultiHandler(o.handlers, o.errorHandler)
	}

	// Apply middlewares: declared later wraps outermost
	for _, mw := range o.middlewares {
		handler = mw(handler)
	}

	// Propagate error handler to all layers
	propagateErrorHandler(handler, o.errorHandler)

	return handler, nil
}

// safeMultiHandler 包装多个子 Handler，每个调用加 panic recover。防止单个 Handler panic 导致整个日志调用崩溃。
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

func (h *safeMulti) Close() error {
	visited := make(map[uintptr]bool)
	var errs []error
	for _, hh := range h.handlers {
		if err := closeAll(hh, visited); err != nil {
			errs = append(errs, err)
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
				ReportError(h.errorHandler, HandlerError{Component: "multi", Operation: "handle", Err: fmt.Errorf("handler panic recovered: %v", r)})
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
					ReportError(h.errorHandler, HandlerError{Component: "multi", Operation: "handle", Err: fmt.Errorf("handler panic recovered: %v", r)})
				}
			}()
			// r.Clone() 防止并发 goroutine 竞争 slog.Record。
			// Clone 内部有快速路径：无 Attr 时仅复制固定字段，无堆分配。
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
func (h *safeMulti) setErrorHandler(fn ErrorHandler) {
	h.errorHandler = fn
	for _, hh := range h.handlers {
		propagateErrorHandler(hh, fn)
	}
}

// errorHandlerSetter 是支持自定义错误处理的 Handler 的内部接口。
type errorHandlerSetter interface {
	setErrorHandler(fn ErrorHandler)
}

// propagateErrorHandler 递归解包装饰器链，向所有支持 setErrorHandler 的 handler 注入 errorHandler。
func propagateErrorHandler(h slog.Handler, fn ErrorHandler) {
	if s, ok := h.(errorHandlerSetter); ok {
		s.setErrorHandler(fn)
	}
	if uw, ok := h.(handlerUnwrapper); ok {
		propagateErrorHandler(uw.unwrapHandler(), fn)
	}
}

// handlerUnwrapper 是装饰器实现的内部接口，用于 CloseAll 递归解包。
type handlerUnwrapper interface {
	unwrapHandler() slog.Handler
}

// CloseAll 递归关闭 handler 及装饰器链中所有实现 io.Closer 的资源。
// 使用 visited map 防止共享 handler 被重复关闭。
func CloseAll(handler slog.Handler) error {
	return closeAll(handler, make(map[uintptr]bool))
}

func closeAll(handler slog.Handler, visited map[uintptr]bool) error {
	if handler == nil {
		return nil
	}
	ptr := reflect.ValueOf(handler).Pointer()
	if visited[ptr] {
		return nil
	}
	visited[ptr] = true

	var errs []error
	if closer, ok := handler.(io.Closer); ok {
		if err := closer.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if uw, ok := handler.(handlerUnwrapper); ok {
		if err := closeAll(uw.unwrapHandler(), visited); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// prefixAttrs 给 attrs 的 key 添加 "group." 前缀。group 为空时原样返回。
func prefixAttrs(group string, attrs []slog.Attr) []slog.Attr {
	if group == "" {
		return attrs
	}
	out := make([]slog.Attr, len(attrs))
	for i, a := range attrs {
		out[i] = slog.Attr{Key: group + "." + a.Key, Value: a.Value}
	}
	return out
}

// MergeAttrs merges existing and newAttrs, prefixing newAttrs keys with the given group.
func MergeAttrs(existing, newAttrs []slog.Attr, group string) []slog.Attr {
	merged := make([]slog.Attr, len(existing), len(existing)+len(newAttrs))
	copy(merged, existing)
	merged = append(merged, prefixAttrs(group, newAttrs)...)
	return merged
}

// RecordWithGroupAttrs creates a new slog.Record with group-prefixed attrs from the original record plus extraAttrs.
func RecordWithGroupAttrs(r slog.Record, group string, extraAttrs []slog.Attr) slog.Record {
	newR := slog.NewRecord(r.Time, r.Level, r.Message, r.PC)
	r.Attrs(func(attr slog.Attr) bool {
		newR.AddAttrs(slog.Attr{Key: group + "." + attr.Key, Value: attr.Value})
		return true
	})
	newR.AddAttrs(extraAttrs...)
	return newR
}

// AttrsSub is a generic sub-handler for WithAttrs/WithGroup chains, eliminating duplicate sub-types across handlers.
type AttrsSub[H slog.Handler] struct {
	Parent H
	Attrs  []slog.Attr
	Group  string
}

func (h *AttrsSub[H]) Enabled(ctx context.Context, level slog.Level) bool {
	return h.Parent.Enabled(ctx, level)
}

func (h *AttrsSub[H]) Handle(ctx context.Context, r slog.Record) error {
	if h.Group != "" {
		return h.Parent.Handle(ctx, RecordWithGroupAttrs(r, h.Group, h.Attrs))
	}
	r.AddAttrs(h.Attrs...)
	return h.Parent.Handle(ctx, r)
}

func (h *AttrsSub[H]) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &AttrsSub[H]{
		Parent: h.Parent,
		Attrs:  MergeAttrs(h.Attrs, attrs, h.Group),
		Group:  h.Group,
	}
}

func (h *AttrsSub[H]) WithGroup(name string) slog.Handler {
	return &GroupSub[H]{
		Parent: h.Parent,
		Group:  name,
		Attrs:  h.Attrs,
	}
}

func (h *AttrsSub[H]) unwrapHandler() slog.Handler {
	return h.Parent
}

// GroupSub is a generic sub-handler for WithGroup chains, prefixing all record attrs with the group name before forwarding to the parent.
type GroupSub[H slog.Handler] struct {
	Parent H
	Group  string
	Attrs  []slog.Attr
}

func (h *GroupSub[H]) Enabled(ctx context.Context, level slog.Level) bool {
	return h.Parent.Enabled(ctx, level)
}

func (h *GroupSub[H]) Handle(ctx context.Context, r slog.Record) error {
	return h.Parent.Handle(ctx, RecordWithGroupAttrs(r, h.Group, h.Attrs))
}

func (h *GroupSub[H]) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &AttrsSub[H]{
		Parent: h.Parent,
		Attrs:  MergeAttrs(h.Attrs, attrs, h.Group),
		Group:  h.Group,
	}
}

func (h *GroupSub[H]) WithGroup(name string) slog.Handler {
	return &GroupSub[H]{
		Parent: h.Parent,
		Group:  h.Group + "." + name,
		Attrs:  h.Attrs,
	}
}

func (h *GroupSub[H]) unwrapHandler() slog.Handler {
	return h.Parent
}
