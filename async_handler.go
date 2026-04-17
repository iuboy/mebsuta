package mebsuta

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// =============================================================================
// AsyncConfig — 异步写入配置
// =============================================================================

// AsyncConfig 配置 AsyncHandler 的行为。
type AsyncConfig struct {
	// BufferSize 缓冲通道大小。默认 256。
	BufferSize int
}

// =============================================================================
// AsyncHandler — 异步写入装饰器
// =============================================================================

const defaultAsyncBufferSize = 256

// asyncRecord 是 slog.Record 的异步拷贝。
// slog.Record 的 Attr 只能遍历一次，Handle 中必须同步复制。
// inner 指向带有 WithGroup/WithAttrs 链式传播信息的 handler，
// 确保 run() 回放时使用正确的内层 handler。
type asyncRecord struct {
	Time    time.Time
	Level   slog.Level
	Message string
	PC      uintptr
	Attrs   []slog.Attr
	inner   slog.Handler
}

// AsyncHandler 将日志写入委托给后台 goroutine。
// Handle 中同步复制 slog.Record 的 Attr 到 asyncRecord，放入 channel。
// 后台 goroutine 消费 channel 并调用内层 handler。
//
// 注意：不要将 AsyncHandler 套在 SyslogHandler 或 DatabaseHandler 上，
// 因为它们内部已有异步机制（Decision #15）。
type AsyncHandler struct {
	inner        slog.Handler
	ch           chan asyncRecord
	wg           sync.WaitGroup
	ctx          context.Context
	cancel       context.CancelFunc
	closed       atomic.Bool
	dropped      atomic.Int64
	errorHandler atomic.Pointer[ErrorHandler]
}

// WithAsync 返回一个异步写入装饰器，包裹给定的 handler。
func WithAsync(inner slog.Handler, cfg AsyncConfig) slog.Handler {
	if inner == nil {
		return inner
	}
	bufferSize := cfg.BufferSize
	if bufferSize <= 0 {
		bufferSize = defaultAsyncBufferSize
	}

	ctx, cancel := context.WithCancel(context.Background())

	eh := DefaultErrorHandler
	h := &AsyncHandler{
		inner:  inner,
		ch:     make(chan asyncRecord, bufferSize),
		ctx:    ctx,
		cancel: cancel,
	}
	h.errorHandler.Store(&eh)
	h.wg.Add(1)
	go h.run()
	return h
}

// Enabled 代理到内层 handler。
func (h *AsyncHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.inner.Enabled(ctx, level)
}

// Handle 同步复制 slog.Record，放入 channel。
func (h *AsyncHandler) Handle(ctx context.Context, r slog.Record) error {
	if h.closed.Load() {
		return nil
	}

	// 同步复制 Attr（slog.Record.Attr 只能遍历一次）
	ar := asyncRecord{
		Time:    r.Time,
		Level:   r.Level,
		Message: r.Message,
		PC:      r.PC,
		inner:   h.inner,
	}
	r.Attrs(func(attr slog.Attr) bool {
		ar.Attrs = append(ar.Attrs, attr)
		return true
	})

	// recover 防止 Close() 关闭 channel 后并发 send 导致 panic。
	defer func() {
		if r := recover(); r != nil {
			h.dropped.Add(1)
			ReportError(loadErrorHandler(&h.errorHandler), "async", fmt.Errorf("send on closed channel, log dropped (total dropped: %d)", h.dropped.Load()))
		}
	}()

	select {
	case h.ch <- ar:
		return nil
	default:
		h.dropped.Add(1)
		ReportError(loadErrorHandler(&h.errorHandler), "async", fmt.Errorf("buffer full, log dropped (total dropped: %d)", h.dropped.Load()))
		return nil
	}
}

// WithAttrs 返回带有预置属性的新 AsyncHandler，链式传播到内层。
func (h *AsyncHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &asyncAttrsHandler{
		AsyncHandler: h,
		attrs:        attrs,
	}
}

// WithGroup 返回带有分组前缀的新 AsyncHandler，链式传播到内层。
func (h *AsyncHandler) WithGroup(name string) slog.Handler {
	return &asyncGroupHandler{
		AsyncHandler: h,
		group:        name,
	}
}

// Close 关闭异步 handler，等待所有缓冲日志写入完成。
func (h *AsyncHandler) Close() error {
	if !h.closed.CompareAndSwap(false, true) {
		return nil
	}
	h.cancel()
	close(h.ch)
	h.wg.Wait()
	return nil
}

// setErrorHandler 设置内部错误处理函数（由 buildHandler 传播调用）。
func (h *AsyncHandler) setErrorHandler(fn ErrorHandler) {
	h.errorHandler.Store(&fn)
}

// unwrapHandler 返回内层 handler，供 CloseAll 递归关闭。
func (h *AsyncHandler) unwrapHandler() slog.Handler {
	return h.inner
}

// Dropped 返回因 channel 满而丢弃的日志数量。
func (h *AsyncHandler) Dropped() int64 {
	return h.dropped.Load()
}

// run 后台消费 channel 并写入内层 handler。
func (h *AsyncHandler) run() {
	defer h.wg.Done()
	for ar := range h.ch {
		r := slog.NewRecord(ar.Time, ar.Level, ar.Message, ar.PC)
		r.AddAttrs(ar.Attrs...)
		if err := ar.inner.Handle(context.Background(), r); err != nil {
			ReportError(loadErrorHandler(&h.errorHandler), "async", err)
		}
	}
}

// =============================================================================
// 子 Handler 类型（WithAttrs/WithGroup 返回）
// =============================================================================

type asyncAttrsHandler struct {
	*AsyncHandler
	attrs []slog.Attr
}

func (h *asyncAttrsHandler) Handle(ctx context.Context, r slog.Record) error {
	for _, attr := range h.attrs {
		r.AddAttrs(attr)
	}
	return h.AsyncHandler.Handle(ctx, r)
}

func (h *asyncAttrsHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	merged := make([]slog.Attr, 0, len(h.attrs)+len(attrs))
	merged = append(merged, h.attrs...)
	merged = append(merged, attrs...)
	return &asyncAttrsHandler{
		AsyncHandler: h.AsyncHandler,
		attrs:        merged,
	}
}

func (h *asyncAttrsHandler) WithGroup(name string) slog.Handler {
	return &asyncGroupHandler{
		AsyncHandler: h.AsyncHandler,
		group:        name,
		attrs:        h.attrs,
	}
}

type asyncGroupHandler struct {
	*AsyncHandler
	group string
	attrs []slog.Attr
}

func (h *asyncGroupHandler) Handle(ctx context.Context, r slog.Record) error {
	if h.closed.Load() {
		return nil
	}

	for _, attr := range h.attrs {
		r.AddAttrs(attr)
	}

	// 同步复制 Attr，使用 WithGroup 后的内层 handler
	ar := asyncRecord{
		Time:    r.Time,
		Level:   r.Level,
		Message: r.Message,
		PC:      r.PC,
		inner:   h.inner.WithGroup(h.group),
	}
	r.Attrs(func(attr slog.Attr) bool {
		ar.Attrs = append(ar.Attrs, attr)
		return true
	})

	select {
	case h.ch <- ar:
		return nil
	default:
		h.dropped.Add(1)
		ReportError(loadErrorHandler(&h.errorHandler), "async", fmt.Errorf("buffer full, log dropped (total dropped: %d)", h.dropped.Load()))
		return nil
	}
}

func (h *asyncGroupHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	merged := make([]slog.Attr, len(h.attrs), len(h.attrs)+len(attrs))
	copy(merged, h.attrs)
	for _, a := range attrs {
		merged = append(merged, slog.Attr{Key: h.group + "." + a.Key, Value: a.Value})
	}
	return &asyncAttrsHandler{
		AsyncHandler: h.AsyncHandler,
		attrs:        merged,
	}
}

func (h *asyncGroupHandler) WithGroup(name string) slog.Handler {
	return &asyncGroupHandler{
		AsyncHandler: h.AsyncHandler,
		group:        h.group + "." + name,
		attrs:        h.attrs,
	}
}

// =============================================================================
// 检查已丢弃日志数量
// =============================================================================

// AsyncDropped 从 handler 链中提取 AsyncHandler 并返回丢弃数量。
// 如果 handler 不是 AsyncHandler 或其子类型，返回 0。
func AsyncDropped(h slog.Handler) int64 {
	switch v := h.(type) {
	case *AsyncHandler:
		return v.Dropped()
	case *asyncAttrsHandler:
		return v.Dropped()
	case *asyncGroupHandler:
		return v.Dropped()
	default:
		return 0
	}
}

// 编译期断言
var _ slog.Handler = (*AsyncHandler)(nil)
