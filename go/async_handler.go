package mebsuta

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// AsyncConfig holds configuration for the AsyncHandler.
type AsyncConfig struct {
	// BufferSize is the buffered channel size. Defaults to 256.
	BufferSize int
}

const defaultAsyncBufferSize = 256

// asyncRecord 是 slog.Record 的异步拷贝。
// slog.Record 的 Attr 只能遍历一次，Handle 中必须同步复制。
type asyncRecord struct {
	Time    time.Time
	Level   slog.Level
	Message string
	PC      uintptr
	Attrs   []slog.Attr
	inner   slog.Handler
}

// AsyncHandler delegates log writes to a background goroutine.
// Do not wrap SyslogHandler or DatabaseHandler — they have built-in async mechanisms.
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

// WithAsync wraps inner in an AsyncHandler that buffers records and writes them from a background goroutine.
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

func (h *AsyncHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.inner.Enabled(ctx, level)
}

func (h *AsyncHandler) Handle(ctx context.Context, r slog.Record) error {
	if h.closed.Load() {
		return nil
	}
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
	return h.sendRecord(ar)
}

func (h *AsyncHandler) sendRecord(ar asyncRecord) error {
	defer func() {
		if r := recover(); r != nil {
			h.dropped.Add(1)
			ReportError(loadErrorHandler(&h.errorHandler), "async", fmt.Errorf("send on closed channel, log dropped (total dropped: %d)", h.dropped.Load()))
		}
	}()

	// Error and Audit records block until sent or timeout (5s).
	// Other levels use non-blocking send and drop on buffer full.
	if ar.Level >= slog.LevelError {
		select {
		case h.ch <- ar:
			return nil
		case <-time.After(5 * time.Second):
			h.dropped.Add(1)
			ReportError(loadErrorHandler(&h.errorHandler), "async", fmt.Errorf("buffer full timeout for %v record, dropped (total: %d)", ar.Level, h.dropped.Load()))
			return nil
		}
	}

	select {
	case h.ch <- ar:
		return nil
	default:
		h.dropped.Add(1)
		ReportError(loadErrorHandler(&h.errorHandler), "async", fmt.Errorf("buffer full, log dropped (total dropped: %d)", h.dropped.Load()))
		return nil
	}
}

func (h *AsyncHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &asyncAttrsHandler{
		AsyncHandler: h,
		attrs:        attrs,
	}
}

func (h *AsyncHandler) WithGroup(name string) slog.Handler {
	return &asyncGroupHandler{
		AsyncHandler: h,
		group:        name,
	}
}

func (h *AsyncHandler) Close() error {
	if !h.closed.CompareAndSwap(false, true) {
		return nil
	}
	h.cancel()
	close(h.ch)
	h.wg.Wait()
	return nil
}

func (h *AsyncHandler) setErrorHandler(fn ErrorHandler) {
	h.errorHandler.Store(&fn)
}

func (h *AsyncHandler) unwrapHandler() slog.Handler {
	return h.inner
}

func (h *AsyncHandler) Dropped() int64 {
	return h.dropped.Load()
}

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
	return &asyncAttrsHandler{
		AsyncHandler: h.AsyncHandler,
		attrs:        MergeAttrs(h.attrs, attrs, ""),
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
	return h.sendRecord(ar)
}

func (h *asyncGroupHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &asyncAttrsHandler{
		AsyncHandler: h.AsyncHandler,
		attrs:        MergeAttrs(h.attrs, attrs, h.group),
	}
}

func (h *asyncGroupHandler) WithGroup(name string) slog.Handler {
	return &asyncGroupHandler{
		AsyncHandler: h.AsyncHandler,
		group:        h.group + "." + name,
		attrs:        h.attrs,
	}
}

// AsyncDropped extracts the total number of dropped records from an AsyncHandler in the handler chain.
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

var _ slog.Handler = (*AsyncHandler)(nil)
