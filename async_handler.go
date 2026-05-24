package mebsuta

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

const defaultAsyncBufferSize = 256

// SelfBufferedHandler is a marker interface for handlers with built-in async
// buffering. Wrapping such a handler in AsyncHandler creates double-buffering
// and is rejected at construction time.
type SelfBufferedHandler interface {
	SelfBuffered()
}

// asyncRecord is an async copy of slog.Record.
// slog.Record Attrs can only be iterated once; they must be copied synchronously in Handle.
type asyncRecord struct {
	Time    time.Time
	Level   slog.Level
	Message string
	PC      uintptr
	Attrs   []slog.Attr
	inner   slog.Handler
	ctx     context.Context
}

// AsyncHandler delegates log writes to a background goroutine.
// Do not wrap syslog.Handler or database.Handler — they have built-in async mechanisms.
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

// findSelfBuffered recursively checks whether the handler chain contains a SelfBufferedHandler.
func findSelfBuffered(h slog.Handler) bool {
	if _, ok := h.(SelfBufferedHandler); ok {
		return true
	}
	if uw, ok := h.(handlerUnwrapper); ok {
		return findSelfBuffered(uw.unwrapHandler())
	}
	return false
}

// WithAsync wraps inner in an AsyncHandler that buffers records and writes them from a background goroutine.
func WithAsync(inner slog.Handler, cfg AsyncConfig) slog.Handler {
	if inner == nil {
		return inner
	}
	if findSelfBuffered(inner) {
		ReportError(DefaultErrorHandler, HandlerError{Component: "async", Operation: "init", Err: fmt.Errorf("WithAsync: wrapping %T creates double-buffering; returning inner handler directly", inner)})
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

// Enabled implements slog.Handler.
func (h *AsyncHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.inner.Enabled(ctx, level)
}

// Handle implements slog.Handler.
func (h *AsyncHandler) Handle(ctx context.Context, r slog.Record) error {
	if h.closed.Load() {
		return fmt.Errorf("async handler is closed, log dropped")
	}
	ar := asyncRecord{
		Time:    r.Time,
		Level:   r.Level,
		Message: r.Message,
		PC:      r.PC,
		inner:   h.inner,
		ctx:     ctx,
	}
	r.Attrs(func(attr slog.Attr) bool {
		ar.Attrs = append(ar.Attrs, attr)
		return true
	})
	return h.sendRecord(ar)
}

func (h *AsyncHandler) sendRecord(ar asyncRecord) error {
	// Error and Audit records: blocking send with 5s timeout.
	// Other levels use non-blocking send and drop on buffer full.
	if ar.Level >= slog.LevelError {
		timer := time.NewTimer(5 * time.Second)
		defer timer.Stop()
		select {
		case h.ch <- ar:
			return nil
		case <-h.ctx.Done():
			return fmt.Errorf("async handler is closed, log dropped")
		case <-timer.C:
			h.dropped.Add(1)
			err := fmt.Errorf("mebsuta: buffer full timeout for %v record, dropped (total: %d)", ar.Level, h.dropped.Load())
			ReportError(loadErrorHandler(&h.errorHandler), HandlerError{Component: "async", Operation: "process", Err: err})
			return err
		}
	}

	select {
	case h.ch <- ar:
		return nil
	case <-h.ctx.Done():
		return fmt.Errorf("async handler is closed, log dropped")
	default:
		h.dropped.Add(1)
		ReportError(loadErrorHandler(&h.errorHandler), HandlerError{Component: "async", Operation: "send", Err: fmt.Errorf("buffer full, log dropped (total dropped: %d)", h.dropped.Load()), Dropped: 1})
		return nil
	}
}

// WithAttrs implements slog.Handler.
func (h *AsyncHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &asyncAttrsHandler{
		AsyncHandler: h,
		attrs:        attrs,
	}
}

// WithGroup implements slog.Handler.
func (h *AsyncHandler) WithGroup(name string) slog.Handler {
	return &asyncGroupHandler{
		AsyncHandler: h,
		group:        name,
	}
}

// Close implements io.Closer.
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

// Dropped returns the total number of records dropped due to buffer overflow.
func (h *AsyncHandler) Dropped() int64 {
	return h.dropped.Load()
}

func (h *AsyncHandler) run() {
	defer h.wg.Done()
	for ar := range h.ch {
		r := slog.NewRecord(ar.Time, ar.Level, ar.Message, ar.PC)
		r.AddAttrs(ar.Attrs...)
		if err := ar.inner.Handle(ar.ctx, r); err != nil {
			ReportError(loadErrorHandler(&h.errorHandler), HandlerError{Component: "async", Operation: "process", Err: err})
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
		return fmt.Errorf("async handler is closed, log dropped")
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
		ctx:     ctx,
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

var (
	_ slog.Handler     = (*AsyncHandler)(nil)
	_ slog.Handler     = (*asyncAttrsHandler)(nil)
	_ slog.Handler     = (*asyncGroupHandler)(nil)
	_ io.Closer        = (*AsyncHandler)(nil)
	_ handlerUnwrapper = (*AsyncHandler)(nil)
	_ handlerUnwrapper = (*asyncAttrsHandler)(nil)
	_ handlerUnwrapper = (*asyncGroupHandler)(nil)
)
