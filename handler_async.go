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
	handlerCore
	inner          slog.Handler
	errorTimeout   time.Duration
	ch             chan asyncRecord
	sendMu         sync.RWMutex // RLock during channel send; Lock during Close's close(ch)
	wg             sync.WaitGroup
	ctx            context.Context
	cancel         context.CancelFunc
	closed         atomic.Bool
	dropped        atomic.Int64
	lastDropReport atomic.Int64 // unix nanos of the last surfaced drop report
	errorHandler   atomic.Pointer[ErrorHandler]
}

// findSelfBuffered recursively checks whether the handler chain contains a
// SelfBufferedHandler. Depth is bounded so a self-referential third-party
// unwrapHandler chain cannot overflow the stack during construction.
func findSelfBuffered(h slog.Handler) bool {
	return findSelfBufferedDepth(h, 0)
}

func findSelfBufferedDepth(h slog.Handler, depth int) bool {
	if depth > maxUnwrapDepth {
		return false
	}
	if _, ok := h.(SelfBufferedHandler); ok {
		return true
	}
	if uw, ok := h.(handlerUnwrapper); ok {
		return findSelfBufferedDepth(uw.unwrapHandler(), depth+1)
	}
	return false
}

// WithAsync wraps inner in an AsyncHandler that buffers records and writes them from a background goroutine.
func WithAsync(inner slog.Handler, cfg AsyncConfig) slog.Handler {
	if inner == nil {
		return inner
	}
	if findSelfBuffered(inner) {
		ReportError(DefaultErrorHandler, &HandlerError{Component: "async", Operation: "init", Err: fmt.Errorf("WithAsync: wrapping %T creates double-buffering; returning inner handler directly", inner)})
		return inner
	}
	bufferSize := cfg.BufferSize
	if bufferSize <= 0 {
		bufferSize = DefaultAsyncBufferSize
	}
	cfg, _ = cfg.Validate() // applies ErrorTimeout default

	ctx, cancel := context.WithCancel(context.Background())

	eh := DefaultErrorHandler
	h := &AsyncHandler{
		handlerCore:  newHandlerCore(),
		inner:        inner,
		errorTimeout: cfg.ErrorTimeout,
		ch:           make(chan asyncRecord, bufferSize),
		ctx:          ctx,
		cancel:       cancel,
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
		h.dropped.Add(1)
		return fmt.Errorf("async handler is closed, log dropped")
	}
	// Strip cancellation while keeping values: the record may outlive the
	// request (buffered during Close's drain), and a cancelled request ctx
	// would make ctx-aware inner handlers drop the final flush. Values are
	// preserved so ctx-derived attributes still work. Contexts that can
	// never be cancelled (Done() == nil, e.g. Background) skip the wrapper
	// — it would be a per-record allocation with no effect.
	if ctx.Done() != nil {
		ctx = context.WithoutCancel(ctx)
	}
	ar := asyncRecord{
		Time:    r.Time,
		Level:   r.Level,
		Message: r.Message,
		PC:      r.PC,
		inner:   h.inner,
		ctx:     ctx,
	}
	if n := r.NumAttrs(); n > 0 {
		// Pre-size the copy: append alone re-allocates as the slice grows.
		ar.Attrs = make([]slog.Attr, 0, n)
	}
	r.Attrs(func(attr slog.Attr) bool {
		ar.Attrs = append(ar.Attrs, attr)
		return true
	})
	return h.sendRecord(ar)
}

func (h *AsyncHandler) sendRecord(ar asyncRecord) error {
	// Fast path: check if already closing before attempting channel operations.
	if h.closed.Load() {
		h.dropped.Add(1)
		return fmt.Errorf("async handler is closed, log dropped")
	}

	return h.sendRecordInner(ar)
}

// shouldReportDrop reports whether a drop should be surfaced now (at most one
// report per second, carrying the cumulative count). Without rate limiting, a
// flood that overflows the buffer triggers one locked stderr write per
// dropped record — a 1:1 amplification of attack traffic.
func (h *AsyncHandler) shouldReportDrop() int64 {
	total := h.dropped.Load()
	now := time.Now().UnixNano()
	last := h.lastDropReport.Load()
	if now-last < int64(time.Second) {
		return 0
	}
	if h.lastDropReport.CompareAndSwap(last, now) {
		return total
	}
	return 0
}

func (h *AsyncHandler) sendRecordInner(ar asyncRecord) error {
	// sendMu mirrors database.Handler: sends take the read lock (concurrent),
	// Close takes the write lock around close(ch). This makes close-vs-send
	// race-detector-clean without relying on recover — a send-on-closed
	// channel panic is structurally impossible because Close cannot close the
	// channel while any sender holds the read lock.
	h.sendMu.RLock()
	defer h.sendMu.RUnlock()

	if h.closed.Load() {
		h.dropped.Add(1)
		return fmt.Errorf("async handler is closed, log dropped")
	}

	// Error and Audit (LevelAudit > LevelError) records: blocking send bounded
	// by ErrorTimeout. Other levels use non-blocking send and drop on buffer full.
	if ar.Level >= slog.LevelError {
		// Try non-blocking send first to avoid timer allocation in the common case.
		select {
		case h.ch <- ar:
			return nil
		case <-h.ctx.Done():
			return fmt.Errorf("async handler is closed, log dropped")
		default:
		}

		timer := time.NewTimer(h.errorTimeout)
		defer timer.Stop()
		select {
		case h.ch <- ar:
			return nil
		case <-h.ctx.Done():
			return fmt.Errorf("async handler is closed, log dropped")
		case <-timer.C:
			h.dropped.Add(1)
			err := fmt.Errorf("mebsuta: buffer full timeout for %v record after %v, dropped (total: %d)", ar.Level, h.errorTimeout, h.dropped.Load())
			if total := h.shouldReportDrop(); total > 0 {
				ReportError(LoadErrorHandler(&h.errorHandler), &HandlerError{Component: "async", Operation: "process", Err: err, Dropped: total})
			}
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
		if total := h.shouldReportDrop(); total > 0 {
			ReportError(LoadErrorHandler(&h.errorHandler), &HandlerError{Component: "async", Operation: "send", Err: fmt.Errorf("buffer full, log dropped (total dropped: %d)", total), Dropped: total})
		}
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
		groupInner:   h.inner.WithGroup(name),
	}
}

// Close implements io.Closer.
//
// Drains before cancelling: close(ch) lets run() process every buffered
// record, and wg.Wait() returns only after the final writes finished. The
// earlier cancel()-first order made ctx-aware inner handlers see a cancelled
// context during the drain and drop the final batch. sendMu (write lock held
// around close(ch)) guarantees no in-flight sender can hit a closed channel,
// so the drain start is race-detector-clean like database.Handler.
func (h *AsyncHandler) Close() error {
	if !h.closed.CompareAndSwap(false, true) {
		return nil
	}
	h.sendMu.Lock()
	close(h.ch) // safe: write lock excludes all in-flight senders
	h.sendMu.Unlock()
	h.wg.Wait()
	h.cancel()
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
		h.processRecord(ar, r)
	}
}

// processRecord dispatches one record with panic recovery. safeMulti's
// handleWithRecovery only guards the synchronous path; when a user wraps a
// third-party handler directly in WithAsync, an inner panic must not kill
// the background goroutine (and with it the whole process).
func (h *AsyncHandler) processRecord(ar asyncRecord, r slog.Record) {
	err := h.handleInner(ar, r)
	if err != nil {
		ReportError(LoadErrorHandler(&h.errorHandler), &HandlerError{Component: "async", Operation: "process", Err: err})
	}
}

func (h *AsyncHandler) handleInner(ar asyncRecord, r slog.Record) (err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("inner handler panic recovered: %v", p)
		}
	}()
	return ar.inner.Handle(ar.ctx, r)
}

// asyncAttrsHandler preserves preset attrs through the async boundary.
type asyncAttrsHandler struct {
	*AsyncHandler
	attrs []slog.Attr
}

func (h *asyncAttrsHandler) Handle(ctx context.Context, r slog.Record) error {
	// Clone instead of mutating the caller's record (slog contract). The
	// fan-out paths may share one record across handlers; AddAttrs on the
	// original would leak preset attrs into sibling handlers.
	grouped := RecordWithGroupAttrs(r, "", h.attrs)
	return h.AsyncHandler.Handle(ctx, grouped)
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
		groupInner:   h.inner.WithGroup(name),
	}
}

// asyncGroupHandler preserves preset attrs and group prefix through the async boundary.
type asyncGroupHandler struct {
	*AsyncHandler
	group      string
	attrs      []slog.Attr
	groupInner slog.Handler // cached WithGroup result, avoids per-Handle allocation
}

func (h *asyncGroupHandler) Handle(ctx context.Context, r slog.Record) error {
	if h.closed.Load() {
		return fmt.Errorf("async handler is closed, log dropped")
	}
	// Same cancellation-stripping as AsyncHandler.Handle: the group path
	// previously forwarded the raw request ctx, so ctx-aware inner handlers
	// dropped records queued during Close's drain (the exact bug the plain
	// path fixed). Uncancellable contexts skip the wrapper allocation.
	if ctx.Done() != nil {
		ctx = context.WithoutCancel(ctx)
	}
	// Use RecordWithGroupAttrs to prefix only the record attrs with the group,
	// while keeping preset attrs (h.attrs) at the root level. This matches the
	// slog contract: attrs added BEFORE WithGroup are NOT inside the group.
	// Forward to the ungrouped inner (h.inner), not h.groupInner, because
	// RecordWithGroupAttrs already applied the prefix manually.
	grouped := RecordWithGroupAttrs(r, h.group, h.attrs)
	ar := asyncRecord{
		Time:    grouped.Time,
		Level:   grouped.Level,
		Message: grouped.Message,
		PC:      grouped.PC,
		inner:   h.inner,
		ctx:     ctx,
	}
	if n := grouped.NumAttrs(); n > 0 {
		ar.Attrs = make([]slog.Attr, 0, n)
	}
	grouped.Attrs(func(attr slog.Attr) bool {
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
	combined := h.group + "." + name
	return &asyncGroupHandler{
		AsyncHandler: h.AsyncHandler,
		group:        combined,
		attrs:        h.attrs,
		groupInner:   h.inner.WithGroup(combined),
	}
}

// unwrapHandler returns the group-prefixed inner handler so that CloseAll
// traverses through the group layer correctly. The inherited unwrapHandler
// from AsyncHandler returns h.inner, which skips the group wrapping.
func (h *asyncGroupHandler) unwrapHandler() slog.Handler {
	return h.groupInner
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
