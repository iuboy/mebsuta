package mebsuta

import (
	"context"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"
)

// HandlerMetrics defines the interface for collecting handler-level metrics such as latency, errors, and drops.
type HandlerMetrics interface {
	// ObserveHandle records the latency of a single Handle call.
	ObserveHandle(duration time.Duration)

	// IncError increments the error counter.
	IncError(handlerName string)

	// IncDropped increments the dropped-record counter.
	IncDropped(handlerName string)
}

// DroppedCounter is implemented by handlers that track records dropped due to
// a full backlog or shutdown (AsyncHandler, database/syslog/mbta Handlers).
// MetricsHandler probes its inner chain for one and surfaces the delta as
// IncDropped — without this, buffer-full floods were invisible to Prometheus.
type DroppedCounter interface {
	Dropped() int64
}

// droppedNone is the sentinel stored when no DroppedCounter exists in the
// chain, so the probe walk runs at most once per handler instance.
type droppedNone struct{}

func (droppedNone) Dropped() int64 { return 0 }

// findDroppedCounter walks the decorator chain for a DroppedCounter. Depth is
// bounded like every other unwrap walk.
func findDroppedCounter(h slog.Handler) DroppedCounter {
	for depth := 0; h != nil && depth <= maxUnwrapDepth; depth++ {
		if dc, ok := h.(DroppedCounter); ok {
			return dc
		}
		uw, ok := h.(handlerUnwrapper)
		if !ok {
			return nil
		}
		h = uw.unwrapHandler()
	}
	return nil
}

// MetricsHandler is a slog.Handler decorator that records write latency and error counts via the HandlerMetrics interface.
//
// Drops: when the wrapped chain contains a buffering handler (declare
// UseMetrics AFTER UseAsync/UseSyslog-style options so this middleware ends
// up outermost), each Handle surfaces the buffering handler's dropped delta
// as IncDropped.
type MetricsHandler struct {
	inner        slog.Handler
	metrics      HandlerMetrics
	handlerName  string
	dropCounter  atomic.Value // DroppedCounter or droppedNone; resolved lazily
	lastDropped  atomic.Int64
	errorHandler *atomic.Pointer[ErrorHandler] // shared across clones
}

// WithMetrics wraps inner in a MetricsHandler that observes latency and errors for the named handler.
func WithMetrics(inner slog.Handler, m HandlerMetrics, handlerName string) slog.Handler {
	if inner == nil || m == nil {
		return inner
	}
	eh := DefaultErrorHandler
	ep := new(atomic.Pointer[ErrorHandler])
	ep.Store(&eh)
	return &MetricsHandler{
		inner:        inner,
		metrics:      m,
		handlerName:  handlerName,
		errorHandler: ep,
	}
}

// Enabled implements slog.Handler.
func (h *MetricsHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.inner.Enabled(ctx, level)
}

// metricsSafe contains panics from user-supplied HandlerMetrics
// implementations — the same containment every other user callback gets.
func (h *MetricsHandler) metricsSafe(op string, fn func()) {
	defer func() {
		if p := recover(); p != nil {
			ReportError(LoadErrorHandler(h.errorHandler), &HandlerError{
				Component: "metrics", Operation: op,
				Err: fmt.Errorf("HandlerMetrics panic recovered: %v", p),
			})
		}
	}()
	fn()
}

// reportDropped surfaces the inner chain's dropped-record delta.
func (h *MetricsHandler) reportDropped() {
	var dc DroppedCounter
	if v := h.dropCounter.Load(); v != nil {
		dc = v.(DroppedCounter)
	} else {
		if found := findDroppedCounter(h.inner); found != nil {
			dc = found
		} else {
			dc = droppedNone{}
		}
		h.dropCounter.Store(dc)
	}
	cur := dc.Dropped()
	for {
		last := h.lastDropped.Load()
		if cur <= last {
			return
		}
		if h.lastDropped.CompareAndSwap(last, cur) {
			h.metricsSafe("dropped", func() { h.metrics.IncDropped(h.handlerName) })
			return
		}
	}
}

// Handle implements slog.Handler.
func (h *MetricsHandler) Handle(ctx context.Context, r slog.Record) error {
	start := time.Now()
	err := h.inner.Handle(ctx, r)
	d := time.Since(start)
	h.metricsSafe("observe", func() { h.metrics.ObserveHandle(d) })
	if err != nil {
		h.metricsSafe("error", func() { h.metrics.IncError(h.handlerName) })
	}
	h.reportDropped()
	return err
}

// WithAttrs implements slog.Handler.
func (h *MetricsHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &MetricsHandler{
		inner:        h.inner.WithAttrs(attrs),
		metrics:      h.metrics,
		handlerName:  h.handlerName,
		errorHandler: h.errorHandler,
	}
}

// WithGroup implements slog.Handler.
func (h *MetricsHandler) WithGroup(name string) slog.Handler {
	return &MetricsHandler{
		inner:        h.inner.WithGroup(name),
		metrics:      h.metrics,
		handlerName:  h.handlerName,
		errorHandler: h.errorHandler,
	}
}

func (h *MetricsHandler) unwrapHandler() slog.Handler {
	return h.inner
}

func (h *MetricsHandler) setErrorHandler(fn ErrorHandler) {
	h.errorHandler.Store(&fn)
	// propagateErrorHandler also recurses via unwrapHandler to reach inner.
}

var (
	_ slog.Handler     = (*MetricsHandler)(nil)
	_ handlerUnwrapper = (*MetricsHandler)(nil)
)
