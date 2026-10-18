package mebsuta

import (
	"context"
	"fmt"
	"log/slog"
	"sync/atomic"
)

// ContextExtractor extracts slog.Attr values from a context.Context.
//
// Extractors run on the log call path. A panicking extractor (e.g. an
// unchecked ctx.Value type assertion) is recovered and reported via the
// ErrorHandler; the record is still logged, without the extracted attrs.
type ContextExtractor func(ctx context.Context) []slog.Attr

// contextExtractorHandler is a slog.Handler decorator that injects context-derived
// attrs into each record. It uses a fully-delegating model: WithGroup/WithAttrs are
// forwarded to inner, and extracted attrs are injected as ordinary record attrs.
// The inner handler owns all group prefixing, so record attrs, WithAttrs attrs,
// and extracted attrs all receive the group prefix exactly once.
type contextExtractorHandler struct {
	errorHandler *atomic.Pointer[ErrorHandler] // shared across clones
	inner        slog.Handler
	extract      ContextExtractor
}

// WithContextExtractor wraps inner and injects attributes extracted from context into each log record.
//
// A nil extractor is a no-op: inner is returned unchanged rather than being
// replaced by a discard handler — silently discarding the whole output chain
// (audit records included) over a nil callback was far worse than skipping
// the injection. If inner is nil, a no-op discard handler is returned.
func WithContextExtractor(inner slog.Handler, extract ContextExtractor) slog.Handler {
	if inner == nil {
		// Return a safe discard handler instead of nil to prevent panics
		// when callers invoke Handler methods on the result.
		return discardHandler{}
	}
	if extract == nil {
		return inner
	}
	eh := DefaultErrorHandler
	ep := new(atomic.Pointer[ErrorHandler])
	ep.Store(&eh)
	return &contextExtractorHandler{
		errorHandler: ep,
		inner:        inner,
		extract:      extract,
	}
}

func (h *contextExtractorHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.inner.Enabled(ctx, level)
}

// extractSafe runs the user extractor with panic recovery. Whether the
// extractor runs on the caller's goroutine (this middleware outermost) or on
// the async worker (extractor inside WithAsync) must not decide whether a
// panic kills the process — safeMulti and the async worker both contain
// handler panics, so the only user callback on the synchronous path gets the
// same containment.
func (h *contextExtractorHandler) extractSafe(ctx context.Context) (attrs []slog.Attr) {
	defer func() {
		if p := recover(); p != nil {
			attrs = nil
			ReportError(LoadErrorHandler(h.errorHandler), &HandlerError{
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
	// Clone before AddAttrs to avoid mutating the caller's record (slog contract).
	// The inner handler applies group prefixing uniformly to all attrs — record,
	// extracted, and WithAttrs — so we don't need any local group tracking.
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
	h.errorHandler.Store(&fn)
	// propagateErrorHandler also recurses via unwrapHandler to reach inner.
}

// discardHandler is a slog.Handler that silently discards all records.
// It is used as a safe default when a nil handler is passed to a constructor.
type discardHandler struct{}

func (discardHandler) Enabled(context.Context, slog.Level) bool  { return false }
func (discardHandler) Handle(context.Context, slog.Record) error { return nil }
func (d discardHandler) WithAttrs([]slog.Attr) slog.Handler      { return d }
func (d discardHandler) WithGroup(string) slog.Handler           { return d }

var (
	_ slog.Handler     = (*contextExtractorHandler)(nil)
	_ handlerUnwrapper = (*contextExtractorHandler)(nil)
)
