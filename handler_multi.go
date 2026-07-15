package mebsuta

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// ReportError invokes the ErrorHandler if non-nil.
func ReportError(eh ErrorHandler, he *HandlerError) {
	if eh != nil {
		if he.Time.IsZero() {
			he.Time = time.Now()
		}
		eh(he)
	}
}

// safeMultiHandler wraps multiple sub-handlers, adding panic recovery to each call. Prevents a single handler panic from crashing the entire log call.
func safeMultiHandler(handlers []slog.Handler, eh ErrorHandler) slog.Handler {
	sm := &safeMulti{
		handlerCore: newHandlerCore(),
		handlers:    handlers,
	}
	sm.errorHandler.Store(&eh)
	return sm
}

// safeMulti fans out log records to multiple handlers with per-handler panic recovery.
type safeMulti struct {
	handlerCore
	handlers     []slog.Handler
	errorHandler atomic.Pointer[ErrorHandler]
}

// loadEH returns the configured ErrorHandler, or nil if none was set.
// setErrorHandler writes this field concurrently with Handle reads, so it is
// stored in an atomic.Pointer (matching syslog/database/async handlers).
func (h *safeMulti) loadEH() ErrorHandler {
	v := h.errorHandler.Load()
	if v == nil {
		return nil
	}
	return *v
}

func (h *safeMulti) Close() error {
	visited := make(map[uint64]bool)
	var errs []error
	for _, hh := range h.handlers {
		if err := closeAll(hh, visited, 0); err != nil {
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

// handleWithRecovery calls handler.Handle with panic recovery. Panics are reported via the error handler and converted to nil errors.
func (h *safeMulti) handleWithRecovery(handler slog.Handler, ctx context.Context, r slog.Record) (err error) {
	defer func() {
		if p := recover(); p != nil {
			ReportError(h.loadEH(), &HandlerError{Component: "multi", Operation: "handle", Err: fmt.Errorf("handler panic recovered: %v", p)})
			err = nil
		}
	}()
	return handler.Handle(ctx, r)
}

func (h *safeMulti) Handle(ctx context.Context, r slog.Record) error {
	if len(h.handlers) == 1 {
		// Single handler: call directly without goroutine overhead
		hh := h.handlers[0]
		if !hh.Enabled(ctx, r.Level) {
			return nil
		}
		return h.handleWithRecovery(hh, ctx, r)
	}

	// Filter to only enabled handlers.
	var enabled []slog.Handler
	for _, hh := range h.handlers {
		if hh.Enabled(ctx, r.Level) {
			enabled = append(enabled, hh)
		}
	}
	if len(enabled) == 0 {
		return nil
	}

	// For 2-3 enabled handlers, use sequential calls to avoid goroutine scheduling overhead.
	// Clone the record once per handler to prevent data races on slog.Record internals.
	if len(enabled) <= 3 {
		var firstErr error
		for _, hh := range enabled {
			func() {
				if err := h.handleWithRecovery(hh, ctx, r.Clone()); err != nil && firstErr == nil {
					firstErr = err
				}
			}()
		}
		return firstErr
	}

	// For 4+ enabled handlers, fan out with goroutines.
	var firstErr error
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, hh := range enabled {
		wg.Add(1)
		go func(handler slog.Handler) {
			defer wg.Done()
			if err := h.handleWithRecovery(handler, ctx, r.Clone()); err != nil {
				mu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				mu.Unlock()
			}
		}(hh)
	}
	wg.Wait()
	return firstErr
}

func (h *safeMulti) WithAttrs(attrs []slog.Attr) slog.Handler {
	propagated := make([]slog.Handler, len(h.handlers))
	for i, hh := range h.handlers {
		propagated[i] = hh.WithAttrs(attrs)
	}
	return h.cloneWith(propagated)
}

func (h *safeMulti) WithGroup(name string) slog.Handler {
	propagated := make([]slog.Handler, len(h.handlers))
	for i, hh := range h.handlers {
		propagated[i] = hh.WithGroup(name)
	}
	return h.cloneWith(propagated)
}

// cloneWith returns a new safeMulti sharing the current error handler (by
// pointer, so a later setErrorHandler on either instance is visible to both).
func (h *safeMulti) cloneWith(handlers []slog.Handler) slog.Handler {
	next := &safeMulti{
		handlerCore: newHandlerCore(),
		handlers:    handlers,
	}
	if eh := h.errorHandler.Load(); eh != nil {
		next.errorHandler.Store(eh)
	}
	return next
}

func (h *safeMulti) setErrorHandler(fn ErrorHandler) {
	h.errorHandler.Store(&fn)
	for _, hh := range h.handlers {
		propagateErrorHandler(hh, fn)
	}
}

// errorHandlerSetter is an internal interface for handlers that support custom error handling.
type errorHandlerSetter interface {
	setErrorHandler(fn ErrorHandler)
}

// propagateErrorHandler recursively unwraps the decorator chain, injecting errorHandler into all handlers that support setErrorHandler.
func propagateErrorHandler(h slog.Handler, fn ErrorHandler) {
	// Skip nil: do not overwrite handler defaults that were set at construction time.
	// When buildHandler is called without WithErrorHandler, fn is nil, and each
	// handler already initialized with DefaultErrorHandler should keep it.
	if fn == nil {
		return
	}
	if s, ok := h.(errorHandlerSetter); ok {
		s.setErrorHandler(fn)
	}
	if uw, ok := h.(handlerUnwrapper); ok {
		propagateErrorHandler(uw.unwrapHandler(), fn)
	}
}

// handlerUnwrapper is an internal interface for decorator implementations, used by CloseAll for recursive unwrapping.
type handlerUnwrapper interface {
	unwrapHandler() slog.Handler
}

// CloseAll recursively closes all resources in the handler and decorator chain that implement io.Closer.
// Built-in handlers are deduplicated by stable id; cycle protection is guaranteed
// by maxUnwrapDepth regardless of identity.
func CloseAll(handler slog.Handler) error {
	return closeAll(handler, make(map[uint64]bool), 0)
}

// handlerSeq assigns a unique, stable id to each built-in handler instance,
// replacing pointer-based identity so the close path no longer relies on
// unsafe.Pointer or interface-layout probing.
var handlerSeq atomic.Uint64

// handlerCore equips a built-in handler with a stable identity for CloseAll
// deduplication. Embed it in any concrete handler type; the embedded handlerID
// method satisfies handlerIdentifier.
type handlerCore struct{ id uint64 }

func newHandlerCore() handlerCore { return handlerCore{id: handlerSeq.Add(1)} }

func (c handlerCore) handlerID() uint64 { return c.id }

// handlerIdentifier is an internal interface for handlers that opt into CloseAll
// deduplication. All built-in handlers satisfy it via embedded handlerCore.
// External (third-party) handlers do not implement it: they are not deduplicated
// and rely on Close being idempotent (the standard io.Closer contract). Cycle
// protection comes from maxUnwrapDepth, not from identity, so no unsafe/reflect
// probing is required.
type handlerIdentifier interface {
	handlerID() uint64
}

// handlerIdentity returns a built-in handler's stable id. There is deliberately
// no fallback: third-party handlers are not deduplicated.
func handlerIdentity(h slog.Handler) (uint64, bool) {
	if hi, ok := h.(handlerIdentifier); ok {
		return hi.handlerID(), true
	}
	return 0, false
}

// maxUnwrapDepth caps recursion through handlerUnwrapper chains to guarantee
// termination even if a handler's unwrapHandler is self-referential. Real
// decorator chains are shallow (<10 layers); 64 is a generous safety bound.
const maxUnwrapDepth = 64

func closeAll(handler slog.Handler, visited map[uint64]bool, depth int) error {
	if handler == nil {
		return nil
	}
	// Hard termination guarantee against self-referential unwrapHandler cycles,
	// independent of any identity/dedup logic.
	if depth > maxUnwrapDepth {
		return nil
	}
	// Dedupe built-in handlers by stable id. External handlers without
	// handlerIdentifier are not deduplicated; their Close must be idempotent.
	if ptr, ok := handlerIdentity(handler); ok {
		if visited[ptr] {
			return nil
		}
		visited[ptr] = true
	}

	var errs []error
	if closer, ok := handler.(io.Closer); ok {
		if err := closer.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if uw, ok := handler.(handlerUnwrapper); ok {
		if err := closeAll(uw.unwrapHandler(), visited, depth+1); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// prefixAttrs prepends "group." to each attr's key. Returns attrs unchanged when group is empty.
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

var (
	_ slog.Handler = (*safeMulti)(nil)
	_ io.Closer    = (*safeMulti)(nil)
)
