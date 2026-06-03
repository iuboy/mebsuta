package mebsuta

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"reflect"
	"sync"
	"time"
)

// ReportError invokes the ErrorHandler if non-nil.
func ReportError(eh ErrorHandler, he HandlerError) {
	if eh != nil {
		if he.Time.IsZero() {
			he.Time = time.Now()
		}
		eh(he)
	}
}

// safeMultiHandler wraps multiple sub-handlers, adding panic recovery to each call. Prevents a single handler panic from crashing the entire log call.
func safeMultiHandler(handlers []slog.Handler, eh ErrorHandler) slog.Handler {
	return &safeMulti{
		handlers:     handlers,
		errorHandler: eh,
	}
}

// safeMulti fans out log records to multiple handlers with per-handler panic recovery.
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
		// Single handler: call directly without goroutine overhead
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
			// r.Clone() prevents concurrent goroutines from racing on slog.Record.
			// Clone has a fast path: with no Attrs, only fixed fields are copied with no heap allocation.
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
// Uses a visited map to prevent shared handlers from being closed more than once.
func CloseAll(handler slog.Handler) error {
	return closeAll(handler, make(map[uintptr]bool))
}

// handlerIdentity returns a unique pointer for deduplication. Returns (0, false)
// for value-type handlers that cannot be identified by pointer.
func handlerIdentity(h slog.Handler) (uintptr, bool) {
	v := reflect.ValueOf(h)
	if v.Kind() == reflect.Ptr {
		return v.Pointer(), true
	}
	return 0, false
}

func closeAll(handler slog.Handler, visited map[uintptr]bool) error {
	if handler == nil {
		return nil
	}
	// Use reflect to get the interface's underlying pointer for identity comparison.
	// This is necessary because slog.Handler is an interface — you can't take the
	// address of an interface value directly. reflect.ValueOf is the standard Go
	// approach for interface pointer identity.
	// Value-type handlers (uncommon) cannot be deduplicated; they are always processed.
	ptr, canDedup := handlerIdentity(handler)
	if canDedup {
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
		if err := closeAll(uw.unwrapHandler(), visited); err != nil {
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
