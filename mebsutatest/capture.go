// Package mebsutatest provides test utilities for mebsuta log handlers.
//
// Typical usage:
//
//	h := mebsutatest.NewCaptureHandler()
//	logger := slog.New(h)
//	logger.Info("hello", "key", "value")
//	mebsutatest.AssertRecordCount(t, h, 1)
//	mebsutatest.AssertHasAttr(t, h, 0, "key", "value")
package mebsutatest

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// CapturedRecord holds a single captured log record with all its attributes.
type CapturedRecord struct {
	Time    time.Time
	Level   slog.Level
	Message string
	Attrs   []slog.Attr
}

// CaptureHandler is a slog.Handler that captures all records in memory
// for test assertions. It is safe for concurrent use.
type CaptureHandler struct {
	mu      sync.Mutex
	records []CapturedRecord
	enabled slog.Level
}

// NewCaptureHandler creates a CaptureHandler that accepts all log levels.
func NewCaptureHandler() *CaptureHandler {
	return &CaptureHandler{enabled: slog.LevelDebug}
}

// NewCaptureHandlerAt creates a CaptureHandler that only accepts levels >= min.
func NewCaptureHandlerAt(min slog.Level) *CaptureHandler {
	return &CaptureHandler{enabled: min}
}

// Enabled implements slog.Handler.
func (h *CaptureHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.enabled
}

// Handle implements slog.Handler.
func (h *CaptureHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	rec := CapturedRecord{
		Time:    r.Time,
		Level:   r.Level,
		Message: r.Message,
	}
	r.Attrs(func(a slog.Attr) bool {
		rec.Attrs = append(rec.Attrs, a)
		return true
	})
	h.records = append(h.records, rec)
	return nil
}

// WithAttrs implements slog.Handler.
func (h *CaptureHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &captureAttrsHandler{parent: h, attrs: attrs}
}

// WithGroup implements slog.Handler.
func (h *CaptureHandler) WithGroup(name string) slog.Handler {
	return &captureGroupHandler{parent: h, group: name}
}

// Records returns all captured records. The returned slice is a copy.
func (h *CaptureHandler) Records() []CapturedRecord {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]CapturedRecord, len(h.records))
	copy(out, h.records)
	return out
}

// Len returns the number of captured records.
func (h *CaptureHandler) Len() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.records)
}

// Reset clears all captured records.
func (h *CaptureHandler) Reset() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = nil
}

// Last returns the most recently captured record, or false if none.
func (h *CaptureHandler) Last() (CapturedRecord, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.records) == 0 {
		return CapturedRecord{}, false
	}
	return h.records[len(h.records)-1], true
}

type captureAttrsHandler struct {
	parent *CaptureHandler
	attrs  []slog.Attr
	group  string
}

func (h *captureAttrsHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.parent.Enabled(ctx, level)
}

func (h *captureAttrsHandler) Handle(ctx context.Context, r slog.Record) error {
	if h.group != "" {
		prefixed := slog.NewRecord(r.Time, r.Level, r.Message, r.PC)
		r.Attrs(func(a slog.Attr) bool {
			prefixed.AddAttrs(slog.Attr{Key: h.group + "." + a.Key, Value: a.Value})
			return true
		})
		r = prefixed
	}
	r.AddAttrs(h.attrs...)
	return h.parent.Handle(ctx, r)
}

func (h *captureAttrsHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &captureAttrsHandler{parent: h.parent, attrs: append(h.attrs[:], attrs...), group: h.group}
}

func (h *captureAttrsHandler) WithGroup(name string) slog.Handler {
	return &captureGroupHandler{parent: h.parent, group: name, attrs: h.attrs}
}

type captureGroupHandler struct {
	parent *CaptureHandler
	group  string
	attrs  []slog.Attr
}

func (h *captureGroupHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.parent.Enabled(ctx, level)
}

func (h *captureGroupHandler) Handle(ctx context.Context, r slog.Record) error {
	prefixed := slog.NewRecord(r.Time, r.Level, r.Message, r.PC)
	r.Attrs(func(a slog.Attr) bool {
		prefixed.AddAttrs(slog.Attr{Key: h.group + "." + a.Key, Value: a.Value})
		return true
	})
	prefixed.AddAttrs(h.attrs...)
	return h.parent.Handle(ctx, prefixed)
}

func (h *captureGroupHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &captureAttrsHandler{parent: h.parent, attrs: attrs, group: h.group}
}

func (h *captureGroupHandler) WithGroup(name string) slog.Handler {
	return &captureGroupHandler{parent: h.parent, group: h.group + "." + name, attrs: h.attrs}
}

var (
	_ slog.Handler = (*CaptureHandler)(nil)
	_ slog.Handler = (*captureAttrsHandler)(nil)
	_ slog.Handler = (*captureGroupHandler)(nil)
)
