package mebsuta

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestContractJSONHandler_NestedUnserializableFallback is the regression test
// for the silent record loss: a NaN (or chan/func) nested inside a map attr
// used to fail json.Marshal, and Handle returned the error — which
// slog.Logger discards — so the record vanished with no trace. Now a
// fallback ERROR record must be written.
func TestContractJSONHandler_NestedUnserializableFallback(t *testing.T) {
	h, buf := newJSONHandler(t)

	r := slog.NewRecord(time.Now(), slog.LevelInfo, "IMPORTANT audit message", 0)
	r.AddAttrs(slog.Any("nested", map[string]any{"ratio": math.NaN()}))
	if err := h.Handle(context.Background(), r); err != nil {
		t.Fatalf("Handle returned error instead of degrading: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "marshal failed") {
		t.Fatalf("expected fallback record, got: %q", out)
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &parsed); err != nil {
		t.Fatalf("fallback output is not valid JSON: %v\n%s", err, out)
	}
	if parsed["level"] != "ERROR" {
		t.Errorf("fallback level = %v, want ERROR", parsed["level"])
	}
	attrs := parsed["attributes"].(map[string]any)
	if !strings.Contains(attrs["original_message"].(string), "IMPORTANT audit message") {
		t.Errorf("fallback lost original message: %v", attrs["original_message"])
	}
	if attrs["marshal_error"] == nil {
		t.Error("fallback missing marshal_error attribute")
	}
}

// TestAsyncHandler_InnerPanicRecovered: a panicking third-party inner handler
// must not kill the background goroutine (and the process).
func TestAsyncHandler_InnerPanicRecovered(t *testing.T) {
	var mu sync.Mutex
	handled := 0
	inner := regressPanicHandler{onHandle: func() { mu.Lock(); handled++; mu.Unlock() }}

	h := WithAsync(inner, AsyncConfig{BufferSize: 4}).(*AsyncHandler)
	defer h.Close()

	logger := slog.New(h)
	logger.Info("before")
	logger.Info("boom") // panics in inner
	logger.Info("after")

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := handled
		mu.Unlock()
		if n == 3 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if handled != 3 {
		t.Fatalf("records handled = %d, want 3 (panic must not stop the worker)", handled)
	}
}

type regressPanicHandler struct{ onHandle func() }

func (p regressPanicHandler) Enabled(context.Context, slog.Level) bool { return true }

func (p regressPanicHandler) Handle(_ context.Context, r slog.Record) error {
	p.onHandle()
	if r.Message == "boom" {
		panic("inner handler exploded")
	}
	return nil
}

func (p regressPanicHandler) WithAttrs([]slog.Attr) slog.Handler { return p }
func (p regressPanicHandler) WithGroup(string) slog.Handler      { return p }

// TestAsyncHandler_CloseDrainsWithLiveContext is the regression test for the
// Close ordering bug: Close previously cancelled the context before draining,
// so ctx-aware inner handlers dropped the final batch. The drained records
// must now observe a live (non-cancelled) context.
func TestAsyncHandler_CloseDrainsWithLiveContext(t *testing.T) {
	var mu sync.Mutex
	var gotErrs []error
	inner := ctxProbeHandler{onHandle: func(err error) {
		mu.Lock()
		defer mu.Unlock()
		gotErrs = append(gotErrs, err)
	}}

	h := WithAsync(inner, AsyncConfig{BufferSize: 8}).(*AsyncHandler)
	logger := slog.New(h)
	for i := range 5 {
		logger.Info(fmt.Sprintf("record %d", i))
	}

	if err := h.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(gotErrs) != 5 {
		t.Fatalf("drained records = %d, want 5", len(gotErrs))
	}
	for i, err := range gotErrs {
		if err != nil {
			t.Errorf("record %d saw cancelled context during Close drain: %v", i, err)
		}
	}
}

type ctxProbeHandler struct{ onHandle func(error) }

func (c ctxProbeHandler) Enabled(context.Context, slog.Level) bool { return true }
func (c ctxProbeHandler) Handle(ctx context.Context, _ slog.Record) error {
	c.onHandle(ctx.Err())
	return nil
}
func (c ctxProbeHandler) WithAttrs([]slog.Attr) slog.Handler { return c }
func (c ctxProbeHandler) WithGroup(string) slog.Handler      { return c }

// TestAsyncHandler_DropReportRateLimited: a flood that overflows the buffer
// must not produce one error-handler invocation per dropped record.
func TestAsyncHandler_DropReportRateLimited(t *testing.T) {
	block := make(chan struct{})
	inner := blockingHandler{block: block}

	h := WithAsync(inner, AsyncConfig{BufferSize: 2}).(*AsyncHandler)
	// Unblock the worker BEFORE Close (defers run LIFO: h.Close would wait
	// forever on a worker parked on block).
	defer func() { close(block); _ = h.Close() }()

	var mu sync.Mutex
	reports := 0
	h.setErrorHandler(func(*HandlerError) {
		mu.Lock()
		defer mu.Unlock()
		reports++
	})

	logger := slog.New(h)
	// Fill the buffer (worker blocked), then overflow heavily.
	for i := 0; i < 200; i++ {
		logger.Info("flood")
	}

	mu.Lock()
	defer mu.Unlock()
	if reports > 2 {
		t.Errorf("drop reports = %d for ~198 drops, rate limiter not effective (want <= 2)", reports)
	}
	if h.Dropped() < 190 {
		t.Errorf("dropped counter = %d, want the flood losses counted", h.Dropped())
	}
}

type blockingHandler struct{ block chan struct{} }

func (b blockingHandler) Enabled(context.Context, slog.Level) bool { return true }
func (b blockingHandler) Handle(context.Context, slog.Record) error {
	<-b.block
	return nil
}
func (b blockingHandler) WithAttrs([]slog.Attr) slog.Handler { return b }
func (b blockingHandler) WithGroup(string) slog.Handler      { return b }

// TestWithErrorHandler_ReachesSubHandlers verifies the exported
// ErrorHandlerSetter path: WithErrorHandler must reach handlers in other
// packages (here represented by a fake implementing the exported interface).
func TestWithErrorHandler_ReachesSubHandlers(t *testing.T) {
	fake := &fakeSettableHandler{}
	logger, err := New(WithHandler(fake), WithErrorHandler(SilentErrorHandler()))
	if err != nil {
		t.Fatal(err)
	}
	if fake.set == nil {
		t.Fatal("WithErrorHandler did not propagate to the exported SetErrorHandler")
	}
	_ = logger
}

type fakeSettableHandler struct{ set ErrorHandler }

func (f *fakeSettableHandler) Enabled(context.Context, slog.Level) bool { return true }
func (f *fakeSettableHandler) Handle(context.Context, slog.Record) error {
	var buf bytes.Buffer
	_, _ = buf.WriteString("")
	return nil
}
func (f *fakeSettableHandler) WithAttrs([]slog.Attr) slog.Handler { return f }
func (f *fakeSettableHandler) WithGroup(string) slog.Handler      { return f }
func (f *fakeSettableHandler) SetErrorHandler(fn ErrorHandler)    { f.set = fn }
