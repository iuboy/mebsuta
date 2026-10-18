package mebsuta

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
)

type mutexBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *mutexBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *mutexBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

type ctxProbeHandler2 struct{ onHandle func(error) }

func (c ctxProbeHandler2) Enabled(context.Context, slog.Level) bool { return true }
func (c ctxProbeHandler2) Handle(ctx context.Context, _ slog.Record) error {
	c.onHandle(ctx.Err())
	return nil
}
func (c ctxProbeHandler2) WithAttrs([]slog.Attr) slog.Handler { return c }
func (c ctxProbeHandler2) WithGroup(string) slog.Handler      { return c }

// TestAsyncGroupHandler_CloseDrainsWithLiveContext is the regression test for
// the fix gap: the WithoutCancel change initially covered only the plain
// path — the WithGroup path still forwarded the raw request ctx, so ctx-aware
// inner handlers dropped records queued during Close's drain.
func TestAsyncGroupHandler_CloseDrainsWithLiveContext(t *testing.T) {
	var mu sync.Mutex
	var gotErrs []error
	inner := ctxProbeHandler2{onHandle: func(err error) {
		mu.Lock()
		defer mu.Unlock()
		gotErrs = append(gotErrs, err)
	}}

	h := WithAsync(inner, AsyncConfig{BufferSize: 8}).(*AsyncHandler)
	grouped := h.WithGroup("audit")
	for i := 0; i < 5; i++ {
		// Cancelled request contexts must not leak cancellation into the
		// drained records.
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		r := slog.NewRecord(time.Now(), slog.LevelInfo, "g", 0)
		if err := grouped.Handle(ctx, r); err != nil {
			t.Fatalf("Handle: %v", err)
		}
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

type traceKey struct{}

// TestContextExtractor_PanicRecovered: an extractor that panics (classic
// unchecked ctx.Value type assertion) must not kill the log call — the record
// is still logged without the context attrs, and the panic is reported.
func TestContextExtractor_PanicRecovered(t *testing.T) {
	var buf mutexBuffer
	inner := newContractJSONHandler(&buf, nil)
	h := WithContextExtractor(inner, func(ctx context.Context) []slog.Attr {
		_ = ctx.Value(traceKey{}).(string) // panics when key absent
		return nil
	})

	var reported int
	h.(*contextExtractorHandler).setErrorHandler(func(*HandlerError) { reported++ })

	logger := slog.New(h)
	logger.Info("must survive")

	if !strings.Contains(buf.String(), "must survive") {
		t.Fatalf("record lost after extractor panic: %q", buf.String())
	}
	if reported == 0 {
		t.Error("extractor panic was not reported to the error handler")
	}
}

// TestContextExtractor_NilExtractorPassthrough: nil extractor must degrade to
// a no-op pass-through, NOT replace the whole output chain with a discard
// handler (which silently ate every log including audit records).
func TestContextExtractor_NilExtractorPassthrough(t *testing.T) {
	var buf mutexBuffer
	inner := newContractJSONHandler(&buf, nil)
	h := WithContextExtractor(inner, nil)
	if _, same := h.(*contractJSONHandler); !same {
		t.Fatalf("nil extractor should return inner unchanged, got %T", h)
	}
	slog.New(h).Info("still logged")
	if !strings.Contains(buf.String(), "still logged") {
		t.Fatal("nil extractor discarded the output chain")
	}
}

// TestAsyncHandler_ConcurrentCloseSendRace exercises the sendMu design: close
// racing with in-flight sends must be race-detector-clean (the previous
// close+recover design reported DATA RACE under -race).
func TestAsyncHandler_ConcurrentCloseSendRace(t *testing.T) {
	for range 20 {
		inner := ctxProbeHandler2{onHandle: func(error) {}}
		h := WithAsync(inner, AsyncConfig{BufferSize: 4}).(*AsyncHandler)
		var wg sync.WaitGroup
		for i := 0; i < 4; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := 0; j < 50; j++ {
					r := slog.NewRecord(time.Now(), slog.LevelInfo, "m", 0)
					_ = h.Handle(context.Background(), r)
				}
			}()
		}
		_ = h.Close()
		wg.Wait()
	}
}
