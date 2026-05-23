package mebsutatest

import (
	"context"
	"log/slog"
	"sync"
	"testing"
	"time"
)

func TestCaptureHandler_Basic(t *testing.T) {
	h := NewCaptureHandler()
	logger := slog.New(h)

	logger.Info("hello", "key", "value")

	AssertRecordCount(t, h, 1)
	AssertLevel(t, h, 0, slog.LevelInfo)
	AssertMessage(t, h, 0, "hello")
	AssertHasAttr(t, h, 0, "key", "value")
}

func TestCaptureHandler_MultipleRecords(t *testing.T) {
	h := NewCaptureHandler()
	logger := slog.New(h)

	logger.Debug("debug msg")
	logger.Info("info msg")
	logger.Warn("warn msg")

	AssertRecordCount(t, h, 3)
	AssertMessage(t, h, 0, "debug msg")
	AssertMessage(t, h, 1, "info msg")
	AssertMessage(t, h, 2, "warn msg")
}

func TestCaptureHandler_WithAttrs(t *testing.T) {
	h := NewCaptureHandler()
	logger := slog.New(h)

	child := logger.With("preset", "yes")
	child.Info("child msg", "extra", "data")

	AssertRecordCount(t, h, 1)
	AssertHasAttr(t, h, 0, "preset", "yes")
	AssertHasAttr(t, h, 0, "extra", "data")
}

func TestCaptureHandler_WithGroup(t *testing.T) {
	h := NewCaptureHandler()
	logger := slog.New(h)

	grouped := logger.WithGroup("request")
	grouped.Info("test", "id", "123")

	AssertRecordCount(t, h, 1)
	AssertHasAttr(t, h, 0, "request.id", "123")
}

func TestCaptureHandler_LevelFilter(t *testing.T) {
	h := NewCaptureHandlerAt(slog.LevelWarn)
	logger := slog.New(h)

	logger.Info("should be filtered")
	logger.Warn("should pass")

	AssertRecordCount(t, h, 1)
	AssertMessage(t, h, 0, "should pass")
}

func TestCaptureHandler_Reset(t *testing.T) {
	h := NewCaptureHandler()
	logger := slog.New(h)

	logger.Info("first")
	AssertRecordCount(t, h, 1)

	h.Reset()
	AssertRecordCount(t, h, 0)

	logger.Info("second")
	AssertRecordCount(t, h, 1)
}

func TestCaptureHandler_Last(t *testing.T) {
	h := NewCaptureHandler()

	_, ok := h.Last()
	if ok {
		t.Fatal("expected no records")
	}

	logger := slog.New(h)
	logger.Info("msg1")
	logger.Info("msg2")

	rec, ok := h.Last()
	if !ok {
		t.Fatal("expected a record")
	}
	if rec.Message != "msg2" {
		t.Fatalf("expected msg2, got %q", rec.Message)
	}
}

func TestCaptureHandler_Concurrent(t *testing.T) {
	h := NewCaptureHandler()
	logger := slog.New(h)

	var wg sync.WaitGroup
	for i := range 100 {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			logger.Info("concurrent", "n", n)
		}(i)
	}
	wg.Wait()

	AssertRecordCount(t, h, 100)
}

func TestCaptureHandler_RecordFields(t *testing.T) {
	h := NewCaptureHandler()
	ctx := context.Background()

	ts := time.Date(2026, 5, 23, 12, 0, 0, 0, time.UTC)
	r := slog.NewRecord(ts, slog.LevelError, "error msg", 0)
	r.AddAttrs(slog.Int("code", 500))

	_ = h.Handle(ctx, r)

	records := h.Records()
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	rec := records[0]
	if !rec.Time.Equal(ts) {
		t.Fatalf("expected time %v, got %v", ts, rec.Time)
	}
	if rec.Level != slog.LevelError {
		t.Fatalf("expected ERROR, got %v", rec.Level)
	}
	if rec.Message != "error msg" {
		t.Fatalf("expected 'error msg', got %q", rec.Message)
	}
	if len(rec.Attrs) != 1 || rec.Attrs[0].Key != "code" {
		t.Fatalf("expected attr 'code', got %v", rec.Attrs)
	}
}
