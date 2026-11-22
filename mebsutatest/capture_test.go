package mebsutatest

import (
	"context"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
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
	require.False(t, ok, "不应有记录")

	logger := slog.New(h)
	logger.Info("msg1")
	logger.Info("msg2")

	rec, ok := h.Last()
	require.True(t, ok, "应有一条记录")
	require.Equal(t, "msg2", rec.Message)
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
	require.Len(t, records, 1)
	rec := records[0]
	require.True(t, rec.Time.Equal(ts), "时间应为 %v，实际 %v", ts, rec.Time)
	require.Equal(t, slog.LevelError, rec.Level)
	require.Equal(t, "error msg", rec.Message)
	require.Len(t, rec.Attrs, 1)
	require.Equal(t, "code", rec.Attrs[0].Key)
}
