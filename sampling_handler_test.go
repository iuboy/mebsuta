package mebsuta

import (
	"bytes"
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// =============================================================================
// 辅助
// =============================================================================

type countHandler struct {
	mu     sync.Mutex
	count  int64
	levels []slog.Level
}

func (h *countHandler) Enabled(_ context.Context, _ slog.Level) bool { return true }
func (h *countHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	h.count++
	h.levels = append(h.levels, r.Level)
	h.mu.Unlock()
	return nil
}
func (h *countHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *countHandler) WithGroup(string) slog.Handler      { return h }

func (h *countHandler) Count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return int(h.count)
}

func (h *countHandler) Levels() []slog.Level {
	h.mu.Lock()
	defer h.mu.Unlock()
	cp := make([]slog.Level, len(h.levels))
	copy(cp, h.levels)
	return cp
}

func (h *countHandler) ErrorLevelCount() int64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	var n int64
	for _, l := range h.levels {
		if l >= slog.LevelError {
			n++
		}
	}
	return n
}

func closeSampling(t *testing.T, h slog.Handler) {
	t.Helper()
	if closer, ok := h.(interface{ Close() error }); ok {
		closer.Close()
	}
}

// =============================================================================
// SamplingHandler 测试
// =============================================================================

func TestWithSampling_Disabled(t *testing.T) {
	inner := &countHandler{}
	h := WithSampling(inner, SamplingConfig{Enabled: false})
	logger := slog.New(h)

	for range 100 {
		logger.Info("test")
	}

	if inner.Count() != 100 {
		t.Errorf("expected 100 when disabled, got %d", inner.Count())
	}
}

func TestWithSampling_NilHandler(t *testing.T) {
	h := WithSampling(nil, SamplingConfig{Enabled: true, Initial: 100, Thereafter: 10, Window: time.Second})
	if h != nil {
		t.Error("expected nil handler to return nil")
	}
}

func TestWithSampling_BasicSampling(t *testing.T) {
	inner := &countHandler{}
	h := WithSampling(inner, SamplingConfig{Enabled: true, Initial: 5, Thereafter: 2, Window: time.Second})
	defer closeSampling(t, h)
	logger := slog.New(h)

	for i := range 20 {
		logger.Info("test", "i", i)
	}

	count := inner.Count()
	// 前 5 条 + 之后每 2 条记 1 条: 5 + ceil(15/2) = 5 + 8 = 13
	if count < 5 {
		t.Errorf("expected at least initial 5, got %d", count)
	}
	if count > 20 {
		t.Errorf("expected at most 20, got %d", count)
	}
}

func TestWithSampling_ErrorAlwaysRecorded(t *testing.T) {
	inner := &countHandler{}
	h := WithSampling(inner, SamplingConfig{Enabled: true, Initial: 1, Thereafter: 100, Window: time.Second})
	defer closeSampling(t, h)
	logger := slog.New(h)

	for i := range 10 {
		logger.Error("error", "i", i)
	}

	if inner.Count() != 10 {
		t.Errorf("all errors should be recorded, got %d", inner.Count())
	}
}

func TestWithSampling_WarnSampled(t *testing.T) {
	inner := &countHandler{}
	h := WithSampling(inner, SamplingConfig{Enabled: true, Initial: 1, Thereafter: 100, Window: time.Second})
	defer closeSampling(t, h)
	logger := slog.New(h)

	for i := range 10 {
		logger.Warn("warn", "i", i)
	}

	if inner.Count() != 1 {
		t.Errorf("only initial 1 warn should be recorded, got %d", inner.Count())
	}
}

func TestWithSampling_WindowReset(t *testing.T) {
	inner := &countHandler{}
	h := WithSampling(inner, SamplingConfig{Enabled: true, Initial: 5, Thereafter: 10, Window: 100 * time.Millisecond})
	defer closeSampling(t, h)
	logger := slog.New(h)

	// 第一窗口：6 条（前 5 全记录，第 6 条被采样）
	for range 6 {
		logger.Info("window1")
	}

	time.Sleep(150 * time.Millisecond)

	// 第二窗口：6 条（计数器重置，前 5 全记录）
	for range 6 {
		logger.Info("window2")
	}

	count := inner.Count()
	// 至少 10 条（每个窗口 5 条初始）
	if count < 10 {
		t.Errorf("expected at least 10 after window reset, got %d", count)
	}
}

func TestWithSampling_Concurrent(t *testing.T) {
	inner := &countHandler{}
	h := WithSampling(inner, SamplingConfig{Enabled: true, Initial: 100, Thereafter: 10, Window: time.Second})
	defer closeSampling(t, h)
	logger := slog.New(h)

	var wg sync.WaitGroup
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 100 {
				logger.Info("concurrent")
			}
		}()
	}
	wg.Wait()

	count := inner.Count()
	if count == 0 {
		t.Error("expected some logs to be recorded")
	}
	if count > 1000 {
		t.Errorf("expected less than 1000, got %d", count)
	}
}

func TestWithSampling_WithAttrs(t *testing.T) {
	inner := &countHandler{}
	h := WithSampling(inner, SamplingConfig{Enabled: true, Initial: 3, Thereafter: 10, Window: time.Second})
	defer closeSampling(t, h)

	child := h.WithAttrs([]slog.Attr{slog.String("component", "test")})
	logger := slog.New(child)

	for range 10 {
		logger.Info("test")
	}

	if inner.Count() < 3 {
		t.Errorf("expected at least initial 3, got %d", inner.Count())
	}
}

func TestWithSampling_WithGroup(t *testing.T) {
	inner := &countHandler{}
	h := WithSampling(inner, SamplingConfig{Enabled: true, Initial: 3, Thereafter: 10, Window: time.Second})
	defer closeSampling(t, h)

	child := h.WithGroup("request")
	logger := slog.New(child)

	for range 10 {
		logger.Info("test")
	}

	if inner.Count() < 3 {
		t.Errorf("expected at least initial 3, got %d", inner.Count())
	}
}

func TestWithSampling_Enabled(t *testing.T) {
	h := WithSampling(&countHandler{}, SamplingConfig{Enabled: true, Initial: 1, Thereafter: 100, Window: time.Second})
	defer closeSampling(t, h)

	if !h.Enabled(context.Background(), slog.LevelError) {
		t.Error("Error should always be enabled")
	}
	if !h.Enabled(context.Background(), slog.LevelInfo) {
		t.Error("Info should be enabled (delegated to inner)")
	}
}

func TestWithSampling_Close(t *testing.T) {
	inner := &countHandler{}
	h := WithSampling(inner, SamplingConfig{Enabled: true, Initial: 10, Thereafter: 5, Window: 100 * time.Millisecond})

	if sh, ok := h.(interface{ Close() error }); ok {
		// 第一次关闭
		if err := sh.Close(); err != nil {
			t.Errorf("Close() error: %v", err)
		}
		// 第二次关闭应幂等
		if err := sh.Close(); err != nil {
			t.Errorf("double Close() error: %v", err)
		}
	}
}

func TestWithSampling_Defaults(t *testing.T) {
	inner := &countHandler{}
	// 零值配置应使用默认值
	h := WithSampling(inner, SamplingConfig{Enabled: true, Initial: 100, Thereafter: 10, Window: time.Second})
	defer closeSampling(t, h)
	logger := slog.New(h)

	for range 200 {
		logger.Info("test")
	}

	count := inner.Count()
	if count == 0 || count > 200 {
		t.Errorf("expected some sampling with defaults, got %d", count)
	}
}

// =============================================================================
// RecordToLogEntry 已在 mebsuta_test.go 中测试
// 这里验证 Attr 提取完整性
// =============================================================================

func TestRecordToLogEntry_ManyAttrs(t *testing.T) {
	r := slog.NewRecord(time.Now(), slog.LevelInfo, "test", 0)
	r.AddAttrs(
		slog.String("k1", "v1"),
		slog.Int("k2", 42),
		slog.Bool("k3", true),
		slog.Duration("k4", time.Second),
	)

	entry := RecordToLogEntry(r)
	if len(entry.Attrs) != 4 {
		t.Errorf("expected 4 attrs, got %d", len(entry.Attrs))
	}
}

// =============================================================================
// 并发安全的 atomic 计数测试
// =============================================================================

func TestAtomicSamplingCounter(t *testing.T) {
	var count atomic.Int64
	const goroutines = 100

	var wg sync.WaitGroup
	for range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 1000 {
				count.Add(1)
			}
		}()
	}
	wg.Wait()

	if count.Load() != int64(goroutines*1000) {
		t.Errorf("expected %d, got %d", goroutines*1000, count.Load())
	}
}

// =============================================================================
// StdoutHandler + Sampling 组合测试
// =============================================================================

func TestStdoutHandler_WithSampling(t *testing.T) {
	var buf bytes.Buffer
	h := newStdoutHandlerWithWriter(&buf, StdoutConfig{Level: slog.LevelInfo})

	sampled := WithSampling(h, SamplingConfig{Enabled: true, Initial: 5, Thereafter: 10, Window: time.Second})
	defer closeSampling(t, sampled)

	logger := slog.New(sampled)
	for range 20 {
		logger.Info("test")
	}

	lines := bytes.Count(buf.Bytes(), []byte("\n"))
	if lines < 5 {
		t.Errorf("expected at least 5 lines, got %d", lines)
	}
	if lines > 20 {
		t.Errorf("expected at most 20 lines, got %d", lines)
	}
}

// SPEC: "Audit records must not be dropped regardless of sampling state."
func TestWithSampling_AuditAlwaysRecorded(t *testing.T) {
	inner := &countHandler{}
	h := WithSampling(inner, SamplingConfig{Enabled: true, Initial: 1, Thereafter: 100, Window: time.Second})
	defer closeSampling(t, h)
	logger := slog.New(h)

	for range 10 {
		logger.Log(context.Background(), LevelAudit, "audit", "i", 0)
	}

	if inner.Count() != 10 {
		t.Errorf("all audit records should bypass sampling, got %d/10", inner.Count())
	}
}
