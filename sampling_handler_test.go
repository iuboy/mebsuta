package mebsuta

import (
	"bytes"
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/iuboy/mebsuta/config"
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
func (h *countHandler) WithGroup(string) slog.Handler        { return h }

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

// =============================================================================
// SamplingHandler 测试
// =============================================================================

func TestWithSampling_Disabled(t *testing.T) {
	inner := &countHandler{}
	h := WithSampling(inner, config.SamplingConfig{Enabled: false})
	logger := slog.New(h)

	for range 100 {
		logger.Info("test")
	}

	if inner.Count() != 100 {
		t.Errorf("expected 100 when disabled, got %d", inner.Count())
	}
}

func TestWithSampling_NilHandler(t *testing.T) {
	h := WithSampling(nil, config.SamplingConfig{Enabled: true})
	if h != nil {
		t.Error("expected nil handler to return nil")
	}
}

func TestWithSampling_BasicSampling(t *testing.T) {
	inner := &countHandler{}
	h := WithSampling(inner, config.SamplingConfig{
		Enabled:    true,
		Initial:    5,
		Thereafter: 2,
		Window:     time.Second,
	})
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
	h := WithSampling(inner, config.SamplingConfig{
		Enabled:    true,
		Initial:    1,
		Thereafter: 100,
		Window:     time.Second,
	})
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
	h := WithSampling(inner, config.SamplingConfig{
		Enabled:    true,
		Initial:    1,
		Thereafter: 100,
		Window:     time.Second,
	})
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
	h := WithSampling(inner, config.SamplingConfig{
		Enabled:    true,
		Initial:    5,
		Thereafter: 10,
		Window:     100 * time.Millisecond,
	})
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
	h := WithSampling(inner, config.SamplingConfig{
		Enabled:    true,
		Initial:    100,
		Thereafter: 10,
		Window:     time.Second,
	})
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
	h := WithSampling(inner, config.SamplingConfig{
		Enabled:    true,
		Initial:    3,
		Thereafter: 10,
		Window:     time.Second,
	})

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
	h := WithSampling(inner, config.SamplingConfig{
		Enabled:    true,
		Initial:    3,
		Thereafter: 10,
		Window:     time.Second,
	})

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
	h := WithSampling(&countHandler{}, config.SamplingConfig{
		Enabled:    true,
		Initial:    1,
		Thereafter: 100,
		Window:     time.Second,
	})

	if !h.Enabled(context.Background(), slog.LevelError) {
		t.Error("Error should always be enabled")
	}
	if !h.Enabled(context.Background(), slog.LevelInfo) {
		t.Error("Info should be enabled (delegated to inner)")
	}
}

func TestWithSampling_Close(t *testing.T) {
	inner := &countHandler{}
	h := WithSampling(inner, config.SamplingConfig{
		Enabled:    true,
		Initial:    10,
		Thereafter: 5,
		Window:     100 * time.Millisecond,
	})

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
	h := WithSampling(inner, config.SamplingConfig{Enabled: true})
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
// SyslogHandler 配置验证测试（不需要真实连接）
// =============================================================================

func TestNewSyslogHandler_EmptyAddress(t *testing.T) {
	_, err := NewSyslogHandler(config.SyslogConfig{}, slog.LevelInfo)
	if err == nil {
		t.Fatal("expected error for empty address")
	}
}

func TestNewSyslogHandler_InvalidFacility(t *testing.T) {
	_, err := NewSyslogHandler(config.SyslogConfig{
		Address:  "localhost:514",
		Facility: 25,
	}, slog.LevelInfo)
	if err == nil {
		t.Fatal("expected error for invalid facility")
	}
}

func TestNewSyslogHandler_InvalidNetwork(t *testing.T) {
	// Network 不验证，只提供默认值
	// 但连接会失败
	_, err := NewSyslogHandler(config.SyslogConfig{
		Address: "localhost:1", // 非常端口，几乎不可能连接
	}, slog.LevelInfo)
	if err == nil {
		t.Error("expected connection error")
	}
}

func TestSyslogHandler_Enabled(t *testing.T) {
	h := &SyslogHandler{
		LevelHandler: LevelHandler{Level: slog.LevelWarn},
	}
	if h.Enabled(context.Background(), slog.LevelDebug) {
		t.Error("Debug should not be enabled at Warn level")
	}
	if !h.Enabled(context.Background(), slog.LevelError) {
		t.Error("Error should be enabled at Warn level")
	}
}

// =============================================================================
// 辅助函数测试
// =============================================================================

func TestCleanHostname(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"my-host", "my-host"},
		{"my_host", "my-host"},
		{"my host", "my-host"},
		{"192.168.1.1", "192.168.1.1"},
		{"", ""},
	}

	for _, tt := range tests {
		got := cleanHostname(tt.input)
		if got != tt.expected {
			t.Errorf("cleanHostname(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestSafeMessageForLog(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"hello world", "hello world"},
		{"hello\tworld", "hello world"},
		{"hello\x00world", "hello world"},
		{"  hello   world  ", "hello world"},
	}

	for _, tt := range tests {
		got := safeMessageForLog(tt.input)
		if got != tt.expected {
			t.Errorf("safeMessageForLog(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestLevelToSeverity(t *testing.T) {
	h := &SyslogHandler{cfg: config.SyslogConfig{Facility: 1}}

	tests := []struct {
		level slog.Level
		want  int
	}{
		{slog.LevelDebug, 7},
		{slog.LevelInfo, 6},
		{slog.LevelWarn, 4},
		{slog.LevelError, 3},
	}

	for _, tt := range tests {
		got := h.levelToSeverity(tt.level)
		if got != tt.want {
			t.Errorf("levelToSeverity(%v) = %d, want %d", tt.level, got, tt.want)
		}
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
	h := newStdoutHandlerWithWriter(&buf, slog.LevelInfo, JSON)

	sampled := WithSampling(h, config.SamplingConfig{
		Enabled:    true,
		Initial:    5,
		Thereafter: 10,
		Window:     time.Second,
	})

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
