package mebsuta

import (
	"bytes"
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/iuboy/mebsuta/config"
)

func BenchmarkStdoutHandler_JSON(b *testing.B) {
	var buf bytes.Buffer
	h := newStdoutHandlerWithWriter(&buf, slog.LevelInfo, JSON)
	logger := slog.New(h)

	b.ResetTimer()
	b.ReportAllocs()
	for range b.N {
		logger.Info("benchmark", "key", "value", "n", 42)
	}
}

func BenchmarkStdoutHandler_Console(b *testing.B) {
	var buf bytes.Buffer
	h := newStdoutHandlerWithWriter(&buf, slog.LevelInfo, Console)
	logger := slog.New(h)

	b.ResetTimer()
	b.ReportAllocs()
	for range b.N {
		logger.Info("benchmark", "key", "value", "n", 42)
	}
}

func BenchmarkStdoutHandler_WithAttrs(b *testing.B) {
	var buf bytes.Buffer
	h := newStdoutHandlerWithWriter(&buf, slog.LevelInfo, JSON)
	logger := slog.New(h.WithAttrs([]slog.Attr{
		slog.String("service", "bench"),
		slog.String("version", "1.0.0"),
	}))

	b.ResetTimer()
	b.ReportAllocs()
	for range b.N {
		logger.Info("benchmark", "key", "value")
	}
}

func BenchmarkSamplingHandler_Pass(b *testing.B) {
	var buf bytes.Buffer
	inner := newStdoutHandlerWithWriter(&buf, slog.LevelInfo, JSON)
	h := WithSampling(inner, config.SamplingConfig{
		Enabled:    true,
		Initial:    b.N + 100,
		Thereafter: 1,
		Window:     10 * time.Second,
	})
	logger := slog.New(h)

	b.ResetTimer()
	b.ReportAllocs()
	for range b.N {
		logger.Info("benchmark", "key", "value")
	}
}

func BenchmarkSamplingHandler_Drop(b *testing.B) {
	var buf bytes.Buffer
	inner := newStdoutHandlerWithWriter(&buf, slog.LevelInfo, JSON)
	h := WithSampling(inner, config.SamplingConfig{
		Enabled:    true,
		Initial:    1,
		Thereafter: 1000000,
		Window:     10 * time.Second,
	})
	logger := slog.New(h)

	b.ResetTimer()
	b.ReportAllocs()
	for range b.N {
		logger.Info("benchmark", "key", "value")
	}
}

func BenchmarkAsyncHandler(b *testing.B) {
	var buf bytes.Buffer
	inner := newStdoutHandlerWithWriter(&buf, slog.LevelInfo, JSON)
	h := WithAsync(inner, AsyncConfig{BufferSize: 1024})
	logger := slog.New(h)

	b.ResetTimer()
	b.ReportAllocs()
	for range b.N {
		logger.Info("benchmark", "key", "value", "n", 42)
	}

	// 等待所有异步写入完成
	if closer, ok := h.(interface{ Close() error }); ok {
		closer.Close()
	}
}

func BenchmarkMetricsHandler(b *testing.B) {
	var buf bytes.Buffer
	inner := newStdoutHandlerWithWriter(&buf, slog.LevelInfo, JSON)
	m := &nopMetrics{}
	h := WithMetrics(inner, m, "stdout")
	logger := slog.New(h)

	b.ResetTimer()
	b.ReportAllocs()
	for range b.N {
		logger.Info("benchmark", "key", "value", "n", 42)
	}
}

func BenchmarkContextExtractor(b *testing.B) {
	var buf bytes.Buffer
	inner := newStdoutHandlerWithWriter(&buf, slog.LevelInfo, JSON)
	h := WithContextExtractor(inner, func(ctx context.Context) []slog.Attr {
		return []slog.Attr{slog.String("trace_id", "abc-123")}
	})
	logger := slog.New(h)

	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()
	for range b.N {
		logger.InfoContext(ctx, "benchmark", "key", "value")
	}
}

func BenchmarkSafeMultiHandler_2Handlers(b *testing.B) {
	var buf1, buf2 bytes.Buffer
	h1 := newStdoutHandlerWithWriter(&buf1, slog.LevelInfo, JSON)
	h2 := newStdoutHandlerWithWriter(&buf2, slog.LevelInfo, JSON)
	multi := safeMultiHandler(slog.NewMultiHandler(h1, h2), []slog.Handler{h1, h2})
	logger := slog.New(multi)

	b.ResetTimer()
	b.ReportAllocs()
	for range b.N {
		logger.Info("benchmark", "key", "value", "n", 42)
	}
}

func BenchmarkSafeMultiHandler_4Handlers(b *testing.B) {
	var buf1, buf2, buf3, buf4 bytes.Buffer
	h1 := newStdoutHandlerWithWriter(&buf1, slog.LevelInfo, JSON)
	h2 := newStdoutHandlerWithWriter(&buf2, slog.LevelInfo, JSON)
	h3 := newStdoutHandlerWithWriter(&buf3, slog.LevelInfo, JSON)
	h4 := newStdoutHandlerWithWriter(&buf4, slog.LevelInfo, JSON)
	multi := safeMultiHandler(slog.NewMultiHandler(h1, h2, h3, h4), []slog.Handler{h1, h2, h3, h4})
	logger := slog.New(multi)

	b.ResetTimer()
	b.ReportAllocs()
	for range b.N {
		logger.Info("benchmark", "key", "value", "n", 42)
	}
}

// nopMetrics 是 MetricsHandler 测试用的空实现。
type nopMetrics struct{}

func (nopMetrics) ObserveHandle(_ time.Duration) {}
func (nopMetrics) IncError(_ string)               {}
func (nopMetrics) IncDropped(_ string)             {}
