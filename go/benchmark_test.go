package mebsuta

import (
	"bytes"
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/iuboy/mebsuta/go/config"
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
	h := WithSampling(inner, config.MustNewSamplingConfig(true, b.N+100, 1, 10*time.Second))
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
	h := WithSampling(inner, config.MustNewSamplingConfig(true, 1, 1000000, 10*time.Second))
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
	multi := safeMultiHandler([]slog.Handler{h1, h2}, nil)
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
	multi := safeMultiHandler([]slog.Handler{h1, h2, h3, h4}, nil)
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
func (nopMetrics) IncError(_ string)             {}
func (nopMetrics) IncDropped(_ string)           {}

// Parallel benchmarks quantify goroutine contention overhead.

func BenchmarkStdoutHandler_JSON_Parallel(b *testing.B) {
	var buf bytes.Buffer
	h := newStdoutHandlerWithWriter(&buf, slog.LevelInfo, JSON)
	logger := slog.New(h)

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			logger.Info("benchmark", "key", "value", "n", 42)
		}
	})
}

func BenchmarkSafeMultiHandler_2Handlers_Parallel(b *testing.B) {
	var buf1, buf2 bytes.Buffer
	h1 := newStdoutHandlerWithWriter(&buf1, slog.LevelInfo, JSON)
	h2 := newStdoutHandlerWithWriter(&buf2, slog.LevelInfo, JSON)
	multi := safeMultiHandler([]slog.Handler{h1, h2}, nil)
	logger := slog.New(multi)

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			logger.Info("benchmark", "key", "value", "n", 42)
		}
	})
}

// Handler chain: Sampling → Async → Stdout (common production config).

func BenchmarkHandlerChain_SamplingAsyncStdout(b *testing.B) {
	var buf bytes.Buffer
	stdout := newStdoutHandlerWithWriter(&buf, slog.LevelInfo, JSON)
	async := WithAsync(stdout, AsyncConfig{BufferSize: 4096})
	sampled := WithSampling(async, config.MustNewSamplingConfig(true, b.N+100, 1, 10*time.Second))
	logger := slog.New(sampled)

	b.ResetTimer()
	b.ReportAllocs()
	for range b.N {
		logger.Info("benchmark", "key", "value", "n", 42)
	}

	if closer, ok := sampled.(interface{ Close() error }); ok {
		closer.Close()
	}
}

// AsyncHandler with larger buffer to avoid drops under benchmark load.

func BenchmarkAsyncHandler_LargeBuffer(b *testing.B) {
	var buf bytes.Buffer
	inner := newStdoutHandlerWithWriter(&buf, slog.LevelInfo, JSON)
	h := WithAsync(inner, AsyncConfig{BufferSize: 65536})
	logger := slog.New(h)

	b.ResetTimer()
	b.ReportAllocs()
	for range b.N {
		logger.Info("benchmark", "key", "value", "n", 42)
	}

	if closer, ok := h.(interface{ Close() error }); ok {
		closer.Close()
	}
}
