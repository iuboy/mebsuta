package mebsuta

import (
	"bytes"
	"context"
	"log/slog"
	"testing"
	"time"
)

func BenchmarkStdoutHandler_JSON(b *testing.B) {
	var buf bytes.Buffer
	h, err := newStdoutHandlerWithWriter(&buf, StdoutConfig{Level: slog.LevelInfo})
	if err != nil {
		b.Fatal(err)
	}
	logger := slog.New(h)

	b.ResetTimer()
	b.ReportAllocs()
	for range b.N {
		logger.Info("benchmark", "key", "value", "n", 42)
	}
}

func BenchmarkStdoutHandler_Console(b *testing.B) {
	var buf bytes.Buffer
	h, err := newStdoutHandlerWithWriter(&buf, StdoutConfig{Level: slog.LevelInfo, Format: "console"})
	if err != nil {
		b.Fatal(err)
	}
	logger := slog.New(h)

	b.ResetTimer()
	b.ReportAllocs()
	for range b.N {
		logger.Info("benchmark", "key", "value", "n", 42)
	}
}

func BenchmarkStdoutHandler_WithAttrs(b *testing.B) {
	var buf bytes.Buffer
	h, err := newStdoutHandlerWithWriter(&buf, StdoutConfig{Level: slog.LevelInfo})
	if err != nil {
		b.Fatal(err)
	}
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
	inner, err := newStdoutHandlerWithWriter(&buf, StdoutConfig{Level: slog.LevelInfo})
	if err != nil {
		b.Fatal(err)
	}
	h := WithSampling(inner, SamplingConfig{Enabled: true, Initial: b.N + 100, Thereafter: 1, Window: 10 * time.Second})
	logger := slog.New(h)

	b.ResetTimer()
	b.ReportAllocs()
	for range b.N {
		logger.Info("benchmark", "key", "value")
	}
}

func BenchmarkSamplingHandler_Drop(b *testing.B) {
	var buf bytes.Buffer
	inner, err := newStdoutHandlerWithWriter(&buf, StdoutConfig{Level: slog.LevelInfo})
	if err != nil {
		b.Fatal(err)
	}
	h := WithSampling(inner, SamplingConfig{Enabled: true, Initial: 1, Thereafter: 1000000, Window: 10 * time.Second})
	logger := slog.New(h)

	b.ResetTimer()
	b.ReportAllocs()
	for range b.N {
		logger.Info("benchmark", "key", "value")
	}
}

func BenchmarkAsyncHandler(b *testing.B) {
	var buf bytes.Buffer
	inner, err := newStdoutHandlerWithWriter(&buf, StdoutConfig{Level: slog.LevelInfo})
	if err != nil {
		b.Fatal(err)
	}
	h := WithAsync(inner, AsyncConfig{BufferSize: 1024})
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

func BenchmarkMetricsHandler(b *testing.B) {
	var buf bytes.Buffer
	inner, err := newStdoutHandlerWithWriter(&buf, StdoutConfig{Level: slog.LevelInfo})
	if err != nil {
		b.Fatal(err)
	}
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
	inner, err := newStdoutHandlerWithWriter(&buf, StdoutConfig{Level: slog.LevelInfo})
	if err != nil {
		b.Fatal(err)
	}
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
	h1, err := newStdoutHandlerWithWriter(&buf1, StdoutConfig{Level: slog.LevelInfo})
	if err != nil {
		b.Fatal(err)
	}
	h2, err := newStdoutHandlerWithWriter(&buf2, StdoutConfig{Level: slog.LevelInfo})
	if err != nil {
		b.Fatal(err)
	}
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
	h1, err := newStdoutHandlerWithWriter(&buf1, StdoutConfig{Level: slog.LevelInfo})
	if err != nil {
		b.Fatal(err)
	}
	h2, err := newStdoutHandlerWithWriter(&buf2, StdoutConfig{Level: slog.LevelInfo})
	if err != nil {
		b.Fatal(err)
	}
	h3, err := newStdoutHandlerWithWriter(&buf3, StdoutConfig{Level: slog.LevelInfo})
	if err != nil {
		b.Fatal(err)
	}
	h4, err := newStdoutHandlerWithWriter(&buf4, StdoutConfig{Level: slog.LevelInfo})
	if err != nil {
		b.Fatal(err)
	}
	multi := safeMultiHandler([]slog.Handler{h1, h2, h3, h4}, nil)
	logger := slog.New(multi)

	b.ResetTimer()
	b.ReportAllocs()
	for range b.N {
		logger.Info("benchmark", "key", "value", "n", 42)
	}
}

type nopMetrics struct{}

func (nopMetrics) ObserveHandle(_ time.Duration) {}
func (nopMetrics) IncError(_ string)             {}
func (nopMetrics) IncDropped(_ string)           {}

func BenchmarkStdoutHandler_JSON_Parallel(b *testing.B) {
	var buf bytes.Buffer
	h, err := newStdoutHandlerWithWriter(&buf, StdoutConfig{Level: slog.LevelInfo})
	if err != nil {
		b.Fatal(err)
	}
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
	h1, err := newStdoutHandlerWithWriter(&buf1, StdoutConfig{Level: slog.LevelInfo})
	if err != nil {
		b.Fatal(err)
	}
	h2, err := newStdoutHandlerWithWriter(&buf2, StdoutConfig{Level: slog.LevelInfo})
	if err != nil {
		b.Fatal(err)
	}
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

func BenchmarkHandlerChain_SamplingAsyncStdout(b *testing.B) {
	var buf bytes.Buffer
	stdout, err := newStdoutHandlerWithWriter(&buf, StdoutConfig{Level: slog.LevelInfo})
	if err != nil {
		b.Fatal(err)
	}
	async := WithAsync(stdout, AsyncConfig{BufferSize: 4096})
	sampled := WithSampling(async, SamplingConfig{Enabled: true, Initial: b.N + 100, Thereafter: 1, Window: 10 * time.Second})
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

func BenchmarkAsyncHandler_LargeBuffer(b *testing.B) {
	var buf bytes.Buffer
	inner, err := newStdoutHandlerWithWriter(&buf, StdoutConfig{Level: slog.LevelInfo})
	if err != nil {
		b.Fatal(err)
	}
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
