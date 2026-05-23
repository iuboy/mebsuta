package mebsuta_test

import (
	"log/slog"
	"os"
	"time"

	"github.com/iuboy/mebsuta"
)

// ExampleNewStdoutHandler demonstrates basic stdout JSON logging.
func ExampleNewStdoutHandler() {
	handler, _ := mebsuta.NewStdoutHandler(mebsuta.StdoutConfig{Level: slog.LevelInfo})
	logger := slog.New(handler)
	logger.Info("hello", "key", "value")
}

// ExampleNewStdoutHandler_text demonstrates text format logging.
func ExampleNewStdoutHandler_text() {
	handler, _ := mebsuta.NewStdoutHandler(mebsuta.StdoutConfig{Level: slog.LevelInfo, Format: "console"})
	logger := slog.New(handler)
	logger.Info("hello", "key", "value")
}

// ExampleWithAsync demonstrates asynchronous logging with buffering.
func ExampleWithAsync() {
	stdout, _ := mebsuta.NewStdoutHandler(mebsuta.StdoutConfig{Level: slog.LevelInfo})
	async := mebsuta.WithAsync(stdout, mebsuta.AsyncConfig{
		BufferSize: 100,
	})

	logger := slog.New(async)
	logger.Info("async message")
	defer mebsuta.CloseAll(async)
}

// ExampleWithSampling demonstrates log sampling to reduce volume.
func ExampleWithSampling() {
	stdout, _ := mebsuta.NewStdoutHandler(mebsuta.StdoutConfig{Level: slog.LevelInfo})
	cfg := mebsuta.SamplingConfig{Enabled: true, Initial: 5, Thereafter: 2, Window: time.Second}
	sampled := mebsuta.WithSampling(stdout, cfg)

	logger := slog.New(sampled)
	for i := 0; i < 7; i++ {
		logger.Info("message", "i", i)
	}
	// First 5 pass through, then 1 in 2 is sampled
}

// ExampleAuditEvent demonstrates audit logging for compliance.
func ExampleAuditEvent() {
	handler, _ := mebsuta.NewStdoutHandler(mebsuta.StdoutConfig{Level: slog.LevelInfo})
	logger := slog.New(handler)
	slog.SetDefault(logger)

	mebsuta.AuditEvent(
		mebsuta.EventLogin,
		"user login",
		"actor", "user:42",
		"success", true,
		"ip", "127.0.0.1",
	)
}

// ExampleNew demonstrates creating a logger with a handler.
func ExampleNew() {
	stdout, _ := mebsuta.NewStdoutHandler(mebsuta.StdoutConfig{Level: slog.LevelInfo})
	logger, err := mebsuta.New(mebsuta.WithHandler(stdout))
	if err != nil {
		panic(err)
	}

	logger.Info("application started")
}

// ExampleNew_fileHandler demonstrates file-based logging with rotation.
func ExampleNew_fileHandler() {
	tmpDir := os.TempDir()
	compress := true
	cfg := mebsuta.FileConfig{
		Path:       tmpDir + "/app-example.log",
		MaxSizeMB:  1,
		MaxBackups: 3,
		Compress:   &compress,
	}

	fileH, _ := mebsuta.NewFileHandler(cfg)
	logger, _ := mebsuta.New(mebsuta.WithHandler(fileH))

	logger.Info("written to file")
	mebsuta.CloseAll(fileH)
}

// ExampleWithMetrics demonstrates metrics collection for logging.
func ExampleWithMetrics() {
	stdout, _ := mebsuta.NewStdoutHandler(mebsuta.StdoutConfig{Level: slog.LevelInfo})
	m := &testMetrics{}

	withMetrics := mebsuta.WithMetrics(stdout, m, "myapp")
	logger := slog.New(withMetrics)

	logger.Info("message")
}

// testMetrics is a minimal implementation for the example.
type testMetrics struct{}

func (m *testMetrics) ObserveHandle(duration time.Duration) {}
func (m *testMetrics) IncError(handlerName string)          {}
func (m *testMetrics) IncDropped(handlerName string)        {}

// ExampleCloseAll demonstrates proper handler cleanup.
func ExampleCloseAll() {
	stdout, _ := mebsuta.NewStdoutHandler(mebsuta.StdoutConfig{Level: slog.LevelInfo})
	async := mebsuta.WithAsync(stdout, mebsuta.AsyncConfig{
		BufferSize: 100,
	})

	logger := slog.New(async)
	logger.Info("before close")

	// CloseAll flushes buffers and releases resources
	mebsuta.CloseAll(async)
	logger.Info("after close") // safely ignored
}

// Example_withHandlerChain demonstrates a complete production handler chain.
func Example_withHandlerChain() {
	// Build chain: Sampling → Async → Stdout
	stdout, _ := mebsuta.NewStdoutHandler(mebsuta.StdoutConfig{Level: slog.LevelInfo})
	samplingCfg := mebsuta.SamplingConfig{Enabled: true, Initial: 100, Thereafter: 10, Window: time.Second}
	sampled := mebsuta.WithSampling(stdout, samplingCfg)
	async := mebsuta.WithAsync(sampled, mebsuta.AsyncConfig{
		BufferSize: 1000,
	})

	logger := slog.New(async)
	defer mebsuta.CloseAll(async)

	logger.Info("production message")
}

// ExampleAsyncDropped demonstrates checking for dropped log records.
func ExampleAsyncDropped() {
	stdout, _ := mebsuta.NewStdoutHandler(mebsuta.StdoutConfig{Level: slog.LevelInfo})
	async := mebsuta.WithAsync(stdout, mebsuta.AsyncConfig{
		BufferSize: 5, // small buffer
	})

	logger := slog.New(async)
	for i := 0; i < 100; i++ {
		logger.Info("message", "i", i)
	}

	dropped := mebsuta.AsyncDropped(async)
	_ = dropped // number of dropped records
	mebsuta.CloseAll(async)
}

// ExampleEventLogin is a predefined event type for login actions.
func ExampleEventLogin() {
	handler, _ := mebsuta.NewStdoutHandler(mebsuta.StdoutConfig{Level: slog.LevelInfo})
	logger := slog.New(handler)
	slog.SetDefault(logger)

	mebsuta.AuditEvent(
		mebsuta.EventLogin,
		"user logged in",
		"actor", "user:123",
		"success", true,
	)
}
