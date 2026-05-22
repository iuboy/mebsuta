package mebsuta_test

import (
	"log/slog"
	"os"
	"time"

	"github.com/iuboy/mebsuta/go"
	"github.com/iuboy/mebsuta/go/config"
)

// ExampleNewStdoutHandler demonstrates basic stdout JSON logging.
func ExampleNewStdoutHandler() {
	handler := mebsuta.NewStdoutHandler(slog.LevelInfo, mebsuta.JSON)
	logger := slog.New(handler)
	logger.Info("hello", "key", "value")
}

// ExampleNewStdoutHandler_text demonstrates text format logging.
func ExampleNewStdoutHandler_text() {
	handler := mebsuta.NewStdoutHandler(slog.LevelInfo, mebsuta.Console)
	logger := slog.New(handler)
	logger.Info("hello", "key", "value")
}

// ExampleWithAsync demonstrates asynchronous logging with buffering.
func ExampleWithAsync() {
	stdout := mebsuta.NewStdoutHandler(slog.LevelInfo, mebsuta.JSON)
	async := mebsuta.WithAsync(stdout, mebsuta.AsyncConfig{
		BufferSize: 100,
	})

	logger := slog.New(async)
	logger.Info("async message")
	defer mebsuta.CloseAll(async)
}

// ExampleWithSampling demonstrates log sampling to reduce volume.
func ExampleWithSampling() {
	stdout := mebsuta.NewStdoutHandler(slog.LevelInfo, mebsuta.JSON)
	cfg, _ := config.NewSamplingConfig(true, 5, 2, time.Second)
	sampled := mebsuta.WithSampling(stdout, cfg)

	logger := slog.New(sampled)
	for i := 0; i < 7; i++ {
		logger.Info("message", "i", i)
	}
	// First 5 pass through, then 1 in 2 is sampled
}

// ExampleAuditEvent demonstrates audit logging for compliance.
func ExampleAuditEvent() {
	handler := mebsuta.NewStdoutHandler(slog.LevelInfo, mebsuta.JSON)
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
	stdout := mebsuta.NewStdoutHandler(slog.LevelInfo, mebsuta.JSON)
	logger, err := mebsuta.New(mebsuta.WithHandler(stdout))
	if err != nil {
		panic(err)
	}

	logger.Info("application started")
}

// ExampleNew_fileHandler demonstrates file-based logging with rotation.
func ExampleNew_fileHandler() {
	tmpDir := os.TempDir()
	cfg, _ := config.NewFileConfig(
		tmpDir+"/app-example.log",
		config.WithMaxSizeMB(1),
		config.WithMaxBackups(3),
		config.WithCompress(true),
	)

	fileH, _ := mebsuta.NewFileHandler(cfg, slog.LevelInfo)
	logger, _ := mebsuta.New(mebsuta.WithHandler(fileH))

	logger.Info("written to file")
	mebsuta.CloseAll(fileH)
}

// ExampleWithMetrics demonstrates metrics collection for logging.
func ExampleWithMetrics() {
	stdout := mebsuta.NewStdoutHandler(slog.LevelInfo, mebsuta.JSON)
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
	stdout := mebsuta.NewStdoutHandler(slog.LevelInfo, mebsuta.JSON)
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
	stdout := mebsuta.NewStdoutHandler(slog.LevelInfo, mebsuta.JSON)
	samplingCfg, _ := config.NewSamplingConfig(true, 100, 10, time.Second)
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
	stdout := mebsuta.NewStdoutHandler(slog.LevelInfo, mebsuta.JSON)
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
	handler := mebsuta.NewStdoutHandler(slog.LevelInfo, mebsuta.JSON)
	logger := slog.New(handler)
	slog.SetDefault(logger)

	mebsuta.AuditEvent(
		mebsuta.EventLogin,
		"user logged in",
		"actor", "user:123",
		"success", true,
	)
}
