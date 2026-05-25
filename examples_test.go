package mebsuta_test

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/iuboy/mebsuta"
	"github.com/iuboy/mebsuta/audit"
	"github.com/iuboy/mebsuta/filerotate"
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

// Example_auditLevel demonstrates audit-level logging.
func Example_auditLevel() {
	handler, _ := mebsuta.NewStdoutHandler(mebsuta.StdoutConfig{Level: slog.LevelInfo})
	logger := slog.New(handler)
	slog.SetDefault(logger)

	// Use audit package: audit.AuditEvent(audit.EventLogin, "user login", ...)
	// This example uses slog.Log directly with the audit level.
	logger.Log(context.Background(), slog.LevelError+4, "user login",
		"event_type", "login",
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
	rotateCfg := filerotate.Config{
		Path:       tmpDir + "/app-example.log",
		MaxSizeMB:  1,
		MaxBackups: 3,
		Compress:   &compress,
	}

	fileH, _ := mebsuta.NewFileHandler(rotateCfg, mebsuta.FileConfig{})
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

// Example_loginAudit demonstrates login audit logging.
func Example_loginAudit() {
	handler, _ := mebsuta.NewStdoutHandler(mebsuta.StdoutConfig{Level: slog.LevelInfo})
	logger := slog.New(handler)
	slog.SetDefault(logger)

	// Use audit package: audit.AuditEvent(audit.EventLogin, ...)
	logger.Log(context.Background(), slog.LevelError+4, "user logged in",
		"event_type", "login",
		"actor", "user:123",
		"success", true,
	)
}

// ExampleUseContextExtractor demonstrates extracting fields from context.Context.
func ExampleUseContextExtractor() {
	type ctxKey string
	const reqID ctxKey = "request_id"

	logger, _ := mebsuta.New(
		mebsuta.UseContextExtractor(func(ctx context.Context) []slog.Attr {
			if id, ok := ctx.Value(reqID).(string); ok {
				return []slog.Attr{slog.String("request_id", id)}
			}
			return nil
		}),
	)
	slog.SetDefault(logger)
	defer mebsuta.CloseAll(logger.Handler())

	ctx := context.WithValue(context.Background(), reqID, "req-789")
	slog.InfoContext(ctx, "request received", "path", "/api")
}

// ExampleWithErrorHandler demonstrates custom error handling for internal handler errors.
func ExampleWithErrorHandler() {
	dir, _ := os.MkdirTemp("", "mebsuta-example-err")
	defer os.RemoveAll(dir)

	logger, err := mebsuta.New(
		mebsuta.UseFile(filerotate.Config{
			Path:       filepath.Join(dir, "app.log"),
			MaxSizeMB:  1,
			MaxBackups: 3,
		}, mebsuta.FileConfig{}),
		mebsuta.WithErrorHandler(func(he mebsuta.HandlerError) {
			fmt.Fprintf(os.Stderr, "component=%s op=%s err=%v\n",
				he.Component, he.Operation, he.Err)
		}),
	)
	if err != nil {
		panic(err)
	}
	slog.SetDefault(logger)
	defer mebsuta.CloseAll(logger.Handler())

	slog.Info("normal log", "status", "ok")
}

// ExampleSilentErrorHandler demonstrates suppressing all internal error reports.
func ExampleSilentErrorHandler() {
	logger, _ := mebsuta.New(
		mebsuta.WithErrorHandler(mebsuta.SilentErrorHandler()),
	)
	defer mebsuta.CloseAll(logger.Handler())

	logger.Info("errors from handlers are silently discarded")
}

// ExampleInit demonstrates the one-line Init shortcut.
func ExampleInit() {
	logger, err := mebsuta.Init()
	if err != nil {
		panic(err)
	}
	defer mebsuta.CloseAll(logger.Handler())

	// Init sets the global default automatically.
	slog.Info("using Init")

	mebsuta.Info("convenience function")
	mebsuta.Warn("convenience function")
}

// Example_auditEventTypes demonstrates audit event type constants.
func Example_auditEventTypes() {
	handler, _ := mebsuta.NewStdoutHandler(mebsuta.StdoutConfig{Level: slog.LevelInfo})
	logger := slog.New(handler)
	slog.SetDefault(logger)

	audit.AuditEvent(audit.EventLogin, "user login",
		"actor", "user:42", "success", true)

	audit.AuditEvent(audit.EventDelete, "record deleted",
		"actor", "admin:1", "resource", "doc:99", "success", true)

	audit.AuditEvent(audit.EventConfigChange, "config updated",
		"actor", "admin:1", "key", "timeout", "new_value", "30s")
}

// ExampleHandlerError demonstrates the HandlerError structure.
func ExampleHandlerError() {
	he := mebsuta.HandlerError{
		Component: "file",
		Operation: "rotate",
		Err:       fmt.Errorf("permission denied"),
		Dropped:   0,
	}
	fmt.Printf("component=%s op=%s err=%v dropped=%d\n",
		he.Component, he.Operation, he.Err, he.Dropped)
	// Output: component=file op=rotate err=permission denied dropped=0
}

// Example_filerotateAdvancedConfig demonstrates advanced file rotation settings.
func Example_filerotateAdvancedConfig() {
	dir, _ := os.MkdirTemp("", "mebsuta-example-rotate")
	defer os.RemoveAll(dir)

	logger, err := mebsuta.New(
		mebsuta.UseFile(filerotate.Config{
			Path:           filepath.Join(dir, "app.log"),
			MaxSizeMB:      1,
			MaxBackups:     5,
			MaxAgeDays:     30,
			Compress:       mebsuta.BoolPtr(true),
			RotateInterval: 24 * time.Hour,
			FileMode:       0644,
		}, mebsuta.FileConfig{
			Level:  slog.LevelDebug,
			Format: "json",
		}),
	)
	if err != nil {
		panic(err)
	}
	defer mebsuta.CloseAll(logger.Handler())

	slog.Debug("debug message written to file")
}
