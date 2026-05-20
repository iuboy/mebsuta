// chain: full production handler chain example
// Sampling -> Async -> Multi([File, Stdout])
package main

import (
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/iuboy/mebsuta/go"
	"github.com/iuboy/mebsuta/go/config"
)

func main() {
	dir, err := os.MkdirTemp("", "mebsuta-chain-example")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)

	// File handler with rotation
	fileH, err := mebsuta.NewFileHandler(config.FileConfig{
		Path:       filepath.Join(dir, "app.log"),
		MaxSizeMB:  10,
		MaxBackups: 5,
		Compress:   true,
	}, slog.LevelDebug)
	if err != nil {
		panic(err)
	}

	// Fan-out to both stdout and file
	multi, err := mebsuta.New(
		mebsuta.WithHandler(mebsuta.NewStdoutHandler(slog.LevelInfo, mebsuta.JSON)),
		mebsuta.WithHandler(fileH),
	)
	if err != nil {
		panic(err)
	}

	// Wrap with sampling (first 100 per window, then 1 in 10)
	sampled := mebsuta.WithSampling(multi.Handler(), config.SamplingConfig{
		Enabled:    true,
		Initial:    100,
		Thereafter: 10,
		Window:     time.Second,
	})

	// Wrap with async buffering
	async := mebsuta.WithAsync(sampled, mebsuta.AsyncConfig{
		BufferSize: 256,
	})

	logger := slog.New(async)
	slog.SetDefault(logger)
	defer mebsuta.CloseAll(logger.Handler())

	slog.Info("application started", "pid", os.Getpid())
	slog.Error("simulated error", "code", 500)

	// Audit level: bypasses sampling and async buffer (direct write)
	mebsuta.Audit("compliance event", "action", "login", "user", "admin")
}
