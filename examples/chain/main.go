// chain: full production handler chain — file + stdout with sampling and async
package main

import (
	"log/slog"
	"os"
	"path/filepath"

	"github.com/iuboy/mebsuta"
)

func main() {
	dir, err := os.MkdirTemp("", "mebsuta-chain")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)

	logger, err := mebsuta.New(
		mebsuta.WithHandler(mebsuta.NewStdoutHandler(mebsuta.StdoutConfig{})),
		mebsuta.UseFile(mebsuta.FileConfig{
			Path: filepath.Join(dir, "app.log"), Level: slog.LevelDebug,
		}),
		mebsuta.UseSampling(mebsuta.SamplingConfig{
			Enabled: true, Initial: 100, Thereafter: 10, Window: 1e9,
		}),
		mebsuta.UseAsync(mebsuta.AsyncConfig{BufferSize: 256}),
	)
	if err != nil {
		panic(err)
	}
	slog.SetDefault(logger)
	defer mebsuta.CloseAll(logger.Handler())

	slog.Info("application started", "pid", os.Getpid())
	slog.Error("simulated error", "code", 500)
	mebsuta.AuditEvent(mebsuta.EventLogin, "compliance event", "actor", "admin", "success", true)
}
