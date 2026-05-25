// multi-output: different log levels per output destination
package main

import (
	"log/slog"
	"os"
	"path/filepath"

	"github.com/iuboy/mebsuta"
	"github.com/iuboy/mebsuta/filerotate"
)

func main() {
	dir, _ := os.MkdirTemp("", "mebsuta-multi")
	defer os.RemoveAll(dir)

	logger, err := mebsuta.New(
		mebsuta.UseStdout(mebsuta.StdoutConfig{
			Level:  slog.LevelWarn,
			Format: "console",
		}),
		mebsuta.UseFile(filerotate.Config{
			Path: filepath.Join(dir, "debug.log"),
		}, mebsuta.FileConfig{
			Level: slog.LevelDebug,
		}),
	)
	if err != nil {
		panic(err)
	}
	slog.SetDefault(logger)
	defer mebsuta.CloseAll(logger.Handler())

	slog.Debug("only in file")
	slog.Info("only in file")
	slog.Warn("both file and stdout")
	slog.Error("both file and stdout")
}
