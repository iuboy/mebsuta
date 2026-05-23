// file: file output with rotation
package main

import (
	"log/slog"
	"os"
	"path/filepath"

	"github.com/iuboy/mebsuta"
)

func main() {
	dir, err := os.MkdirTemp("", "mebsuta-file")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)

	logger, err := mebsuta.New(
		mebsuta.UseFile(mebsuta.FileConfig{
			Path:       filepath.Join(dir, "app.log"),
			Level:      slog.LevelInfo,
			MaxSizeMB:  1,
			MaxBackups: 3,
		}),
	)
	if err != nil {
		panic(err)
	}
	slog.SetDefault(logger)
	defer mebsuta.CloseAll(logger.Handler())

	for i := range 1000 {
		slog.Info("log entry", "i", i)
	}
}
