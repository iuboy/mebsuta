// file: file output with rotation
package main

import (
	"log/slog"
	"os"
	"path/filepath"

	"github.com/iuboy/mebsuta"
	"github.com/iuboy/mebsuta/filerotate"
)

func main() {
	dir, err := os.MkdirTemp("", "mebsuta-file")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)

	logger, err := mebsuta.New(
		mebsuta.UseFile(filerotate.Config{
			Path:       filepath.Join(dir, "app.log"),
			MaxSizeMB:  1,
			MaxBackups: 3,
		}, mebsuta.FileConfig{
			Level: slog.LevelInfo,
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
