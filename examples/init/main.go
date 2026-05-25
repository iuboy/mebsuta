// init: one-line logger initialization with mebsuta.Init
package main

import (
	"log/slog"
	"os"
	"path/filepath"

	"github.com/iuboy/mebsuta"
	"github.com/iuboy/mebsuta/filerotate"
)

func main() {
	dir, _ := os.MkdirTemp("", "mebsuta-init")
	defer os.RemoveAll(dir)

	logger, err := mebsuta.Init(
		mebsuta.UseFile(filerotate.Config{
			Path: filepath.Join(dir, "app.log"),
		}, mebsuta.FileConfig{}),
	)
	if err != nil {
		panic(err)
	}
	defer mebsuta.CloseAll(logger.Handler())

	// Init sets the global default, so slog and convenience functions work.
	slog.Info("using Init", "auto", "set default")

	mebsuta.Info("convenience function", "level", "info")
	mebsuta.Warn("convenience function", "level", "warn")
	mebsuta.Error("convenience function", "level", "error")
}
