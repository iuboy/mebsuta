// file: file output with rotation example
package main

import (
	"log/slog"
	"os"
	"path/filepath"

	"github.com/iuboy/mebsuta/go"
	"github.com/iuboy/mebsuta/go/config"
)

func main() {
	dir, err := os.MkdirTemp("", "mebsuta-file-example")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)

	cfg, err := config.NewFileConfig(
		filepath.Join(dir, "app.log"),
		config.WithMaxSizeMB(1),
		config.WithMaxBackups(3),
		config.WithCompress(true),
	)
	if err != nil {
		panic(err)
	}

	fileH, err := mebsuta.NewFileHandler(cfg, slog.LevelInfo)
	if err != nil {
		panic(err)
	}

	logger, err := mebsuta.New(
		mebsuta.WithHandler(fileH),
	)
	if err != nil {
		panic(err)
	}
	slog.SetDefault(logger)
	defer mebsuta.CloseAll(logger.Handler())

	for i := range 1000 {
		slog.Info("log entry", "i", i, "msg", "writing to file")
	}
}
