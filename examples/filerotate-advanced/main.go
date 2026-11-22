// filerotate-advanced: 压缩、时间轮转、文件权限、错误回调
package main

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/iuboy/mebsuta"
	"github.com/iuboy/mebsuta/filerotate"
)

func main() {
	dir, _ := os.MkdirTemp("", "mebsuta-rotate")
	defer func() { _ = os.RemoveAll(dir) }()

	logger, err := mebsuta.New(
		mebsuta.UseFile(filerotate.Config{
			Path:           filepath.Join(dir, "app.log"),
			MaxSizeMB:      1,
			MaxBackups:     5,
			MaxAgeDays:     30,
			Compress:       mebsuta.Ptr(true),
			RotateInterval: 24 * time.Hour,
			FileMode:       0644,
			OnError: func(err error) {
				fmt.Fprintf(os.Stderr, "rotate error: %v\n", err)
			},
		}, mebsuta.FileConfig{
			Level:  slog.LevelDebug,
			Format: "json",
		}),
	)
	if err != nil {
		panic(err)
	}
	slog.SetDefault(logger)
	defer func() { _ = mebsuta.CloseAll(logger.Handler()) }()

	data := strings.Repeat("x", 1024)
	for i := range 1200 {
		slog.Info("bulk write", "batch", i/100, "seq", i, "data", data)
	}
}
