// init: 用 mebsuta.Init 一行完成 logger 初始化
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
	defer func() { _ = os.RemoveAll(dir) }()

	logger, err := mebsuta.Init(
		mebsuta.UseFile(filerotate.Config{
			Path: filepath.Join(dir, "app.log"),
		}, mebsuta.FileConfig{}),
	)
	if err != nil {
		panic(err)
	}
	defer func() { _ = mebsuta.CloseAll(logger.Handler()) }()

	// Init 会设置全局默认 logger，slog 与便捷函数因此都可用。
	slog.Info("using Init", "auto", "set default")

	slog.Info("convenience function", "level", "info")
	slog.Warn("convenience function", "level", "warn")
	slog.Error("convenience function", "level", "error")
}
