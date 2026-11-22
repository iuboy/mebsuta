// basic: 最小化零配置的 stdout JSON 日志
package main

import (
	"github.com/iuboy/mebsuta"
	"log/slog"
)

func main() {
	logger, err := mebsuta.New()
	if err != nil {
		panic(err)
	}
	slog.SetDefault(logger)
	defer func() { _ = mebsuta.CloseAll(logger.Handler()) }()

	slog.Info("hello", "key", "value")
	slog.Warn("warning message")
	slog.Error("error message", "err", "something failed")
}
