// basic: minimal zero-config stdout JSON logging
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
	defer mebsuta.CloseAll(logger.Handler())

	slog.Info("hello", "key", "value")
	slog.Warn("warning message")
	slog.Error("error message", "err", "something failed")
}
