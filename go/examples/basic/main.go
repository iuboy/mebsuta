// basic: minimal stdout JSON logging example
package main

import (
	"log/slog"

	"github.com/iuboy/mebsuta/go"
)

func main() {
	logger, err := mebsuta.New(
		mebsuta.WithHandler(mebsuta.NewStdoutHandler(slog.LevelInfo, mebsuta.JSON)),
	)
	if err != nil {
		panic(err)
	}
	slog.SetDefault(logger)
	defer mebsuta.CloseAll(logger.Handler())

	slog.Info("hello", "key", "value")
	slog.Warn("warning message")
	slog.Error("error message", "err", "something failed")
}
