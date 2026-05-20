// sampling: time-window log sampling example
package main

import (
	"log/slog"
	"time"

	"github.com/iuboy/mebsuta/go"
	"github.com/iuboy/mebsuta/go/config"
)

func main() {
	stdout := mebsuta.NewStdoutHandler(slog.LevelInfo, mebsuta.JSON)
	sampled := mebsuta.WithSampling(stdout, config.SamplingConfig{
		Enabled:    true,
		Initial:    5,
		Thereafter: 3,
		Window:     time.Second,
	})

	logger, err := mebsuta.New(mebsuta.WithHandler(sampled))
	if err != nil {
		panic(err)
	}
	slog.SetDefault(logger)
	defer mebsuta.CloseAll(logger.Handler())

	for i := range 20 {
		slog.Info("message", "i", i)
	}
}
