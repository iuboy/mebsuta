// sampling: time-window log sampling
package main

import (
	"log/slog"
	"time"

	"github.com/iuboy/mebsuta"
)

func main() {
	logger, err := mebsuta.New(
		mebsuta.UseSampling(mebsuta.SamplingConfig{
			Enabled:    true,
			Initial:    100,
			Thereafter: 10,
			Window:     time.Second,
		}),
	)
	if err != nil {
		panic(err)
	}
	slog.SetDefault(logger)
	defer mebsuta.CloseAll(logger.Handler())

	for i := range 20 {
		slog.Info("message", "i", i)
	}
}
