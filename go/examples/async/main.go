// async: async buffered logging example
package main

import (
	"fmt"
	"log/slog"

	"github.com/iuboy/mebsuta/go"
)

func main() {
	stdout := mebsuta.NewStdoutHandler(slog.LevelInfo, mebsuta.JSON)
	async := mebsuta.WithAsync(stdout, mebsuta.AsyncConfig{
		BufferSize: 256,
	})

	logger, err := mebsuta.New(mebsuta.WithHandler(async))
	if err != nil {
		panic(err)
	}
	slog.SetDefault(logger)

	for i := range 10 {
		slog.Info("async message", "i", i)
	}

	mebsuta.CloseAll(logger.Handler())
	fmt.Printf("dropped: %d\n", mebsuta.AsyncDropped(logger.Handler()))
}
