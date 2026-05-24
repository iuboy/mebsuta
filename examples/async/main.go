// async: async buffered logging
package main

import (
	"fmt"
	"log/slog"

	"github.com/iuboy/mebsuta"
)

func main() {
	logger, err := mebsuta.New(
		mebsuta.UseAsync(mebsuta.AsyncConfig{BufferSize: 256}),
	)
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
