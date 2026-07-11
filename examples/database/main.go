// database: batch-write logs to a SQL database
package main

import (
	"log/slog"
	"time"

	"github.com/iuboy/mebsuta"
	"github.com/iuboy/mebsuta/database"
)

func main() {
	dbH, err := database.NewHandler(database.Config{
		Driver:        "sqlite",
		DSN:           "file::memory:",
		Table:         "logs",
		BatchSize:     50,
		BatchInterval: 2 * time.Second,
	})
	if err != nil {
		panic(err)
	}

	logger, err := mebsuta.New(
		mebsuta.UseStdout(mebsuta.StdoutConfig{}),
		mebsuta.WithHandler(dbH),
	)
	if err != nil {
		// H6: close the handler for cleanup, but panic with the actual error —
		// the original `panic(dbH.Close())` discarded err and could even
		// panic(nil) when Close succeeded.
		_ = dbH.Close()
		panic(err)
	}
	slog.SetDefault(logger)
	defer mebsuta.CloseAll(logger.Handler())

	slog.Info("log to both stdout and database", "source", "example")
	slog.Error("error also persisted", "code", 500)
}
