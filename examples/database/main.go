// database: batch-write logs to a PostgreSQL or openGauss database
//
// Note: SQLite is NOT a supported driver for database.Config (Validate only
// accepts "postgres" and "opengauss"); the sqlite GORM driver in this
// repository exists solely as a test dependency for the database package.
// This example targets PostgreSQL — start a throwaway server with:
//
//	docker run --rm -p 5432:5432 -e POSTGRES_PASSWORD=dev postgres:17
//
// and point MEBSUTA_DATABASE_DSN at it (see below).
package main

import (
	"log/slog"
	"os"
	"time"

	"github.com/iuboy/mebsuta"
	"github.com/iuboy/mebsuta/database"
)

func main() {
	// The DSN is read from the environment so credentials stay out of the
	// source tree. Example:
	//	MEBSUTA_DATABASE_DSN='postgres://postgres:dev@localhost:5432/postgres?sslmode=disable'
	dsn := os.Getenv("MEBSUTA_DATABASE_DSN")
	if dsn == "" {
		panic("MEBSUTA_DATABASE_DSN is required, e.g. " +
			"MEBSUTA_DATABASE_DSN='postgres://postgres:dev@localhost:5432/postgres?sslmode=disable' " +
			"(start a server with: docker run --rm -p 5432:5432 -e POSTGRES_PASSWORD=dev postgres:17)")
	}

	cfg := database.Config{
		Driver:        "postgres",
		DSN:           dsn,
		Table:         "logs",
		BatchSize:     50,
		BatchInterval: 2 * time.Second,
	}
	dbH, err := database.NewHandler(cfg)
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
	defer func() { _ = mebsuta.CloseAll(logger.Handler()) }()

	// Config.Sanitize returns a copy with the DSN's credentials redacted —
	// safe to log; printing cfg itself would go through the same redaction
	// via its String method, but the sanitized copy makes the intent explicit.
	slog.Info("logging to both stdout and database", "config", cfg.Sanitize(), "source", "example")
	slog.Error("error also persisted", "code", 500)
}
