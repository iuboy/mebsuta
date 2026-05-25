package database

import (
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"time"

	"github.com/iuboy/mebsuta"
)

var tableNameRe = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

// Config holds configuration for database log output.
type Config struct {
	Driver          string        // Required: "mysql" or "postgres".
	DSN             string        // Required: database connection string.
	Table           string        // Required: log table name.
	Level           slog.Leveler  // Log level filter. Defaults to slog.LevelInfo.
	BatchSize       int           // Records per batch. 0 → 100.
	BatchInterval   time.Duration // Flush interval. 0 → 5s.
	MaxConnLifetime time.Duration // Max connection lifetime. 0 = no limit.
	MaxOpenConns    int           // Max open connections. 0 → 10.
	MaxIdleConns    int           // Max idle connections. 0 → 5.
	RetryDelay      time.Duration // Delay between retries. 0 → 500ms.
	warnNoTLS       bool          // internal: set by Validate when DSN lacks TLS params.
}

// Validate checks required fields and returns a normalized copy with defaults applied.
func (c Config) Validate() (Config, error) {
	if c.Driver == "" {
		return Config{}, &mebsuta.ConfigError{Field: "Driver", Msg: "driver is required"}
	}
	if c.Driver != "mysql" && c.Driver != "postgres" {
		return Config{}, &mebsuta.ConfigError{Field: "Driver", Msg: "unsupported driver: " + c.Driver + " (supported: mysql, postgres)"}
	}
	if c.DSN == "" {
		return Config{}, &mebsuta.ConfigError{Field: "DSN", Msg: "data source name is required"}
	}
	if c.Table == "" {
		return Config{}, &mebsuta.ConfigError{Field: "Table", Msg: "table name is required"}
	}
	if !tableNameRe.MatchString(c.Table) {
		return Config{}, &mebsuta.ConfigError{Field: "Table", Msg: "table name must match [a-zA-Z_][a-zA-Z0-9_]*"}
	}
	if len(c.Table) > 64 {
		return Config{}, &mebsuta.ConfigError{Field: "Table", Msg: fmt.Sprintf("table name too long (max 64, got %d)", len(c.Table))}
	}
	if c.Level == nil {
		c.Level = slog.LevelInfo
	}
	if c.BatchSize <= 0 {
		c.BatchSize = 100
	}
	if c.BatchInterval <= 0 {
		c.BatchInterval = 5 * time.Second
	}
	if c.MaxOpenConns <= 0 {
		c.MaxOpenConns = 10
	}
	if c.MaxIdleConns <= 0 {
		c.MaxIdleConns = 5
	}
	if c.RetryDelay <= 0 {
		c.RetryDelay = 500 * time.Millisecond
	}

	c.warnNoTLS = !dsnHasTLS(c.Driver, c.DSN)

	return c, nil
}

// dsnHasTLS checks whether the DSN contains TLS/SSL connection parameters.
func dsnHasTLS(driver, dsn string) bool {
	switch driver {
	case "mysql":
		dsnLower := strings.ToLower(dsn)
		return strings.Contains(dsnLower, "tls=true") || strings.Contains(dsnLower, "tls=skip-verify") || strings.Contains(dsnLower, "sslmode=")
	case "postgres":
		dsnLower := strings.ToLower(dsn)
		return strings.Contains(dsnLower, "sslmode=require") || strings.Contains(dsnLower, "sslmode=verify-ca") || strings.Contains(dsnLower, "sslmode=verify-full")
	}
	return false
}
