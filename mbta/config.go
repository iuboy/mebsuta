package mbta

import (
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/iuboy/mebsuta"
)

// Retry/delay caps: every failed batch costs MaxRetries × (send deadline +
// RetryDelay) during both runtime and Close's drain, so unbounded values make
// shutdown unbounded. Mirrors syslog.MaxRetryDelay.
const (
	// MaxRetryDelay caps Config.RetryDelay.
	MaxRetryDelay = 30 * time.Second
	// MaxMaxRetries caps Config.MaxRetries.
	MaxMaxRetries = 10
)

// Config holds configuration for the MBTA log shipping handler.
type Config struct {
	// Connection settings
	Server   string // Required: forwarder address (e.g., "localhost:7400")
	AgentID  string // Required: agent identifier
	Hostname string // Optional: defaults to system hostname
	Token    string // Optional: authentication token

	// TLS settings
	CAFile             string
	CertFile           string
	KeyFile            string
	ServerName         string
	InsecureSkipVerify bool

	// Behavior
	Level        slog.Leveler  // Log level filter. Defaults to slog.LevelInfo.
	BufferSize   int           // Internal batch buffer. 0 -> 1000.
	FlushPeriod  time.Duration // How often to flush buffered records. 0 -> 5s.
	BatchSize    int           // Maximum records per batch. 0 -> 100.
	MaxRetries   int           // Maximum send retries. 0 -> 3.
	RetryDelay   time.Duration // Base retry delay. 0 -> 1s.
	ErrorTimeout time.Duration // Max wait when buffer is full for Error+ logs. 0 -> 1s.
	CloseTimeout time.Duration // Max wait for the client's graceful close/drain. 0 -> 5s.
	// Reconnect re-dials the forwarder between send retries when the session
	// is no longer READY. nil -> true. Without it (or when reconnection keeps
	// failing) batches are dropped after MaxRetries attempts.
	Reconnect *bool // Auto-reconnect on disconnect. nil -> true.

	// Metadata
	Tag    string // Tag for SignalBatch. Defaults to "mebsuta".
	Source string // Source identifier. Defaults to hostname.
}

// Validate checks required fields and returns a normalized copy with defaults.
func (c Config) Validate() (Config, error) {
	if c.Server == "" {
		return Config{}, &mebsuta.ConfigError{Field: "Server", Msg: "mbta server address is required"}
	}
	if c.AgentID == "" {
		return Config{}, &mebsuta.ConfigError{Field: "AgentID", Msg: "mbta agent ID is required"}
	}
	if c.Level == nil {
		c.Level = slog.LevelInfo
	}
	if c.BufferSize <= 0 {
		c.BufferSize = defaultBufferSize
	}
	if c.FlushPeriod <= 0 {
		c.FlushPeriod = defaultFlushPeriod
	}
	if c.BatchSize <= 0 {
		c.BatchSize = defaultBatchSize
	}
	if c.MaxRetries <= 0 {
		c.MaxRetries = defaultMaxRetries
	}
	if c.RetryDelay <= 0 {
		c.RetryDelay = defaultRetryDelay
	}
	// Caps keep Close's drain bounded: the final flush costs up to
	// MaxRetries × (SendBatch deadline + RetryDelay), so unbounded values
	// would make "bounded close" a lie.
	if c.RetryDelay > MaxRetryDelay {
		c.RetryDelay = MaxRetryDelay
	}
	if c.MaxRetries > MaxMaxRetries {
		c.MaxRetries = MaxMaxRetries
	}
	if c.ErrorTimeout <= 0 {
		c.ErrorTimeout = time.Second
	}
	if c.CloseTimeout <= 0 {
		c.CloseTimeout = defaultCloseTimeout
	}
	if c.Tag == "" {
		c.Tag = "mebsuta"
	}
	if c.Source == "" {
		hostname, err := resolveHostname(c.Hostname)
		if err != nil {
			c.Source = "localhost"
		} else {
			c.Source = hostname
		}
	}
	if c.Reconnect == nil {
		c.Reconnect = mebsuta.BoolPtr(true)
	}
	return c, nil
}

func resolveHostname(static string) (string, error) {
	if static != "" {
		return static, nil
	}
	hostname, err := os.Hostname()
	if err != nil {
		return "", fmt.Errorf("get hostname: %w", err)
	}
	return hostname, nil
}
