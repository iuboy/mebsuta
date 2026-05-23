package syslog

import (
	"fmt"
	"log/slog"
	"time"
)

// ConfigError represents a configuration validation error.
type ConfigError struct {
	Field string
	Msg   string
}

func (e *ConfigError) Error() string { return e.Field + ": " + e.Msg }

// Config holds configuration for syslog output.
type Config struct {
	Network       string        // "tcp", "udp", "unix". Defaults to "tcp".
	Address       string        // Required: syslog server address (e.g., "localhost:514").
	Level         slog.Leveler  // Log level filter. Defaults to slog.LevelInfo.
	Tag           string        // Syslog tag. Defaults to "mebsuta".
	Facility      int           // Syslog facility (0-23). Defaults to 1 (user).
	Reconnect     *bool         // Auto-reconnect on disconnect. nil → true.
	RetryDelay    time.Duration // Delay between reconnect attempts. 0 → 500ms.
	TLSSkipVerify bool          // Skip TLS certificate verification.
	StaticHost    string        // Override system hostname.
	Secure        bool          // Enable TLS.
	RFC5424       bool          // Use RFC5424 format instead of RFC3164.
	BufferSize    int           // Internal message buffer size. 0 → 1000.
	TimeZone      string        // Timezone for timestamps. Defaults to "UTC".
	JSONInMessage bool          // Include JSON structure in message field.
}

func boolPtr(b bool) *bool { return &b }

// Validate checks required fields and returns a normalized copy with defaults applied.
func (c Config) Validate() (Config, error) {
	if c.Network == "" {
		c.Network = "tcp"
	}
	if c.Address == "" {
		return Config{}, &ConfigError{Field: "Address", Msg: "syslog address is required"}
	}
	if c.Level == nil {
		c.Level = slog.LevelInfo
	}
	if c.Tag == "" {
		c.Tag = "mebsuta"
	}
	if len(c.Tag) > 48 {
		return Config{}, &ConfigError{Field: "Tag", Msg: fmt.Sprintf("syslog tag too long: %d chars (max 48)", len(c.Tag))}
	}
	for _, r := range c.Tag {
		if r < 33 || r > 126 {
			return Config{}, &ConfigError{Field: "Tag", Msg: fmt.Sprintf("syslog tag contains non-printable character: %q", r)}
		}
	}
	if c.Facility < 0 || c.Facility > 23 {
		return Config{}, &ConfigError{Field: "Facility", Msg: fmt.Sprintf("invalid syslog facility: %d, must be 0-23", c.Facility)}
	}
	if c.Reconnect == nil {
		c.Reconnect = boolPtr(true)
	}
	if c.RetryDelay <= 0 {
		c.RetryDelay = 500 * time.Millisecond
	}
	if c.BufferSize <= 0 {
		c.BufferSize = 1000
	}
	if c.TimeZone != "" {
		if _, err := time.LoadLocation(c.TimeZone); err != nil {
			return Config{}, &ConfigError{Field: "TimeZone", Msg: fmt.Sprintf("invalid timezone: %s", c.TimeZone)}
		}
	}
	return c, nil
}
