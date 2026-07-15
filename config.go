package mebsuta

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

func (e *ConfigError) Error() string {
	return e.Field + ": " + e.Msg
}

// --- FileConfig ---

// Default configuration values.
const (
	DefaultAsyncBufferSize = 256

	DefaultSamplingInitial    = 100
	DefaultSamplingThereafter = 10
)

// FileConfig holds mebsuta-specific configuration for file log output (format and level).
// Rotation configuration is handled by filerotate.Config.
type FileConfig struct {
	Level    slog.Leveler   // Log level filter. Defaults to slog.LevelInfo.
	Format   string         // "json" or "console". Defaults to "json".
	Timezone *time.Location // 日志时间展示时区，nil 用 UTC。
}

// Validate returns a normalized copy with defaults applied.
func (c FileConfig) Validate() (FileConfig, error) {
	if c.Level == nil {
		c.Level = slog.LevelInfo
	}
	if err := validateFormat(c.Format); err != nil {
		return c, err
	}
	if c.Format == "" {
		c.Format = "json"
	}
	return c, nil
}

// --- StdoutConfig ---

// StdoutConfig holds configuration for stdout log output.
type StdoutConfig struct {
	Level    slog.Leveler  // Log level filter. Defaults to slog.LevelInfo.
	Format   string        // "json" or "console". Defaults to "json".
	Timezone *time.Location // 日志时间展示时区，nil 用 UTC。
}

// Validate checks required fields and returns a normalized copy with defaults applied.
func (c StdoutConfig) Validate() (StdoutConfig, error) {
	if c.Level == nil {
		c.Level = slog.LevelInfo
	}
	if err := validateFormat(c.Format); err != nil {
		return c, err
	}
	if c.Format == "" {
		c.Format = "json"
	}
	return c, nil
}

func (c StdoutConfig) level() slog.Level {
	if lv, ok := c.Level.(slog.Level); ok {
		return lv
	}
	return c.Level.Level()
}

// validateFormat rejects unsupported Format values (e.g. "text", "yaml") that
// would otherwise silently fall through to JSON in newInnerHandler's default
// case — a silent misconfiguration where the user requests console but gets JSON.
// An empty format is valid and defaulted to "json" by the caller.
func validateFormat(format string) error {
	switch format {
	case "", "json", "console":
		return nil
	default:
		return &ConfigError{Field: "Format", Msg: fmt.Sprintf("unsupported format %q (must be \"json\" or \"console\")", format)}
	}
}

// --- AsyncConfig ---

// AsyncConfig holds configuration for async log processing.
type AsyncConfig struct {
	BufferSize int // Channel buffer size. 0 → 256.
}

// Validate checks required fields and returns a normalized copy with defaults applied.
func (c AsyncConfig) Validate() (AsyncConfig, error) {
	if c.BufferSize <= 0 {
		c.BufferSize = DefaultAsyncBufferSize
	}
	return c, nil
}

// --- SamplingConfig ---

// SamplingConfig holds configuration for log sampling.
type SamplingConfig struct {
	Enabled    bool          // Enable sampling.
	Initial    int           // First N records per window to always log. 0 → 100.
	Thereafter int           // Log 1-in-N after initial. 0 → 10.
	Window     time.Duration // Sampling window duration. 0 → 1s.
}

// Validate checks required fields and returns a normalized copy with defaults applied.
func (c SamplingConfig) Validate() (SamplingConfig, error) {
	if !c.Enabled {
		return c, nil
	}
	if c.Initial <= 0 {
		c.Initial = DefaultSamplingInitial
	}
	if c.Thereafter <= 0 {
		c.Thereafter = DefaultSamplingThereafter
	}
	if c.Window <= 0 {
		c.Window = time.Second
	}
	return c, nil
}
