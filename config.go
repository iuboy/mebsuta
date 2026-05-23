package mebsuta

import (
	"fmt"
	"log/slog"
	"path/filepath"
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

// FileConfig holds configuration for file-based log output.
// Zero values apply sensible defaults when passed to NewFileHandler.
type FileConfig struct {
	Path           string        // Required: absolute path to log file.
	Level          slog.Leveler  // Log level filter. Defaults to slog.LevelInfo.
	Format         string        // "json" or "console". Defaults to "json".
	MaxSizeMB      int           // Max file size before rotation. 0 → 100.
	MaxBackups     int           // Max number of rotated backups. 0 → 5.
	MaxAgeDays     int           // Max age of rotated backups. 0 → 30.
	Compress       *bool         // Gzip compress rotated backups. nil → true.
	RotateInterval time.Duration // Time-based rotation interval. 0 = size-only.
}

// BoolPtr returns a pointer to the given bool value.
func BoolPtr(b bool) *bool { return &b }

// Validate checks required fields and returns a normalized copy with defaults applied.
// The original config is not modified.
func (c FileConfig) Validate() (FileConfig, error) {
	if c.Path == "" {
		return FileConfig{}, &ConfigError{Field: "Path", Msg: "file path is required"}
	}
	if !filepath.IsAbs(c.Path) {
		return FileConfig{}, &ConfigError{Field: "Path", Msg: fmt.Sprintf("file path must be absolute: %s", c.Path)}
	}
	if c.Level == nil {
		c.Level = slog.LevelInfo
	}
	if c.Format == "" {
		c.Format = "json"
	}
	if c.MaxSizeMB <= 0 {
		c.MaxSizeMB = 100
	}
	if c.MaxBackups <= 0 {
		c.MaxBackups = 5
	}
	if c.MaxAgeDays <= 0 {
		c.MaxAgeDays = 30
	}
	if c.Compress == nil {
		c.Compress = BoolPtr(true)
	}
	return c, nil
}

func (c *FileConfig) compress() bool {
	return c.Compress != nil && *c.Compress
}

// --- StdoutConfig ---

// StdoutConfig holds configuration for stdout log output.
type StdoutConfig struct {
	Level  slog.Leveler // Log level filter. Defaults to slog.LevelInfo.
	Format string       // "json" or "console". Defaults to "json".
}

// Validate checks required fields and returns a normalized copy with defaults applied.
func (c StdoutConfig) Validate() (StdoutConfig, error) {
	if c.Level == nil {
		c.Level = slog.LevelInfo
	}
	if c.Format == "" {
		c.Format = "json"
	}
	return c, nil
}

func (c *StdoutConfig) level() slog.Level {
	if lv, ok := c.Level.(slog.Level); ok {
		return lv
	}
	return c.Level.Level()
}

// --- AsyncConfig ---

// AsyncConfig holds configuration for async log processing.
type AsyncConfig struct {
	BufferSize int // Channel buffer size. 0 → 256.
}

// Validate checks required fields and returns a normalized copy with defaults applied.
func (c AsyncConfig) Validate() (AsyncConfig, error) {
	if c.BufferSize <= 0 {
		c.BufferSize = 256
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
		c.Initial = 100
	}
	if c.Thereafter <= 0 {
		c.Thereafter = 10
	}
	if c.Window <= 0 {
		c.Window = time.Second
	}
	return c, nil
}
