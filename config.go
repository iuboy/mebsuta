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
	DefaultSamplingWindow     = time.Second
)

// FileConfig holds mebsuta-specific configuration for file log output (format and level).
// Rotation configuration is handled by filerotate.Config.
type FileConfig struct {
	Level  slog.Leveler // Log level filter. Defaults to slog.LevelInfo.
	Format string       // "json" or "console". Defaults to "json".
}

// Validate returns a normalized copy with defaults applied.
func (c FileConfig) Validate() (FileConfig, error) {
	if isNilLeveler(c.Level) {
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
// It intentionally mirrors FileConfig rather than sharing a common embedded type,
// because file and stdout output may diverge in the future (e.g., stdout gaining
// color/theme options, file gaining compression settings). Keeping them separate
// avoids breaking API changes when they evolve independently.
type StdoutConfig struct {
	Level  slog.Leveler // Log level filter. Defaults to slog.LevelInfo.
	Format string       // "json" or "console". Defaults to "json".
}

// Validate checks required fields and returns a normalized copy with defaults applied.
func (c StdoutConfig) Validate() (StdoutConfig, error) {
	if isNilLeveler(c.Level) {
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

// level returns the effective slog.Level, resolving any Leveler implementation.
// Unlike calling c.Level.Level() directly, this avoids panicking when a typed nil
// pointer (e.g. (*slog.Level)(nil)) is stored in the Leveler interface.
func (c StdoutConfig) level() slog.Level {
	if lv, ok := c.Level.(slog.Level); ok {
		return lv
	}
	if isNilLeveler(c.Level) {
		return slog.LevelInfo
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

// isNilLeveler checks whether l is a nil interface or contains a nil pointer,
// both of which would cause a panic if l.Level() is called.
func isNilLeveler(l slog.Leveler) bool {
	if l == nil {
		return true
	}
	// Detect typed nil pointers stored in the interface. slog.Level and
	// slog.LevelVar both implement Leveler via pointer receiver; a nil
	// *slog.Level or *slog.LevelVar passed to the interface makes the
	// interface non-nil (it holds the type), but calling l.Level()
	// dereferences nil and panics.
	if lv, ok := l.(*slog.Level); ok && lv == nil {
		return true
	}
	if lv, ok := l.(*slog.LevelVar); ok && lv == nil {
		return true
	}
	return false
}

// SafeLevel calls l.Level() defensively. If l is nil or contains a nil pointer
// (e.g. (*slog.Level)(nil) or (*slog.LevelVar)(nil) stored in the Leveler
// interface), it returns slog.LevelInfo as a safe default instead of panicking.
// Exported for use by sub-packages (database, syslog, mbta) that hold a
// slog.Leveler field.
func SafeLevel(l slog.Leveler) slog.Level {
	if isNilLeveler(l) {
		return slog.LevelInfo
	}
	return l.Level()
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
		c.Window = DefaultSamplingWindow
	}
	return c, nil
}
