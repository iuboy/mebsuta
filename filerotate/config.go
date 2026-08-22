// Package filerotate provides a rotating file writer for structured logging.
//
// It handles size-based and time-based rotation, backup management with count
// and age limits, and optional gzip compression — similar to lumberjack but
// as an io.Writer compatible with any slog.Handler.
//
// Usage:
//
//	w, _ := filerotate.New(filerotate.Config{Path: "/var/log/app.log", MaxSizeMB: 100})
//	defer w.Close()
//	logger := slog.New(slog.NewJSONHandler(w, nil))
//	logger.Info("hello")
package filerotate

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Default configuration values.
const (
	DefaultMaxSizeMB  = 100
	DefaultMaxBackups = 5
	DefaultMaxAgeDays = 30

	mib                  = 1 << 20
	maxRotationSuffixSeq = 1000

	// maxConfigurableSizeMB bounds MaxSizeMB. Above this the byte conversion
	// (int64 * mib) overflows to a negative number, which disables size
	// rotation silently via the maxBytes > 0 check. 1<<20 MiB = 1 PiB.
	maxConfigurableSizeMB = 1 << 20
)

// DefaultFileMode is the default file permission for log files and rotated backups.
const DefaultFileMode os.FileMode = 0600

// Config holds configuration for the rotating file writer.
type Config struct {
	// Path is the absolute path to the log file. Required.
	Path string
	// MaxSizeMB is the maximum file size in MiB before rotation. ≤0 → 100.
	MaxSizeMB int
	// MaxBackups is the maximum number of rotated backup files to retain.
	// 0 → default (5). <0 → unlimited (keep all backups).
	MaxBackups int
	// MaxAgeDays is the maximum age of backup files in days.
	// 0 → default (30). <0 → unlimited (no age-based removal).
	MaxAgeDays int
	// Compress enables gzip compression of rotated backups. nil → true.
	Compress *bool
	// RotateInterval triggers time-based rotation at this interval. 0 = size-only.
	RotateInterval time.Duration
	// FileMode for log files. 0 → 0600.
	FileMode os.FileMode
	// OnError is called for internal errors (rotation failure, compression failure, etc).
	// nil → writes to os.Stderr.
	OnError func(error)
}

// UnlimitedBackups is the sentinel value for MaxBackups that means "keep all backups".
const UnlimitedBackups = -1

// UnlimitedAge is the sentinel value for MaxAgeDays that means "no age-based removal".
const UnlimitedAge = -1

// Validate checks required fields and returns a normalized copy with defaults applied.
func (c Config) Validate() (Config, error) {
	if c.Path == "" {
		return Config{}, fmt.Errorf("file path is required")
	}
	if !filepath.IsAbs(c.Path) {
		return Config{}, fmt.Errorf("file path must be absolute: %s", c.Path)
	}
	if c.MaxSizeMB <= 0 {
		c.MaxSizeMB = DefaultMaxSizeMB
	}
	if c.MaxSizeMB > maxConfigurableSizeMB {
		return Config{}, fmt.Errorf("MaxSizeMB too large (max %d MiB): %d", maxConfigurableSizeMB, c.MaxSizeMB)
	}
	if c.MaxBackups == 0 {
		c.MaxBackups = DefaultMaxBackups
	}
	if c.MaxAgeDays == 0 {
		c.MaxAgeDays = DefaultMaxAgeDays
	}
	if c.Compress == nil {
		c.Compress = boolPtr(true)
	}
	if c.FileMode == 0 {
		c.FileMode = DefaultFileMode
	}
	// RotateInterval == 0 means size-only rotation (documented). A negative
	// value is nonsensical and would make time.Since(rotatedAt) >= interval
	// always true, forcing a rotation on every Write — reject it explicitly
	// rather than silently degrading.
	if c.RotateInterval < 0 {
		return Config{}, fmt.Errorf("RotateInterval must be >= 0, got %v", c.RotateInterval)
	}
	return c, nil
}

func (c Config) compress() bool {
	return c.Compress != nil && *c.Compress
}

func boolPtr(b bool) *bool { return &b }

// Error represents an internal error from the rotating writer.
type Error struct {
	Op  string // "rotate", "compress", "cleanup", "write"
	Err error
}

func (e *Error) Unwrap() error { return e.Err }

func (e *Error) Error() string {
	// H3: defend against a nil Err — the Error type is exported and surfaced
	// through OnError to user code, so it must not panic on direct construction.
	msg := "filerotate/" + e.Op
	if e.Err != nil {
		msg += ": " + e.Err.Error()
	}
	return msg
}
