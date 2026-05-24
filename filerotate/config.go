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

	MiB                  = 1 << 20
	MaxRotationSuffixSeq = 1000
)

// DefaultFileMode is the default file permission for log files and rotated backups.
const DefaultFileMode os.FileMode = 0600

// Config holds configuration for the rotating file writer.
type Config struct {
	// Path is the absolute path to the log file. Required.
	Path string
	// MaxSizeMB is the maximum file size in MiB before rotation. 0 → 100.
	MaxSizeMB int
	// MaxBackups is the maximum number of rotated backup files. 0 → 5.
	MaxBackups int
	// MaxAgeDays is the maximum age of backup files in days. 0 → 30.
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
	if c.MaxBackups <= 0 {
		c.MaxBackups = DefaultMaxBackups
	}
	if c.MaxAgeDays <= 0 {
		c.MaxAgeDays = DefaultMaxAgeDays
	}
	if c.Compress == nil {
		c.Compress = boolPtr(true)
	}
	if c.FileMode == 0 {
		c.FileMode = DefaultFileMode
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
	return "filerotate/" + e.Op + ": " + e.Err.Error()
}
