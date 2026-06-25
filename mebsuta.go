// Package mebsuta provides a production-grade structured logging library built on slog.
//
// It offers slog.Handler plugins: stdout/file/syslog/database output, log sampling,
// async writing, Prometheus metrics, and more.
//
// Usage:
//
//	logger, err := mebsuta.New()
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer mebsuta.CloseAll(logger.Handler())
//
//	slog.Info("hello", "key", "value")
package mebsuta

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"
)

// EncodingType defines the log output encoding format.
type EncodingType string

// Log encoding formats. Use JSON for structured machine-readable output, Console for human-readable text.
const (
	JSON    EncodingType = "json"
	Console EncodingType = "console"
)

// LevelAudit is the audit log level for compliance logging (GB/T 22239, GM/T 0054).
// Severity is above Error; handlers at Error level accept Audit records, and samplers always pass them through.
const LevelAudit slog.Level = slog.LevelError + 4

// HandlerError is a structured error reported by handlers through ErrorHandler.
type HandlerError struct {
	Component string // "file", "syslog", "database", "async", "multi"
	Operation string // "write", "rotate", "connect", "batch", "compress", "cleanup", "send"
	Err       error
	Dropped   int64     // records dropped in this operation (async buffer full)
	Retryable bool      // caller can safely retry
	Records   int       // records affected (batch level)
	Time      time.Time // when the error occurred
}

func (e *HandlerError) Unwrap() error { return e.Err }

func (e *HandlerError) Error() string {
	return fmt.Sprintf("mebsuta/%s/%s: %v", e.Component, e.Operation, e.Err)
}

// New creates a *slog.Logger from the given HandlerOption list.
// With zero options, returns a JSON-format stdout logger at Info level.
func New(opts ...HandlerOption) (*slog.Logger, error) {
	handler, err := buildHandler(opts...)
	if err != nil {
		return nil, err
	}
	return slog.New(handler), nil
}

// Init creates a logger with the given options and sets it as the global default.
// Equivalent to: logger, _ := mebsuta.New(opts...); slog.SetDefault(logger)
func Init(opts ...HandlerOption) (*slog.Logger, error) {
	logger, err := New(opts...)
	if err != nil {
		return nil, err
	}
	slog.SetDefault(logger)
	return logger, nil
}

// Debug logs at Debug level using the default logger.
func Debug(msg string, args ...any) { slog.Debug(msg, args...) }

// Info logs at Info level using the default logger.
func Info(msg string, args ...any) { slog.Info(msg, args...) }

// Warn logs at Warn level using the default logger.
func Warn(msg string, args ...any) { slog.Warn(msg, args...) }

// Error logs at Error level using the default logger.
func Error(msg string, args ...any) { slog.Error(msg, args...) }

// DebugContext logs at Debug level with the given context.
func DebugContext(ctx context.Context, msg string, args ...any) {
	slog.DebugContext(ctx, msg, args...)
}

// InfoContext logs at Info level with the given context.
func InfoContext(ctx context.Context, msg string, args ...any) {
	slog.InfoContext(ctx, msg, args...)
}

// WarnContext logs at Warn level with the given context.
func WarnContext(ctx context.Context, msg string, args ...any) {
	slog.WarnContext(ctx, msg, args...)
}

// ErrorContext logs at Error level with the given context.
func ErrorContext(ctx context.Context, msg string, args ...any) {
	slog.ErrorContext(ctx, msg, args...)
}

// LogEntry is a flat representation of a slog.Record, used by the syslog handler
// to marshal structured log data. Fields are the same as slog.Record but Attrs is materialized as
// a slice rather than a callback.
type LogEntry struct {
	Time    time.Time   // Timestamp of the log record.
	Level   slog.Level  // Log severity level.
	Message string      // Log message.
	Attrs   []slog.Attr // All attributes attached to the record.
}

// RecordToLogEntry converts a slog.Record into a LogEntry by materializing its attrs callback
// into a concrete slice. Exported for use by sub-packages (database, syslog).
func RecordToLogEntry(r slog.Record) LogEntry {
	e := LogEntry{
		Time:    r.Time,
		Level:   r.Level,
		Message: r.Message,
	}
	r.Attrs(func(attr slog.Attr) bool {
		e.Attrs = append(e.Attrs, attr)
		return true
	})
	return e
}

// ErrorHandler handles internal Handler errors (e.g., file rotation failure, database write failure).
// Since slog.Logger silently ignores errors returned from Handle, handlers use this mechanism to report errors.
// The default writes to os.Stderr; customize via WithErrorHandler.
type ErrorHandler func(*HandlerError)

// DefaultErrorHandler writes error details to os.Stderr.
var DefaultErrorHandler ErrorHandler = defaultErrorHandler

func defaultErrorHandler(he *HandlerError) {
	_, _ = fmt.Fprintf(os.Stderr, "mebsuta/%s/%s: %v\n", he.Component, he.Operation, he.Err)
}

// LogErrorHandler returns an ErrorHandler that writes to w.
func LogErrorHandler(w io.Writer) ErrorHandler {
	return func(he *HandlerError) {
		_, _ = fmt.Fprintf(w, "mebsuta/%s/%s: %v\n", he.Component, he.Operation, he.Err)
	}
}

// SilentErrorHandler returns an ErrorHandler that discards all errors.
func SilentErrorHandler() ErrorHandler {
	return func(*HandlerError) {}
}

// BoolPtr returns a pointer to the given bool value, useful for config struct fields of type *bool.
func BoolPtr(b bool) *bool { return &b }
