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

// Audit logs at the Audit level for compliance records. The event type defaults to "system".
func Audit(msg string, args ...any) {
	AuditEvent(EventSystem, msg, args...)
}

// AuditContext logs at the Audit level with the given context. The event type defaults to "system".
func AuditContext(ctx context.Context, msg string, args ...any) {
	AuditEventContext(ctx, EventSystem, msg, args...)
}

// AuditEvent logs an audit record with an explicit event type.
func AuditEvent(eventType EventType, msg string, args ...any) {
	AuditEventContext(context.Background(), eventType, msg, args...)
}

// AuditEventContext logs an audit record with an explicit event type and context.
func AuditEventContext(ctx context.Context, eventType EventType, msg string, args ...any) {
	slog.Log(ctx, LevelAudit, msg, append(args, "event_type", string(eventType))...)
}

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

// LogEntry is a structured log entry extracted from a slog.Record, shared by DatabaseHandler and SyslogHandler.
//
// NOTE: This type is exported for cross-package use by the database sub-package; application code should use slog.Record directly.
type LogEntry struct {
	Time    time.Time
	Level   slog.Level
	Message string
	Attrs   []slog.Attr
}

// RecordToLogEntry extracts a LogEntry from a slog.Record.
// NOTE: Exported for the database sub-package; application code does not need to call this directly.
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
type ErrorHandler func(HandlerError)

// DefaultErrorHandler writes error details to os.Stderr.
var DefaultErrorHandler ErrorHandler = defaultErrorHandler

func defaultErrorHandler(he HandlerError) {
	fmt.Fprintf(os.Stderr, "mebsuta/%s/%s: %v\n", he.Component, he.Operation, he.Err)
}

// LogErrorHandler returns an ErrorHandler that writes to w.
func LogErrorHandler(w io.Writer) ErrorHandler {
	return func(he HandlerError) {
		fmt.Fprintf(w, "mebsuta/%s/%s: %v\n", he.Component, he.Operation, he.Err)
	}
}

// SilentErrorHandler returns an ErrorHandler that discards all errors.
func SilentErrorHandler() ErrorHandler {
	return func(HandlerError) {}
}
