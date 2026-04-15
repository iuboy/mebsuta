// Package mebsuta 提供基于 slog 的生产级结构化日志库。
//
// 提供 slog.Handler 插件: stdout/file/syslog/database 输出、日志采样、
// 异步写入、Prometheus 指标等能力。
//
// 使用方式:
//
//	logger, err := mebsuta.New(
//	    mebsuta.WithHandler(mebsuta.NewStdoutHandler(slog.LevelInfo, mebsuta.JSON)),
//	)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	slog.SetDefault(logger)
//	defer mebsuta.CloseAll(logger.Handler())
//
//	slog.Info("hello", "key", "value")
package mebsuta

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"
)

// =============================================================================
// New() — 创建 *slog.Logger
// =============================================================================

// New 使用 HandlerOption 创建 *slog.Logger。
// 返回标准 slog.Logger，可以直接用 slog.SetDefault 设置为全局默认。
func New(opts ...HandlerOption) (*slog.Logger, error) {
	handler, err := buildHandler(opts...)
	if err != nil {
		return nil, err
	}
	return slog.New(handler), nil
}

// =============================================================================
// 包级日志函数 — 透传到 slog.Default()
// =============================================================================

// Debug 记录调试级别日志。
func Debug(msg string, args ...any) { slog.Debug(msg, args...) }

// Info 记录信息级别日志。
func Info(msg string, args ...any) { slog.Info(msg, args...) }

// Warn 记录警告级别日志。
func Warn(msg string, args ...any) { slog.Warn(msg, args...) }

// Error 记录错误级别日志。
func Error(msg string, args ...any) { slog.Error(msg, args...) }

// DebugContext 记录带 context 的调试级别日志。
func DebugContext(ctx context.Context, msg string, args ...any) {
	slog.DebugContext(ctx, msg, args...)
}

// InfoContext 记录带 context 的信息级别日志。
func InfoContext(ctx context.Context, msg string, args ...any) {
	slog.InfoContext(ctx, msg, args...)
}

// WarnContext 记录带 context 的警告级别日志。
func WarnContext(ctx context.Context, msg string, args ...any) {
	slog.WarnContext(ctx, msg, args...)
}

// ErrorContext 记录带 context 的错误级别日志。
func ErrorContext(ctx context.Context, msg string, args ...any) {
	slog.ErrorContext(ctx, msg, args...)
}

// =============================================================================
// LogEntry — 从 slog.Record 转换的通用日志条目
// =============================================================================

// LogEntry 是从 slog.Record 提取的结构化日志条目。
// DatabaseHandler 和 SyslogHandler 共享此 schema。
type LogEntry struct {
	Time    time.Time
	Level   slog.Level
	Message string
	Attrs   []slog.Attr
}

// RecordToLogEntry 从 slog.Record 提取 LogEntry。
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

// =============================================================================
// 内部辅助
// =============================================================================

// writeError 将 Handler 内部错误写入 stderr。
// slog.Logger 静默吞掉 Handle 返回的 error，
// 各 Handler 应在 Handle 失败时调用此函数确保错误可见。
func writeError(component string, err error) {
	fmt.Fprintf(os.Stderr, "mebsuta/%s: %v\n", component, err)
}
