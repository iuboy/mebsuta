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

// New 使用 HandlerOption 创建 *slog.Logger，返回标准 slog.Logger。
func New(opts ...HandlerOption) (*slog.Logger, error) {
	handler, err := buildHandler(opts...)
	if err != nil {
		return nil, err
	}
	return slog.New(handler), nil
}

func Debug(msg string, args ...any) { slog.Debug(msg, args...) }
func Info(msg string, args ...any)  { slog.Info(msg, args...) }
func Warn(msg string, args ...any)  { slog.Warn(msg, args...) }
func Error(msg string, args ...any) { slog.Error(msg, args...) }

// Audit 记录审计级别日志（合规日志）。级别高于 Error，不受采样限制。
func Audit(msg string, args ...any) {
	slog.Log(context.Background(), LevelAudit, msg, args...)
}

// AuditContext 记录带 context 的审计级别日志。
func AuditContext(ctx context.Context, msg string, args ...any) {
	slog.Log(ctx, LevelAudit, msg, args...)
}

func DebugContext(ctx context.Context, msg string, args ...any) {
	slog.DebugContext(ctx, msg, args...)
}

func InfoContext(ctx context.Context, msg string, args ...any) {
	slog.InfoContext(ctx, msg, args...)
}

func WarnContext(ctx context.Context, msg string, args ...any) {
	slog.WarnContext(ctx, msg, args...)
}

func ErrorContext(ctx context.Context, msg string, args ...any) {
	slog.ErrorContext(ctx, msg, args...)
}

// LogEntry 是从 slog.Record 提取的结构化日志条目。
// DatabaseHandler 和 SyslogHandler 共享此 schema。
//
// NOTE: 此类型因 database 子包跨包引用而导出，非面向终端用户。
// 应用代码应直接使用 slog.Record。
type LogEntry struct {
	Time    time.Time
	Level   slog.Level
	Message string
	Attrs   []slog.Attr
}

// RecordToLogEntry 从 slog.Record 提取 LogEntry。
// NOTE: 因 database 子包跨包引用而导出，应用代码无需直接调用。
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

// ErrorHandler 处理 Handler 内部错误（如文件轮转失败、数据库写入失败等）。
// slog.Logger 静默吞掉 Handle 返回的 error，Handler 需要通过此机制报告内部错误。
// 默认写入 os.Stderr。用户可通过 WithErrorHandler 自定义。
type ErrorHandler func(component string, err error)

// DefaultErrorHandler 是默认的内部错误处理函数，写入 os.Stderr。
// Handler 构造时值拷贝，运行时修改不影响已创建的实例。
var DefaultErrorHandler ErrorHandler = defaultErrorHandler

func defaultErrorHandler(component string, err error) {
	fmt.Fprintf(os.Stderr, "mebsuta/%s: %v\n", component, err)
}
