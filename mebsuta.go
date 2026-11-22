// Package mebsuta 提供基于 slog 的生产级结构化日志库。
//
// 它提供一系列 slog.Handler 插件：stdout/file/syslog/database 输出、
// 日志采样、异步写入、Prometheus 指标等。
//
// 用法：
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
	"sync"

	"github.com/iuboy/mebsuta/internal/handlerkit"
)

// EncodingType 定义日志输出的编码格式。
type EncodingType string

// 日志编码格式。JSON 用于结构化机器可读输出，Console 用于人类可读文本。
const (
	JSON    EncodingType = "json"
	Console EncodingType = "console"
)

// LevelAudit 是合规日志（GB/T 22239、GM/T 0054）的审计日志级别。
// 严重级高于 Error；Error 级别的 handler 接受 Audit 记录，采样器总是放行。
//
// 注意：LevelAudit = slog.LevelError + 4 = 12。Go 的 slog 为标准
// Debug/Info/Warn/Error 保留 0–9 级，但未来的 Go 版本可能扩大保留范围。
// 若 Go 新增 9 以上的级别，可能与该值冲突。概率很低（自 1.21 引入 slog
// 以来 Go 一直稳定），但下游使用者应知悉此边界。
const LevelAudit slog.Level = slog.LevelError + 4

// HandlerError 是 handler 通过 ErrorHandler 上报的结构化错误。
// 实体归属 internal/handlerkit,此处以类型别名保持公共契约不变。
type HandlerError = handlerkit.HandlerError

// ErrorHandler 处理 handler 的内部错误（如文件轮转失败、数据库写入失败）。
// 由于 slog.Logger 会静默忽略 Handle 返回的错误，handler 通过该机制上报错误。
// 默认写入 os.Stderr；可通过 WithErrorHandler 定制。
type ErrorHandler = handlerkit.ErrorHandler

// New 根据给定的 HandlerOption 列表创建 *slog.Logger。
// 零选项时返回 Info 级别的 JSON 格式 stdout logger。
func New(opts ...HandlerOption) (*slog.Logger, error) {
	handler, err := buildHandler(opts...)
	if err != nil {
		return nil, err
	}
	return slog.New(handler), nil
}

// Init 用给定选项创建 logger 并设为全局默认。
// 等价于：logger, _ := mebsuta.New(opts...); slog.SetDefault(logger)
func Init(opts ...HandlerOption) (*slog.Logger, error) {
	logger, err := New(opts...)
	if err != nil {
		return nil, err
	}
	slog.SetDefault(logger)
	return logger, nil
}

// Debug 使用默认 logger 以 Debug 级别记录日志。
func Debug(msg string, args ...any) { slog.Debug(msg, args...) }

// Info 使用默认 logger 以 Info 级别记录日志。
func Info(msg string, args ...any) { slog.Info(msg, args...) }

// Warn 使用默认 logger 以 Warn 级别记录日志。
func Warn(msg string, args ...any) { slog.Warn(msg, args...) }

// Error 使用默认 logger 以 Error 级别记录日志。
func Error(msg string, args ...any) { slog.Error(msg, args...) }

// DebugContext 以 Debug 级别携带给定 context 记录日志。
func DebugContext(ctx context.Context, msg string, args ...any) {
	slog.DebugContext(ctx, msg, args...)
}

// InfoContext 以 Info 级别携带给定 context 记录日志。
func InfoContext(ctx context.Context, msg string, args ...any) {
	slog.InfoContext(ctx, msg, args...)
}

// WarnContext 以 Warn 级别携带给定 context 记录日志。
func WarnContext(ctx context.Context, msg string, args ...any) {
	slog.WarnContext(ctx, msg, args...)
}

// ErrorContext 以 Error 级别携带给定 context 记录日志。
func ErrorContext(ctx context.Context, msg string, args ...any) {
	slog.ErrorContext(ctx, msg, args...)
}

// DefaultErrorHandler 将错误详情写入 os.Stderr。
var DefaultErrorHandler ErrorHandler = defaultErrorHandler

// defaultErrMu 串行化 defaultErrorHandler 对 os.Stderr 的写入。错误
// 处理器会在任意 goroutine 中被调用（多输出时每个 handler 并发调用）；
// 无锁的话交错执行的 Fprintf 输出可能撕裂。
var defaultErrMu sync.Mutex

func defaultErrorHandler(he *HandlerError) {
	defaultErrMu.Lock()
	defer defaultErrMu.Unlock()
	// HandlerError.Error() 产出 "mebsuta/<component>/<op>: <err>",
	// Fprintln 恰好补上换行——格式串不再有第二份拷贝。
	_, _ = fmt.Fprintln(os.Stderr, he)
}

// LogErrorHandler 返回写入 w 的 ErrorHandler。
// 返回的 handler 会串行化写入：错误处理器会在任意 goroutine 中被调用，
// 对同一 io.Writer 的并发 Fprintln 调用可能撕裂交错（与 defaultErrorHandler
// 的加锁行为一致）。
func LogErrorHandler(w io.Writer) ErrorHandler {
	var mu sync.Mutex
	return func(he *HandlerError) {
		mu.Lock()
		defer mu.Unlock()
		_, _ = fmt.Fprintln(w, he)
	}
}

// SilentErrorHandler 返回丢弃所有错误的 ErrorHandler。
func SilentErrorHandler() ErrorHandler {
	return func(*HandlerError) {}
}

// Ptr 返回 v 的指针，适用于 *bool、*int 等指针类型配置字段的紧凑构造。
// 泛型形式取代此前逐类型的 BoolPtr/IntPtr 助手。
func Ptr[T any](v T) *T { return &v }
