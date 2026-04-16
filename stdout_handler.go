package mebsuta

import (
	"context"
	"io"
	"log/slog"
	"os"
	"sync"
)

// StdoutHandler 将日志记录输出到 stdout。
// 实现 slog.Handler 和 io.Closer 接口。
type StdoutHandler struct {
	LevelHandler
	format EncodingType
	inner  slog.Handler // 底层 slog.JSONHandler 或 slog.TextHandler
	mu     sync.Mutex
}

// NewStdoutHandler 创建输出到 stdout 的 slog.Handler。
// level 控制日志级别过滤，format 控制 JSON 或 Console 输出格式。
func NewStdoutHandler(level slog.Level, format EncodingType) *StdoutHandler {
	h := &StdoutHandler{
		LevelHandler: LevelHandler{Level: level},
		format:       format,
	}
	h.inner = newInnerHandler(os.Stdout, format)
	return h
}

// newStdoutHandlerWithWriter 创建输出到指定 writer 的 handler（用于测试）。
func newStdoutHandlerWithWriter(w io.Writer, level slog.Level, format EncodingType) *StdoutHandler {
	h := &StdoutHandler{
		LevelHandler: LevelHandler{Level: level},
		format:       format,
	}
	h.inner = newInnerHandler(w, format)
	return h
}

func newInnerHandler(w io.Writer, format EncodingType) slog.Handler {
	opts := &slog.HandlerOptions{
		Level: slog.LevelDebug, // level 过滤由外层 levelHandler 控制
	}
	switch format {
	case Console:
		return slog.NewTextHandler(w, opts)
	default:
		return slog.NewJSONHandler(w, opts)
	}
}

// Handle 处理一条日志记录，写入 stdout。
func (h *StdoutHandler) Handle(ctx context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.inner.Handle(ctx, r)
}

// WithAttrs 返回带有预置属性的新 StdoutHandler。
func (h *StdoutHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &StdoutHandler{
		LevelHandler: h.LevelHandler,
		format:       h.format,
		inner:        h.inner.WithAttrs(attrs),
	}
}

// WithGroup 返回带有分组前缀的新 StdoutHandler。
func (h *StdoutHandler) WithGroup(name string) slog.Handler {
	return &StdoutHandler{
		LevelHandler: h.LevelHandler,
		format:       h.format,
		inner:        h.inner.WithGroup(name),
	}
}

// Close 刷新并关闭 handler（实现 io.Closer）。
// stdout 不需要关闭，此方法为 nop。
func (h *StdoutHandler) Close() error {
	return nil
}
