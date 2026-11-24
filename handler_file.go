package mebsuta

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"

	"github.com/iuboy/mebsuta/filerotate"
	"github.com/iuboy/mebsuta/internal/handlerkit"
)

// FileHandler 将日志记录写入文件，支持按大小与时间轮转及可选 gzip 压缩。
// 轮转由 filerotate 子包处理；本 handler 提供 slog 集成、级别过滤与
// 格式选择。
type FileHandler struct {
	handlerCore
	level  handlerkit.LevelGate
	inner  slog.Handler
	writer *filerotate.Writer
}

// NewFileHandler 用给定的轮转配置与文件配置创建 FileHandler。
func NewFileHandler(rotateCfg filerotate.Config, cfg FileConfig) (*FileHandler, error) {
	cfg, err := cfg.Validate()
	if err != nil {
		return nil, fmt.Errorf("mebsuta: %w", err)
	}

	w, err := filerotate.New(rotateCfg)
	if err != nil {
		return nil, fmt.Errorf("mebsuta: %w", err)
	}

	inner := newInnerHandler(w, EncodingType(cfg.Format), replaceAttr(cfg.Timezone), cfg.Timezone)

	h := &FileHandler{
		handlerCore: newHandlerCore(),
		level:       handlerkit.NewLevelGate(cfg.Level),
		inner:       inner,
		writer:      w,
	}

	// 建立错误处理器桥接：filerotate.Error → HandlerError
	eh := DefaultErrorHandler()
	h.SetErrorHandler(eh)

	return h, nil
}

// Enabled 实现 slog.Handler。
func (h *FileHandler) Enabled(_ context.Context, level slog.Level) bool {
	return h.level.Enabled(level)
}

// Handle 实现 slog.Handler。
func (h *FileHandler) Handle(ctx context.Context, r slog.Record) error {
	return h.inner.Handle(ctx, r)
}

// WithAttrs 实现 slog.Handler。
func (h *FileHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &FileHandler{
		handlerCore: h.handlerCore, // 保留父级的 errorHandler
		level:       h.level,
		inner:       h.inner.WithAttrs(attrs),
		writer:      h.writer,
	}
}

// WithGroup 实现 slog.Handler。
func (h *FileHandler) WithGroup(name string) slog.Handler {
	return &FileHandler{
		handlerCore: h.handlerCore, // 保留父级的 errorHandler
		level:       h.level,
		inner:       h.inner.WithGroup(name),
		writer:      h.writer,
	}
}

// Close 实现 io.Closer。在关闭底层 writer 之前，刷写内层 handler 中
// 可能缓冲的数据。

// SetLevel 运行时热调级别（0.1.0-14）。仅当构造期 Level 传入
// *slog.LevelVar 时生效并返回 true；固定级别返回 false（进入
// mebsuta.SetLevel 的 skipped 诚实面）。
func (h *FileHandler) SetLevel(level slog.Level) bool {
	return h.level.Set(level)
}
func (h *FileHandler) Close() error {
	return h.writer.Close()
}

func (h *FileHandler) SetErrorHandler(fn ErrorHandler) {
	h.writer.SetOnError(func(err error) {
		var ferr *filerotate.Error
		if errors.As(err, &ferr) {
			handlerkit.ReportError(fn, &HandlerError{Component: "file", Operation: ferr.Op, Err: ferr.Err})
		} else {
			handlerkit.ReportError(fn, &HandlerError{Component: "file", Operation: "write", Err: err})
		}
	})
}

// 编译期断言
var (
	_ slog.Handler = (*FileHandler)(nil)
	_ io.Closer    = (*FileHandler)(nil)
)

// Dropped 返回底层 writer 的写失败累计次数。实现 DroppedCounter：
// MetricsHandler 的丢弃观测因此覆盖同步文件链——此前磁盘满/IO 错误
// 在该观测面不可见（B1）。
func (h *FileHandler) Dropped() int64 {
	return h.writer.FailedWrites()
}
