package mebsuta

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"

	"github.com/iuboy/mebsuta/internal/handlerkit"
)

// StdoutHandler 将日志记录写入 stdout。
type StdoutHandler struct {
	handlerCore
	cfg   StdoutConfig
	inner slog.Handler // 底层 contractJSONHandler 或 slog.TextHandler
}

// NewStdoutHandler 创建用 cfg 写 stdout 的 StdoutHandler。
// 内部会调用 cfg.Validate 应用默认值。
func NewStdoutHandler(cfg StdoutConfig) (*StdoutHandler, error) {
	// 委托给 newStdoutHandlerWithWriter，保持单一构造路径。
	return newStdoutHandlerWithWriter(os.Stdout, cfg)
}

func newStdoutHandlerWithWriter(w io.Writer, cfg StdoutConfig) (*StdoutHandler, error) {
	cfg, err := cfg.Validate()
	if err != nil {
		return nil, fmt.Errorf("mebsuta: %w", err)
	}
	h := &StdoutHandler{
		handlerCore: newHandlerCore(),
		cfg:         cfg,
	}
	h.inner = newInnerHandler(w, EncodingType(cfg.Format), replaceAttr(cfg.Timezone), cfg.Timezone)
	return h, nil
}

// Enabled 实现 slog.Handler。
func (h *StdoutHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.cfg.level()
}

// Handle 实现 slog.Handler。
func (h *StdoutHandler) Handle(ctx context.Context, r slog.Record) error {
	return h.inner.Handle(ctx, r)
}

// WithAttrs 实现 slog.Handler。
func (h *StdoutHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &StdoutHandler{
		handlerCore: h.handlerCore, // 保留身份供 CloseAll 去重
		cfg:         h.cfg,
		inner:       h.inner.WithAttrs(attrs),
	}
}

// WithGroup 实现 slog.Handler。
func (h *StdoutHandler) WithGroup(name string) slog.Handler {
	return &StdoutHandler{
		handlerCore: h.handlerCore, // 保留身份供 CloseAll 去重
		cfg:         h.cfg,
		inner:       h.inner.WithGroup(name),
	}
}

// Close 是 no-op：stdout 无需关闭。

// SetLevel 运行时热调级别（0.1.0-14）。仅当构造期 Level 传入
// *slog.LevelVar 时生效并返回 true；固定级别返回 false（进入
// mebsuta.SetLevel 的 skipped 诚实面）。
func (h *StdoutHandler) SetLevel(level slog.Level) bool {
	return handlerkit.NewLevelGate(h.cfg.Level).Set(level)
}
func (h *StdoutHandler) Close() error {
	return nil
}

// unwrapHandler 实现 handlerUnwrapper，使 CloseAll 能穿过
// StdoutHandler 到达可能需要关闭的内层 handler。
func (h *StdoutHandler) unwrapHandler() slog.Handler {
	return h.inner
}

var (
	_ slog.Handler     = (*StdoutHandler)(nil)
	_ io.Closer        = (*StdoutHandler)(nil)
	_ handlerUnwrapper = (*StdoutHandler)(nil)
)

// replaceAttr 返回 TextHandler 的 ReplaceAttr:time 属性转到指定时区,
// level 属性映射为规范文本——AUDIT 此前渲染为 slog 数值形式
// "ERROR+4"(B7)。用于 console 输出。loc 为 nil 时用 UTC。
func replaceAttr(loc *time.Location) func([]string, slog.Attr) slog.Attr {
	if loc == nil {
		loc = time.UTC
	}
	return func(groups []string, a slog.Attr) slog.Attr {
		if len(groups) != 0 {
			return a
		}
		switch a.Key {
		case slog.TimeKey:
			if t, ok := a.Value.Any().(time.Time); ok {
				return slog.Time(slog.TimeKey, t.In(loc))
			}
		case slog.LevelKey:
			if lv, ok := a.Value.Any().(slog.Level); ok {
				return slog.String(slog.LevelKey, LevelName(lv))
			}
		}
		return a
	}
}

// newInnerHandler 按给定格式创建底层 slog handler。
// JSON 格式用强制契约的 JSON handler；Console 用 slog.TextHandler。
// 级别过滤由外层 handler 完成，因此内层 handler 接受所有级别。
// replaceAttr 转发给 TextHandler（用于 console 时区转换）。
// loc 转发给 contractJSONHandler（用于 JSON 时区转换）。
func newInnerHandler(w io.Writer, format EncodingType, replaceAttr func([]string, slog.Attr) slog.Attr, loc *time.Location) slog.Handler {
	opts := &slog.HandlerOptions{
		Level:       slog.LevelDebug, // 级别过滤由外层 handler 控制
		ReplaceAttr: replaceAttr,
	}
	switch format {
	case Console:
		return slog.NewTextHandler(w, opts)
	default:
		return newContractJSONHandler(w, loc)
	}
}
