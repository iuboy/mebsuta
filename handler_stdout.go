package mebsuta

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"
)

// StdoutHandler writes log records to stdout.
type StdoutHandler struct {
	handlerCore
	cfg   StdoutConfig
	inner slog.Handler // underlying contractJSONHandler or slog.TextHandler
}

// NewStdoutHandler creates a StdoutHandler that writes to stdout using cfg.
// cfg.Validate is called internally to apply defaults.
func NewStdoutHandler(cfg StdoutConfig) (*StdoutHandler, error) {
	// Delegate to newStdoutHandlerWithWriter to keep a single constructor path.
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
	h.inner = newInnerHandler(w, EncodingType(cfg.Format), timezoneReplaceAttr(cfg.Timezone), cfg.Timezone)
	return h, nil
}

// Enabled implements slog.Handler.
func (h *StdoutHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.cfg.level()
}

// Handle implements slog.Handler.
func (h *StdoutHandler) Handle(ctx context.Context, r slog.Record) error {
	return h.inner.Handle(ctx, r)
}

// WithAttrs implements slog.Handler.
func (h *StdoutHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &StdoutHandler{
		handlerCore: newHandlerCore(),
		cfg:         h.cfg,
		inner:       h.inner.WithAttrs(attrs),
	}
}

// WithGroup implements slog.Handler.
func (h *StdoutHandler) WithGroup(name string) slog.Handler {
	return &StdoutHandler{
		handlerCore: newHandlerCore(),
		cfg:         h.cfg,
		inner:       h.inner.WithGroup(name),
	}
}

// Close is a no-op because stdout does not need to be closed.
func (h *StdoutHandler) Close() error {
	return nil
}

var (
	_ slog.Handler = (*StdoutHandler)(nil)
	_ io.Closer    = (*StdoutHandler)(nil)
)

// timezoneReplaceAttr 返回一个 ReplaceAttr 函数，把 slog 的 time 属性转到指定时区。
// 用于 console/TextHandler 的时区展示。loc 为 nil 时用 UTC。
func timezoneReplaceAttr(loc *time.Location) func([]string, slog.Attr) slog.Attr {
	if loc == nil {
		loc = time.UTC
	}
	return func(groups []string, a slog.Attr) slog.Attr {
		if a.Key == slog.TimeKey && len(groups) == 0 {
			if t, ok := a.Value.Any().(time.Time); ok {
				return slog.Time(slog.TimeKey, t.In(loc))
			}
		}
		return a
	}
}

// newInnerHandler creates the underlying slog handler for the given format.
// JSON format uses a contract-enforcing JSON handler; Console uses slog.TextHandler.
// Level filtering is done by the outer handler, so the inner handler accepts all levels.
// replaceAttr is forwarded to the TextHandler (for console timezone conversion).
// loc is forwarded to the contractJSONHandler (for JSON timezone conversion).
func newInnerHandler(w io.Writer, format EncodingType, replaceAttr func([]string, slog.Attr) slog.Attr, loc *time.Location) slog.Handler {
	opts := &slog.HandlerOptions{
		Level:       slog.LevelDebug, // level filtering is controlled by the outer handler
		ReplaceAttr: replaceAttr,
	}
	switch format {
	case Console:
		return slog.NewTextHandler(w, opts)
	default:
		return newContractJSONHandler(w, loc)
	}
}
