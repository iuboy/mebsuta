package mebsuta

import (
	"context"
	"io"
	"log/slog"
	"os"
	"sync"
)

// StdoutHandler writes log records to stdout.
type StdoutHandler struct {
	cfg   StdoutConfig
	inner slog.Handler // 底层 slog.JSONHandler 或 slog.TextHandler
	mu    *sync.Mutex
}

// NewStdoutHandler creates a StdoutHandler that writes to stdout using cfg.
// cfg.Validate is called internally to apply defaults.
func NewStdoutHandler(cfg StdoutConfig) *StdoutHandler {
	cfg, _ = cfg.Validate()
	h := &StdoutHandler{
		cfg: cfg,
		mu:  &sync.Mutex{},
	}
	h.inner = newInnerHandler(os.Stdout, EncodingType(cfg.Format))
	return h
}

func newStdoutHandlerWithWriter(w io.Writer, cfg StdoutConfig) *StdoutHandler {
	cfg, _ = cfg.Validate()
	h := &StdoutHandler{
		cfg: cfg,
		mu:  &sync.Mutex{},
	}
	h.inner = newInnerHandler(w, EncodingType(cfg.Format))
	return h
}

func (h *StdoutHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.cfg.level()
}

func (h *StdoutHandler) Handle(ctx context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.inner.Handle(ctx, r)
}

func (h *StdoutHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &StdoutHandler{
		cfg:   h.cfg,
		inner: h.inner.WithAttrs(attrs),
		mu:    h.mu,
	}
}

func (h *StdoutHandler) WithGroup(name string) slog.Handler {
	return &StdoutHandler{
		cfg:   h.cfg,
		inner: h.inner.WithGroup(name),
		mu:    h.mu,
	}
}

// Close is a no-op because stdout does not need to be closed.
func (h *StdoutHandler) Close() error {
	return nil
}

// newInnerHandler creates the underlying slog handler for the given format.
// JSON format uses a contract-enforcing JSON handler; Console uses slog.TextHandler.
// Level filtering is done by the outer handler, so the inner handler accepts all levels.
func newInnerHandler(w io.Writer, format EncodingType) slog.Handler {
	opts := &slog.HandlerOptions{
		Level: slog.LevelDebug, // level 过滤由外层 handler 控制
	}
	switch format {
	case Console:
		return slog.NewTextHandler(w, opts)
	default:
		return newContractJSONHandler(w)
	}
}
