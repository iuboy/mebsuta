package mebsuta

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"unsafe"
)

// StdoutHandler writes log records to stdout.
type StdoutHandler struct {
	cfg   StdoutConfig
	inner slog.Handler // underlying contractJSONHandler or slog.TextHandler
}

// NewStdoutHandler creates a StdoutHandler that writes to stdout using cfg.
// cfg.Validate is called internally to apply defaults.
func NewStdoutHandler(cfg StdoutConfig) (*StdoutHandler, error) {
	cfg, err := cfg.Validate()
	if err != nil {
		return nil, fmt.Errorf("mebsuta: %w", err)
	}
	h := &StdoutHandler{
		cfg: cfg,
	}
	h.inner = newInnerHandler(os.Stdout, EncodingType(cfg.Format))
	return h, nil
}

func newStdoutHandlerWithWriter(w io.Writer, cfg StdoutConfig) (*StdoutHandler, error) {
	cfg, err := cfg.Validate()
	if err != nil {
		return nil, fmt.Errorf("mebsuta: %w", err)
	}
	h := &StdoutHandler{
		cfg: cfg,
	}
	h.inner = newInnerHandler(w, EncodingType(cfg.Format))
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
		cfg:   h.cfg,
		inner: h.inner.WithAttrs(attrs),
	}
}

// WithGroup implements slog.Handler.
func (h *StdoutHandler) WithGroup(name string) slog.Handler {
	return &StdoutHandler{
		cfg:   h.cfg,
		inner: h.inner.WithGroup(name),
	}
}

// Close is a no-op because stdout does not need to be closed.
func (h *StdoutHandler) Close() error {
	return nil
}

func (h *StdoutHandler) handlerAddr() uintptr { return uintptr(unsafe.Pointer(h)) }

var (
	_ slog.Handler = (*StdoutHandler)(nil)
	_ io.Closer    = (*StdoutHandler)(nil)
)

// newInnerHandler creates the underlying slog handler for the given format.
// JSON format uses a contract-enforcing JSON handler; Console uses slog.TextHandler.
// Level filtering is done by the outer handler, so the inner handler accepts all levels.
func newInnerHandler(w io.Writer, format EncodingType) slog.Handler {
	opts := &slog.HandlerOptions{
		Level: slog.LevelDebug, // level filtering is controlled by the outer handler
	}
	switch format {
	case Console:
		return slog.NewTextHandler(w, opts)
	default:
		return newContractJSONHandler(w)
	}
}
