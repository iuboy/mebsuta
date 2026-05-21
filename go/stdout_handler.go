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
	LevelHandler
	format EncodingType
	inner  slog.Handler // 底层 slog.JSONHandler 或 slog.TextHandler
	mu     *sync.Mutex
}

// NewStdoutHandler creates a StdoutHandler that writes to stdout at the given level in the specified format.
func NewStdoutHandler(level slog.Level, format EncodingType) *StdoutHandler {
	h := &StdoutHandler{
		LevelHandler: LevelHandler{Level: level},
		format:       format,
		mu:           &sync.Mutex{},
	}
	h.inner = newInnerHandler(os.Stdout, format)
	return h
}

func newStdoutHandlerWithWriter(w io.Writer, level slog.Level, format EncodingType) *StdoutHandler {
	h := &StdoutHandler{
		LevelHandler: LevelHandler{Level: level},
		format:       format,
		mu:           &sync.Mutex{},
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
		return newContractJSONHandler(w)
	}
}

func (h *StdoutHandler) Handle(ctx context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.inner.Handle(ctx, r)
}

func (h *StdoutHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &StdoutHandler{
		LevelHandler: h.LevelHandler,
		format:       h.format,
		inner:        h.inner.WithAttrs(attrs),
		mu:           h.mu,
	}
}

func (h *StdoutHandler) WithGroup(name string) slog.Handler {
	return &StdoutHandler{
		LevelHandler: h.LevelHandler,
		format:       h.format,
		inner:        h.inner.WithGroup(name),
		mu:           h.mu,
	}
}

// Close is a no-op because stdout does not need to be closed.
func (h *StdoutHandler) Close() error {
	return nil
}
