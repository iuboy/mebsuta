package mebsuta

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"

	"github.com/iuboy/mebsuta/filerotate"
)

// FileHandler writes log records to a file with size and time-based rotation and optional gzip compression.
// Rotation is handled by the filerotate sub-package; this handler provides slog integration with level
// filtering and format selection.
type FileHandler struct {
	handlerCore
	leveler slog.Leveler
	inner   slog.Handler
	writer  *filerotate.Writer
}

// NewFileHandler creates a FileHandler using the given rotation config and file config.
func NewFileHandler(rotateCfg filerotate.Config, cfg FileConfig) (*FileHandler, error) {
	cfg, err := cfg.Validate()
	if err != nil {
		return nil, fmt.Errorf("mebsuta: %w", err)
	}

	w, err := filerotate.New(rotateCfg)
	if err != nil {
		return nil, fmt.Errorf("mebsuta: %w", err)
	}

	inner := newInnerHandler(w, EncodingType(cfg.Format))

	h := &FileHandler{
		handlerCore: newHandlerCore(),
		leveler:     cfg.Level,
		inner:       inner,
		writer:      w,
	}

	// Set up error handler bridge: filerotate.Error → HandlerError
	eh := DefaultErrorHandler
	h.setErrorHandler(eh)

	return h, nil
}

// Enabled implements slog.Handler.
func (h *FileHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.leveler.Level()
}

// Handle implements slog.Handler.
func (h *FileHandler) Handle(ctx context.Context, r slog.Record) error {
	return h.inner.Handle(ctx, r)
}

// WithAttrs implements slog.Handler.
func (h *FileHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &FileHandler{
		handlerCore: newHandlerCore(),
		leveler:     h.leveler,
		inner:       h.inner.WithAttrs(attrs),
		writer:      h.writer,
	}
}

// WithGroup implements slog.Handler.
func (h *FileHandler) WithGroup(name string) slog.Handler {
	return &FileHandler{
		handlerCore: newHandlerCore(),
		leveler:     h.leveler,
		inner:       h.inner.WithGroup(name),
		writer:      h.writer,
	}
}

// Close implements io.Closer.
func (h *FileHandler) Close() error {
	return h.writer.Close()
}

func (h *FileHandler) setErrorHandler(fn ErrorHandler) {
	h.writer.SetOnError(func(err error) {
		var ferr *filerotate.Error
		if errors.As(err, &ferr) {
			ReportError(fn, &HandlerError{Component: "file", Operation: ferr.Op, Err: ferr.Err})
		} else {
			ReportError(fn, &HandlerError{Component: "file", Operation: "write", Err: err})
		}
	})
}

// Compile-time assertions
var (
	_ slog.Handler = (*FileHandler)(nil)
	_ io.Closer    = (*FileHandler)(nil)
)
