package mebsuta

import (
	"fmt"
	"log/slog"
	"sync/atomic"
)

// HandlerOption is a functional option for configuring the handler chain built by New.
type HandlerOption func(*handlerOptions) error

type handlerOptions struct {
	handlers     []slog.Handler
	middlewares  []func(slog.Handler) slog.Handler
	errorHandler ErrorHandler
}

// WithHandler adds a slog.Handler to the multi-handler chain.
func WithHandler(h slog.Handler) HandlerOption {
	return func(o *handlerOptions) error {
		if h == nil {
			return fmt.Errorf("mebsuta: handler cannot be nil")
		}
		o.handlers = append(o.handlers, h)
		return nil
	}
}

// UseStdout adds a StdoutHandler with the given config.
func UseStdout(cfg StdoutConfig) HandlerOption {
	return func(o *handlerOptions) error {
		h, err := NewStdoutHandler(cfg)
		if err != nil {
			return err
		}
		o.handlers = append(o.handlers, h)
		return nil
	}
}

// UseFile adds a FileHandler with the given config.
func UseFile(cfg FileConfig) HandlerOption {
	return func(o *handlerOptions) error {
		h, err := NewFileHandler(cfg)
		if err != nil {
			return err
		}
		o.handlers = append(o.handlers, h)
		return nil
	}
}

// UseAsync wraps the handler chain with async buffering.
func UseAsync(cfg AsyncConfig) HandlerOption {
	return func(o *handlerOptions) error {
		o.middlewares = append(o.middlewares, func(inner slog.Handler) slog.Handler {
			return WithAsync(inner, cfg)
		})
		return nil
	}
}

// UseSampling wraps the handler chain with time-window sampling.
func UseSampling(cfg SamplingConfig) HandlerOption {
	return func(o *handlerOptions) error {
		o.middlewares = append(o.middlewares, func(inner slog.Handler) slog.Handler {
			return WithSampling(inner, cfg)
		})
		return nil
	}
}

// UseMetrics wraps the handler chain with Prometheus metrics collection.
func UseMetrics(m HandlerMetrics, name string) HandlerOption {
	return func(o *handlerOptions) error {
		o.middlewares = append(o.middlewares, func(inner slog.Handler) slog.Handler {
			return WithMetrics(inner, m, name)
		})
		return nil
	}
}

// UseContextExtractor injects context-derived attributes into each log record.
func UseContextExtractor(extract ContextExtractor) HandlerOption {
	return func(o *handlerOptions) error {
		o.middlewares = append(o.middlewares, func(inner slog.Handler) slog.Handler {
			return WithContextExtractor(inner, extract)
		})
		return nil
	}
}

// WithErrorHandler sets the function that handles internal handler errors. Default writes to os.Stderr.
// Set to nil to silently discard internal errors; nil propagates to all sub-handlers.
func WithErrorHandler(fn ErrorHandler) HandlerOption {
	return func(o *handlerOptions) error {
		o.errorHandler = fn
		return nil
	}
}

// loadErrorHandler loads the ErrorHandler from an atomic pointer.
func loadErrorHandler(p *atomic.Pointer[ErrorHandler]) ErrorHandler {
	v := p.Load()
	if v == nil {
		return nil
	}
	return *v
}

// buildHandler builds a slog.Handler from options. With 0 handlers, uses the default stdout JSON logger.
func buildHandler(opts ...HandlerOption) (slog.Handler, error) {
	o := &handlerOptions{}
	for _, opt := range opts {
		if err := opt(o); err != nil {
			return nil, err
		}
	}
	if len(o.handlers) == 0 {
		h, err := NewStdoutHandler(StdoutConfig{})
		if err != nil {
			return nil, err
		}
		o.handlers = append(o.handlers, h)
	}

	// Build terminal: single handler or fanout
	var handler slog.Handler
	if len(o.handlers) == 1 {
		handler = o.handlers[0]
	} else {
		handler = safeMultiHandler(o.handlers, o.errorHandler)
	}

	// Apply middlewares: declared later wraps outermost
	for _, mw := range o.middlewares {
		handler = mw(handler)
	}

	// Propagate error handler to all layers
	propagateErrorHandler(handler, o.errorHandler)

	return handler, nil
}
