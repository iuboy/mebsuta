package mebsuta

import (
	"fmt"
	"log/slog"

	"github.com/iuboy/mebsuta/filerotate"
)

// HandlerOption 是用于配置 New 所构建 handler 链的函数式选项。
type HandlerOption func(*handlerOptions) error

type handlerOptions struct {
	handlers     []slog.Handler
	middlewares  []func(slog.Handler) slog.Handler
	errorHandler ErrorHandler
}

// WithHandler 向多 handler 链中添加一个 slog.Handler。
func WithHandler(h slog.Handler) HandlerOption {
	return func(o *handlerOptions) error {
		if h == nil {
			return fmt.Errorf("mebsuta: handler cannot be nil")
		}
		o.handlers = append(o.handlers, h)
		return nil
	}
}

// UseStdout 以给定配置添加一个 StdoutHandler。
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

// UseFile 以给定的轮转配置与文件配置添加一个 FileHandler。
func UseFile(rotateCfg filerotate.Config, cfg FileConfig) HandlerOption {
	return func(o *handlerOptions) error {
		h, err := NewFileHandler(rotateCfg, cfg)
		if err != nil {
			return err
		}
		o.handlers = append(o.handlers, h)
		return nil
	}
}

// UseAsync 为 handler 链包裹异步缓冲。
func UseAsync(cfg AsyncConfig) HandlerOption {
	return func(o *handlerOptions) error {
		// 快速失败：超限的 BufferSize 是构造期 OOM 面（channel 立即
		// 分配），因此 New 在构建任何 handler 之前就以 *ConfigError
		// 拒绝。
		if _, err := cfg.Validate(); err != nil {
			return err
		}
		o.middlewares = append(o.middlewares, func(inner slog.Handler) slog.Handler {
			return WithAsync(inner, cfg)
		})
		return nil
	}
}

// UseSampling 为 handler 链包裹时间窗口采样。
func UseSampling(cfg SamplingConfig) HandlerOption {
	return func(o *handlerOptions) error {
		o.middlewares = append(o.middlewares, func(inner slog.Handler) slog.Handler {
			return WithSampling(inner, cfg)
		})
		return nil
	}
}

// UseMetrics 为 handler 链包裹 Prometheus 指标采集。
func UseMetrics(m HandlerMetrics, name string) HandlerOption {
	return func(o *handlerOptions) error {
		o.middlewares = append(o.middlewares, func(inner slog.Handler) slog.Handler {
			return WithMetrics(inner, m, name)
		})
		return nil
	}
}

// UseContextExtractor 向每条日志记录注入从 context 提取的属性。
func UseContextExtractor(extract ContextExtractor) HandlerOption {
	return func(o *handlerOptions) error {
		o.middlewares = append(o.middlewares, func(inner slog.Handler) slog.Handler {
			return WithContextExtractor(inner, extract)
		})
		return nil
	}
}

// WithErrorHandler 设置处理 handler 内部错误的函数。默认写入 os.Stderr。
// 要静默丢弃内部错误，传入 SilentErrorHandler()。
// fn 为 nil 时，handler 保留其 DefaultErrorHandler（输出到 os.Stderr）——
// nil 既不传播也不静默错误。
func WithErrorHandler(fn ErrorHandler) HandlerOption {
	return func(o *handlerOptions) error {
		o.errorHandler = fn
		return nil
	}
}

// buildHandler 根据选项构建 slog.Handler。0 个 handler 时使用默认的 stdout JSON logger。
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

	// 构建末端：单个 handler 或 fanout
	var handler slog.Handler
	if len(o.handlers) == 1 {
		handler = o.handlers[0]
	} else {
		// 未设置自定义错误处理器时使用默认值（os.Stderr），
		// 避免 safeMulti 中 panic 恢复产生的错误被静默丢弃。
		eh := o.errorHandler
		if eh == nil {
			eh = DefaultErrorHandler
		}
		handler = safeMultiHandler(o.handlers, eh)
	}

	// 应用中间件：后声明的包裹在最外层
	for _, mw := range o.middlewares {
		handler = mw(handler)
	}

	// 向所有层传播错误处理器
	propagateErrorHandler(handler, o.errorHandler, 0)

	return handler, nil
}
