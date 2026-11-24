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
	planes       []planeOption
}

// planeOption 是 UsePlane 声明的平面:name 命名,opts 为该平面链的
// 独立选项集。
type planeOption struct {
	name string
	opts *handlerOptions
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
// 含 UsePlane 时返回平面路由器(默认链由顶层选项构建,平面链各自独立构建)。
func buildHandler(opts ...HandlerOption) (slog.Handler, error) {
	o := &handlerOptions{}
	for _, opt := range opts {
		if err := opt(o); err != nil {
			return nil, err
		}
	}
	if len(o.planes) > 0 {
		return buildPlaneRouter(o)
	}
	return buildChain(o)
}

// buildChain 由单个选项集构建一条 handler 链(fanout → 中间件 → 错误
// 处理器传播)。
func buildChain(o *handlerOptions) (slog.Handler, error) {
	if len(o.handlers) == 0 {
		h, err := NewStdoutHandler(StdoutConfig{})
		if err != nil {
			return nil, err
		}
		o.handlers = append(o.handlers, h)
	}

	// 构建末端：全部经 safeMulti——单 handler 也不例外。safeMulti
	// 的逐 handler panic 恢复让"默认配置的单 handler 链"同样获得
	// panic 遏制（此前只有多输出链有：会 panic 的第三方 handler 与
	// 会 panic 的 error 值可直达调用方）。单 handler 走 safeMulti 的
	// 免克隆快路径，开销为一次包装调用。未设置自定义错误处理器时
	// 使用默认值（os.Stderr），避免 panic 恢复产生的错误被静默丢弃。
	eh := o.errorHandler
	if eh == nil {
		eh = DefaultErrorHandler
	}
	handler := safeMultiHandler(o.handlers, eh)

	// 应用中间件：后声明的包裹在最外层
	for _, mw := range o.middlewares {
		handler = mw(handler)
	}

	// 向所有层传播错误处理器
	propagateErrorHandler(handler, o.errorHandler, 0)

	return handler, nil
}

// buildPlaneRouter 构建平面路由器:默认链来自顶层选项,各平面链来自
// UsePlane 选项集。fanout(默认链 + 全部平面链)供 walk 穿透,CloseAll/
// SetLevel/SetFileMaxAge/双重缓冲检测对全部平面生效。
func buildPlaneRouter(o *handlerOptions) (slog.Handler, error) {
	def, err := buildChain(o)
	if err != nil {
		return nil, err
	}
	planes := make(map[string]slog.Handler, len(o.planes))
	chains := make([]slog.Handler, 0, len(o.planes)+1)
	chains = append(chains, def)
	for _, p := range o.planes {
		ph, err := buildChain(p.opts)
		if err != nil {
			return nil, fmt.Errorf("plane %q: %w", p.name, err)
		}
		planes[p.name] = ph
		chains = append(chains, ph)
	}
	eh := o.errorHandler
	if eh == nil {
		eh = DefaultErrorHandler
	}
	router := &planeRouter{
		handlerCore: newHandlerCore(),
		def:         def,
		planes:      planes,
		fanout:      safeMultiHandler(chains, eh),
	}
	// 顶层 WithErrorHandler 必须穿透路由器到达全部平面链：各平面链
	// 由 buildChain(p.opts) 构建，只见过平面自己的选项。router 本身
	// 不实现 setErrorHandler，propagateErrorHandler 经 unwrapHandler
	// 到达 fanout（safeMulti），由其 setErrorHandler 分发到默认链与
	// 全部平面链。fn 为 nil 时跳过，各链保留构造期默认值。
	propagateErrorHandler(router, o.errorHandler, 0)
	return router, nil
}
