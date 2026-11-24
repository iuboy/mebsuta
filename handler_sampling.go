package mebsuta

import (
	"context"
	"io"
	"log/slog"
	"sync/atomic"

	"github.com/iuboy/mebsuta/internal/handlerkit"
	"time"
)

// samplingEpoch 是采样窗口的单调时钟基准:窗口终点以 time.Since 计,
// 墙钟回拨不会拉长窗口或造成重置风暴(与 handlerkit.RateGate 同一口径)。
var samplingEpoch = time.Now()

// samplingState 用原子操作跟踪每个窗口的采样计数。通过在 Handle 中
// 惰性检查窗口过期，免除了后台 goroutine。
type samplingState struct {
	count       atomic.Int64
	windowEnd   atomic.Int64 // 当前窗口结束的 unix 纳秒时间戳
	windowNanos int64        // 窗口时长（纳秒；初始化后不可变）
}

// SamplingHandler 是在时间窗口内采样日志记录的 slog.Handler 装饰器。
// Error 及以上总是记录。每窗口前 Initial 条放行；其后每 Thereafter 条
// 保留 1 条。
//
// 采样预算由同一采样链派生的所有 logger 共享（WithAttrs/WithGroup
// 克隆复用一个计数器）。因此高流量组件可耗尽预算并压制其他组件在
// 同一窗口内低于 Error 的日志——这是采样语义固有的。Error 与 Audit
// 记录在 Handle 中免于采样、总是放行；Enabled 则如实反映内层链自身
// 的级别过滤（见 Enabled）。
type SamplingHandler struct {
	handlerCore
	inner slog.Handler
	cfg   SamplingConfig
	state *samplingState
}

// NewSamplingHandler 把 inner 包进 SamplingHandler，按给定
// SamplingConfig 丢弃日志记录。inner 为 nil 时以 *ConfigError 拒绝；
// cfg.Enabled=false 返回 inner 原样（采样未启用，非错误）。
func NewSamplingHandler(inner slog.Handler, cfg SamplingConfig) (slog.Handler, error) {
	if inner == nil {
		return nil, &ConfigError{Field: "UseSampling", Msg: "inner handler cannot be nil"}
	}
	if !cfg.Enabled {
		return inner, nil
	}
	// Validate 对 SamplingConfig 总是成功（只应用默认值，从不返回
	// 错误），因此可以安全忽略错误返回值。
	cfg, _ = cfg.Validate()

	s := &samplingState{
		windowNanos: int64(cfg.Window),
	}
	s.windowEnd.Store(int64(time.Since(samplingEpoch) + cfg.Window))

	return &SamplingHandler{
		handlerCore: newHandlerCore(),
		inner:       inner,
		cfg:         cfg,
		state:       s,
	}, nil
}

// WithSampling 是 NewSamplingHandler 的兼容薄包装（0.1.0-26 起）：
// inner 为 nil 时经默认错误链上报并原样返回。新代码用 New*。
func WithSampling(inner slog.Handler, cfg SamplingConfig) slog.Handler {
	h, err := NewSamplingHandler(inner, cfg)
	if err != nil {
		handlerkit.ReportError(DefaultErrorHandler(), &HandlerError{Component: "sampling", Operation: "init", Err: err})
		return inner
	}
	return h
}

// Enabled 实现 slog.Handler。
//
// Enabled 无条件委托给内层链：Error/Audit 的豁免是采样豁免（下面
// 的 Handle 总是让这些记录穿过采样器），不是级别过滤旁路。若在这里
// 对每条 Error 记录都返回 true，普通 Error 流量将涌入仅审计的内层
// 汇（Level = LevelAudit），也会让运行时收紧的动态 LevelVar 失效。
func (h *SamplingHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.inner.Enabled(ctx, level)
}

// Handle 实现 slog.Handler。
func (h *SamplingHandler) Handle(ctx context.Context, r slog.Record) error {
	// Error 与 Audit（LevelAudit > LevelError）记录永不被采样。
	if r.Level >= slog.LevelError {
		return h.inner.Handle(ctx, r)
	}

	// 检查窗口是否过期，需要时重置。
	now := int64(time.Since(samplingEpoch))
	windowEnd := h.state.windowEnd.Load()
	if now >= windowEnd {
		// 先清零计数再推进窗口（B23）：顺序反了时，CAS 落败者会在
		// 胜者 Store(0) 之前 Add(1)，读到旧窗口的计数而被采样掉
		// ——先清零把误差方向反转为"过渡期多放行"，比静默丢弃
		// 安全。清零对旧窗口是无害的：它已经过期。
		h.state.count.Store(0)
		// CAS 保证只有一个 goroutine 推进窗口终点。
		newEnd := now + h.state.windowNanos
		if !h.state.windowEnd.CompareAndSwap(windowEnd, newEnd) {
			// CAS 落败：另一 goroutine 已推进窗口。若极端时钟偏移导致
			// 新窗口终点也已成为过去，再试一次。这是尽力而为——时钟
			// 异常期间放行全部记录比静默丢弃更安全。
			advanced := h.state.windowEnd.Load()
			if now >= advanced {
				retryEnd := now + h.state.windowNanos
				h.state.windowEnd.CompareAndSwap(advanced, retryEnd)
			}
		}
		// 计数刚被本 goroutine 清零，Add(1) 返回 ≤ 并发 goroutine 数的
		// 值，远在 Initial 预算之内。
		return h.admit(ctx, r, h.state.count.Add(1))
	}

	return h.admit(ctx, r, h.state.count.Add(1))
}

// admit 应用 Initial/Thereafter 判定(E9:窗口过渡与稳态共用同一实现,
// 两条分支此前逐行重复)。
func (h *SamplingHandler) admit(ctx context.Context, r slog.Record, count int64) error {
	if count <= int64(h.cfg.Initial) {
		return h.inner.Handle(ctx, r)
	}
	if (count-int64(h.cfg.Initial))%int64(h.cfg.Thereafter) == 0 {
		return h.inner.Handle(ctx, r)
	}
	return nil
}

// WithAttrs 实现 slog.Handler。
func (h *SamplingHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &SamplingHandler{
		handlerCore: newHandlerCore(),
		inner:       h.inner.WithAttrs(attrs),
		cfg:         h.cfg,
		state:       h.state,
	}
}

// WithGroup 实现 slog.Handler。
func (h *SamplingHandler) WithGroup(name string) slog.Handler {
	return &SamplingHandler{
		handlerCore: newHandlerCore(),
		inner:       h.inner.WithGroup(name),
		cfg:         h.cfg,
		state:       h.state,
	}
}

// Close 实现 io.Closer。
// no-op：没有需要停止的后台 goroutine（窗口重置在 Handle 中惰性完成）。
func (h *SamplingHandler) Close() error {
	return nil
}

func (h *SamplingHandler) unwrapHandler() slog.Handler {
	return h.inner
}

var (
	_ slog.Handler     = (*SamplingHandler)(nil)
	_ io.Closer        = (*SamplingHandler)(nil)
	_ handlerUnwrapper = (*SamplingHandler)(nil)
)
