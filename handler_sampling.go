package mebsuta

import (
	"context"
	"io"
	"log/slog"
	"sync/atomic"
	"time"
)

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

// WithSampling 把 inner 包进 SamplingHandler，按给定 SamplingConfig 丢弃日志记录。
func WithSampling(inner slog.Handler, cfg SamplingConfig) slog.Handler {
	if !cfg.Enabled || inner == nil {
		return inner
	}
	// Validate 对 SamplingConfig 总是成功（只应用默认值，从不返回
	// 错误），因此可以安全忽略错误返回值。
	cfg, _ = cfg.Validate()

	s := &samplingState{
		windowNanos: int64(cfg.Window),
	}
	s.windowEnd.Store(time.Now().Add(cfg.Window).UnixNano())

	return &SamplingHandler{
		handlerCore: newHandlerCore(),
		inner:       inner,
		cfg:         cfg,
		state:       s,
	}
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
	now := time.Now().UnixNano()
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
		count := h.state.count.Add(1)
		if count <= int64(h.cfg.Initial) {
			return h.inner.Handle(ctx, r)
		}
		// 与稳态路径一致地应用 Thereafter，使窗口重置过渡期间的记录
		// 得到同样的采样。
		if (count-int64(h.cfg.Initial))%int64(h.cfg.Thereafter) == 0 {
			return h.inner.Handle(ctx, r)
		}
		return nil
	}

	count := h.state.count.Add(1)
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
