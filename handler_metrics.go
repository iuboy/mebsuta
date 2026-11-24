package mebsuta

import (
	"context"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/iuboy/mebsuta/internal/handlerkit"
)

// HandlerMetrics 定义采集 handler 级指标（延迟、错误、丢弃）的接口。
type HandlerMetrics interface {
	// ObserveHandle 记录一次 Handle 调用的延迟。
	ObserveHandle(duration time.Duration)

	// IncError 递增错误计数器。
	IncError(handlerName string)

	// IncDroppedN 向丢弃记录计数器加 n。带幅值的形式让 MetricsHandler
	// 能精确转发缓冲 handler 的累计丢弃计数：当内层刷写失败并在两次
	// Handle 调用之间丢弃整批记录时，跳变作为一次
	// IncDroppedN(name, batchSize) 上报，而非少计的 +1。
	IncDroppedN(handlerName string, n int64)
}

// DroppedCounter 由跟踪因积压满或关闭而丢弃记录的 handler 实现
// （AsyncHandler、database/syslog/mbta Handler）。MetricsHandler 探测其
// 内层链并以上报丢弃的方式呈现增量——没有它，缓冲满洪峰对
// Prometheus 是不可见的。
type DroppedCounter interface {
	Dropped() int64
}

// droppedNone 是链中不存在 DroppedCounter 时存储的哨兵，
// 使探测遍历每个 handler 实例至多执行一次。
type droppedNone struct{}

func (droppedNone) Dropped() int64 { return 0 }

// findDroppedCounter 沿 handler 图查找首个 DroppedCounter,经
// walkHandlers 统一口径(unwrap 链 + fanout 展开),找到即停。
func findDroppedCounter(h slog.Handler) DroppedCounter {
	var dc DroppedCounter
	_ = walkHandlers(h, func(x slog.Handler) error {
		if d, ok := x.(DroppedCounter); ok {
			dc = d
			return errStopWalk
		}
		return nil
	})
	return dc
}

// dropTracker 跨 WithAttrs/WithGroup 克隆共享丢弃记账：counter 惰性
// 解析内层链的 DroppedCounter（探测遍历经统一 walk），last 是已上报
// 的累计丢弃数。克隆若各自持 last，每个派生 logger 的首次 Handle
// 都会把内层累计丢弃数整体重报一遍——按请求派生 logger
// （With/WithGroup）正是丢弃洪峰的高发场景，重复上报会在洪峰期把
// 指标放大数倍。
type dropTracker struct {
	counter atomic.Value // DroppedCounter 或 droppedNone；惰性解析
	last    atomic.Int64
}

// resolve 返回内层链的 DroppedCounter（不存在时为 droppedNone 哨兵），
// 每个 tracker 实例至多执行一次探测遍历。并发首次解析经
// CompareAndSwap 收敛：落败者读到的与胜者存入的是同一次确定性
// walk 的结果。
func (t *dropTracker) resolve(inner slog.Handler) DroppedCounter {
	if v := t.counter.Load(); v != nil {
		return v.(DroppedCounter)
	}
	var dc DroppedCounter
	if found := findDroppedCounter(inner); found != nil {
		dc = found
	} else {
		dc = droppedNone{}
	}
	if t.counter.CompareAndSwap(nil, dc) {
		return dc
	}
	return t.counter.Load().(DroppedCounter)
}

// MetricsHandler 是一个 slog.Handler 装饰器，经 HandlerMetrics 接口
// 记录写入延迟与错误计数。
//
// 丢弃：当被包裹的链中含有缓冲 handler 时（把 UseMetrics 声明在
// UseAsync/UseSyslog 类选项之后，使本中间件位于最外层），每次 Handle
// 都以幅值形式把缓冲 handler 的丢弃增量上报为 IncDroppedN：两次
// Handle 调用之间内层 Dropped 计数跳变 N 就上报 N 条丢弃记录，而非 1。
type MetricsHandler struct {
	inner        slog.Handler
	metrics      HandlerMetrics
	handlerName  string
	drops        *dropTracker          // 克隆间共享丢弃记账
	errorHandler *handlerkit.ErrorSlot // 克隆间共享
}

// WithMetrics 把 inner 包进 MetricsHandler，为具名 handler 观测延迟与错误。
func WithMetrics(inner slog.Handler, m HandlerMetrics, handlerName string) slog.Handler {
	if inner == nil || m == nil {
		return inner
	}
	return &MetricsHandler{
		inner:        inner,
		metrics:      m,
		handlerName:  handlerName,
		drops:        &dropTracker{},
		errorHandler: handlerkit.NewErrorSlot(DefaultErrorHandler),
	}
}

// Enabled 实现 slog.Handler。
func (h *MetricsHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.inner.Enabled(ctx, level)
}

// metricsSafe 遏制用户提供的 HandlerMetrics 实现的 panic
// ——与其他所有用户回调相同的遏制措施。
func (h *MetricsHandler) metricsSafe(op string, fn func()) {
	defer func() {
		if p := recover(); p != nil {
			h.errorHandler.Report(&HandlerError{
				Component: "metrics", Operation: op,
				Err: fmt.Errorf("HandlerMetrics panic recovered: %v", p),
			})
		}
	}()
	fn()
}

// reportDropped 呈现内层链的丢弃记录增量。
func (h *MetricsHandler) reportDropped() {
	dc := h.drops.resolve(h.inner)
	cur := dc.Dropped()
	for {
		last := h.drops.last.Load()
		if cur <= last {
			return
		}
		if h.drops.last.CompareAndSwap(last, cur) {
			delta := cur - last
			h.metricsSafe("dropped", func() { h.metrics.IncDroppedN(h.handlerName, delta) })
			return
		}
	}
}

// Handle 实现 slog.Handler。
func (h *MetricsHandler) Handle(ctx context.Context, r slog.Record) error {
	start := time.Now()
	err := h.inner.Handle(ctx, r)
	d := time.Since(start)
	h.metricsSafe("observe", func() { h.metrics.ObserveHandle(d) })
	if err != nil {
		h.metricsSafe("error", func() { h.metrics.IncError(h.handlerName) })
	}
	h.reportDropped()
	return err
}

// WithAttrs 实现 slog.Handler。
func (h *MetricsHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &MetricsHandler{
		inner:        h.inner.WithAttrs(attrs),
		metrics:      h.metrics,
		handlerName:  h.handlerName,
		drops:        h.drops,
		errorHandler: h.errorHandler,
	}
}

// WithGroup 实现 slog.Handler。
func (h *MetricsHandler) WithGroup(name string) slog.Handler {
	return &MetricsHandler{
		inner:        h.inner.WithGroup(name),
		metrics:      h.metrics,
		handlerName:  h.handlerName,
		drops:        h.drops,
		errorHandler: h.errorHandler,
	}
}

func (h *MetricsHandler) unwrapHandler() slog.Handler {
	return h.inner
}

func (h *MetricsHandler) setErrorHandler(fn ErrorHandler) {
	h.errorHandler.Store(fn)
	// propagateErrorHandler 也会经 unwrapHandler 递归触达 inner。
}

var (
	_ slog.Handler     = (*MetricsHandler)(nil)
	_ handlerUnwrapper = (*MetricsHandler)(nil)
)
