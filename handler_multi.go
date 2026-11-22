package mebsuta

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync/atomic"

	"github.com/iuboy/mebsuta/internal/handlerkit"
)

// safeMultiHandler 包裹多个子 handler，为每次调用加上 panic 恢复。防止单个 handler 的 panic 崩溃整条日志调用。
func safeMultiHandler(handlers []slog.Handler, eh ErrorHandler) slog.Handler {
	return &safeMulti{
		handlerCore:  newHandlerCore(),
		handlers:     handlers,
		errorHandler: handlerkit.NewErrorSlot(eh),
	}
}

// safeMulti 把日志记录 fanout 到多个 handler，并带逐 handler 的 panic
// 恢复。errorHandler 是 *handlerkit.ErrorSlot，使
// WithAttrs/WithGroup 产生的克隆共享同一个 ErrorHandler 槽位：在原始
// 或任一克隆上调用 setErrorHandler 对全部可见，且并发换入不会与
// Handle 路径的读取竞争（此前裸 *ErrorHandler 的写/读是数据竞争
// ——logger 构造期间的赋值与并发 Handle 调用相争）。
type safeMulti struct {
	handlerCore
	handlers     []slog.Handler
	errorHandler *handlerkit.ErrorSlot
}

func (h *safeMulti) Close() error {
	// 直接调用路径(不经 CloseAll):以独立去重口径对全部子 handler 走
	// 同一关闭遍历。CloseAll 的路径会跳过 safeMulti 的 Close、由 fanout
	// 下降直接关闭子级(见 closeVisit),两条路径互不叠加。
	var errs []error
	visit := closeVisit(&errs)
	visited := map[uint64]struct{}{}
	for _, hh := range h.handlers {
		_ = walkDepth(hh, visit, visited, 0)
	}
	return errors.Join(errs...)
}

func (h *safeMulti) Enabled(ctx context.Context, level slog.Level) bool {
	for _, hh := range h.handlers {
		if hh.Enabled(ctx, level) {
			return true
		}
	}
	return false
}

// handleWithRecovery 带 panic 恢复地调用 handler.Handle。panic 经错误处理器上报并转换为 nil 错误。
func (h *safeMulti) handleWithRecovery(handler slog.Handler, ctx context.Context, r slog.Record) (err error) {
	defer func() {
		if p := recover(); p != nil {
			h.errorHandler.Report(&HandlerError{Component: "multi", Operation: "handle", Err: fmt.Errorf("handler panic recovered: %v", p)})
			err = nil
		}
	}()
	return handler.Handle(ctx, r)
}

func (h *safeMulti) Handle(ctx context.Context, r slog.Record) error {
	if len(h.handlers) == 1 {
		// 单 handler：直接调用，无 goroutine 开销
		hh := h.handlers[0]
		if !hh.Enabled(ctx, r.Level) {
			return nil
		}
		return h.handleWithRecovery(hh, ctx, r)
	}

	// 多 handler 顺序分发。曾经 4 个及以上启用 handler 走 goroutine
	// fanout，但基准显示每条记录 spawn N 个 goroutine 的调度开销在
	// 10–28µs/op 间波动（顺序路径稳定在 ~2µs）；slog 的设计预期是
	// handler 快速返回，需要解耦慢消费者的链应使用 UseAsync（其后台
	// worker 才是做这件事的正确位置）。顺序调用同时让 errors.Join 的
	// 错误顺序确定。每个 handler 克隆一次记录，防止 slog.Record 内部
	// 的数据竞争。
	var errs []error
	for _, hh := range h.handlers {
		if !hh.Enabled(ctx, r.Level) {
			continue
		}
		if err := h.handleWithRecovery(hh, ctx, r.Clone()); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (h *safeMulti) WithAttrs(attrs []slog.Attr) slog.Handler {
	propagated := make([]slog.Handler, len(h.handlers))
	for i, hh := range h.handlers {
		propagated[i] = hh.WithAttrs(attrs)
	}
	return &safeMulti{
		handlerCore:  newHandlerCore(),
		handlers:     propagated,
		errorHandler: h.errorHandler,
	}
}

func (h *safeMulti) WithGroup(name string) slog.Handler {
	propagated := make([]slog.Handler, len(h.handlers))
	for i, hh := range h.handlers {
		propagated[i] = hh.WithGroup(name)
	}
	return &safeMulti{
		handlerCore:  newHandlerCore(),
		handlers:     propagated,
		errorHandler: h.errorHandler,
	}
}
func (h *safeMulti) setErrorHandler(fn ErrorHandler) {
	h.errorHandler.Store(fn)
	for _, hh := range h.handlers {
		propagateErrorHandler(hh, fn, 0)
	}
}

// errorHandlerSetter 是支持自定义错误处理的 handler 的内部接口。
type errorHandlerSetter interface {
	setErrorHandler(fn ErrorHandler)
}

// ErrorHandlerSetter 是 errorHandlerSetter 的导出形式，供其他包的
// handler（database、syslog、mbta）实现——它们无法实现含未导出方法的
// 接口。该接口出现之前，WithErrorHandler 静默地永远到不了那些子包
// handler。
type ErrorHandlerSetter interface {
	SetErrorHandler(fn ErrorHandler)
}

// propagateErrorHandler 递归展开装饰器链，把 errorHandler 注入所有
// 支持它的 handler。深度受 maxUnwrapDepth 限制，防止自引用的第三方
// unwrapHandler 链在 logger 构造期间栈溢出。
func propagateErrorHandler(h slog.Handler, fn ErrorHandler, depth int) {
	// 跳过 nil：不要覆盖构造时设置的 handler 默认值。
	// buildHandler 不带 WithErrorHandler 调用时 fn 为 nil，每个已用
	// DefaultErrorHandler 初始化的 handler 应保留原值。
	if fn == nil || h == nil || depth > maxUnwrapDepth {
		return
	}
	switch s := h.(type) {
	case errorHandlerSetter:
		s.setErrorHandler(fn)
	case ErrorHandlerSetter:
		s.SetErrorHandler(fn)
	}
	if inner, ok := unwrapOf(h); ok {
		propagateErrorHandler(inner, fn, depth+1)
	}
}

// handlerUnwrapper 是装饰器实现的内部接口，CloseAll 借它递归展开。
// 它只能被根包内的类型满足(未导出方法);跨包装饰器(handlerkit 的
// AttrsSub/GroupSub)实现导出的 UnwrapHandler 方法,经 unwrapOf 统一识别。
type handlerUnwrapper interface {
	unwrapHandler() slog.Handler
}

// CloseAll 递归关闭 handler 及装饰器链中所有实现 io.Closer 的资源。
// 内置 handler 按稳定 id 去重；无论标识如何，环保护均由
// maxUnwrapDepth 保证。
func CloseAll(handler slog.Handler) error {
	var errs []error
	_ = walkHandlers(handler, closeVisit(&errs))
	return errors.Join(errs...)
}

// closeVisit 返回关闭单个节点的 visit 函数:在闭包内收集错误而非中止
// 遍历,使 CloseAll 覆盖全图后一次性 Join。*safeMulti 自身无资源,
// 跳过它的 Close——其子 handler 由 walkHandlers 的 fanout 下降直接
// 关闭(与本遍历共享同一去重口径);safeMulti.Close 仅供不经 CloseAll
// 的直接调用使用,两条路径互不叠加。
func closeVisit(errs *[]error) func(slog.Handler) error {
	return func(h slog.Handler) error {
		if _, ok := h.(*safeMulti); ok {
			return nil
		}
		if closer, ok := h.(io.Closer); ok {
			if err := closer.Close(); err != nil {
				*errs = append(*errs, err)
			}
		}
		return nil
	}
}

// handlerSeq 为每个内置 handler 实例分配唯一且稳定的 id，
// 取代基于指针的身份判定，使关闭路径不再依赖 unsafe.Pointer
// 或接口布局探测。
var handlerSeq atomic.Uint64

// handlerCore 为内置 handler 提供稳定身份，供 CloseAll 去重。
// 嵌入任意具体 handler 类型即可；嵌入的 handlerID 方法即满足
// handlerIdentifier。
type handlerCore struct{ id uint64 }

func newHandlerCore() handlerCore { return handlerCore{id: handlerSeq.Add(1)} }

func (c handlerCore) handlerID() uint64 { return c.id }

// handlerIdentifier 是选择加入 CloseAll 去重的 handler 的内部接口。
// 所有内置 handler 经嵌入 handlerCore 满足它。外部（第三方）handler
// 不实现它：它们不去重，依赖 Close 幂等（标准 io.Closer 契约）。环
// 保护来自 maxUnwrapDepth 而非身份，因此无需 unsafe/reflect 探测。
type handlerIdentifier interface {
	handlerID() uint64
}

// handlerIdentity 返回内置 handler 的稳定 id。有意不提供回退：
// 第三方 handler 不去重。
func handlerIdentity(h slog.Handler) (uint64, bool) {
	if hi, ok := h.(handlerIdentifier); ok {
		return hi.handlerID(), true
	}
	return 0, false
}

// maxUnwrapDepth 限制沿 handlerUnwrapper 链的递归深度，即使 handler 的
// unwrapHandler 自引用也能保证终止。真实装饰器链很浅（<10 层）；
// 64 是宽裕的安全上界。
const maxUnwrapDepth = 64

// unwrapOf 返回装饰器的内层 handler:根包内装饰器经未导出的
// handlerUnwrapper 接口,跨包装饰器(handlerkit.AttrsSub/GroupSub)经
// 导出的 UnwrapHandler 方法。同一 handler 不会同时实现两者。
func unwrapOf(h slog.Handler) (slog.Handler, bool) {
	if uw, ok := h.(handlerUnwrapper); ok {
		return uw.unwrapHandler(), true
	}
	if uw, ok := h.(interface{ UnwrapHandler() slog.Handler }); ok {
		return uw.UnwrapHandler(), true
	}
	return nil, false
}

// errStopWalk 是 walkHandlers 的内部哨兵:visit 返回它时遍历立即正常
// 终止(walkHandlers 返回 nil),供"找到即停"的查找类遍历使用。
var errStopWalk = errors.New("mebsuta: stop walk")

// walkHandlers 以统一口径遍历 handler 图:每个节点先交 visit,再沿
// handlerUnwrapper 装饰器链下行,并展开 *safeMulti 的全部 fanout 子
// handler。内置 handler(handlerIdentifier)按稳定 id 去重;环与超深
// 链由 maxUnwrapDepth 保证终止。visit 返回非哨兵错误时立即中止遍历并
// 原样返回;需要收集全部节点错误的调用方(CloseAll)在 visit 内
// 自行累积。CloseAll、SetLevel、SetFileMaxAge、findSelfBuffered 与
// findDroppedCounter 共用本遍历,新增运维面时在此之上挂 visit 即可。
func walkHandlers(h slog.Handler, visit func(slog.Handler) error) error {
	return walkDepth(h, visit, map[uint64]struct{}{}, 0)
}

// walkDepth 是 walkHandlers 的递归实现。visited 在同一次遍历的所有
// 分支间共享:需要自定义入口的调用方(safeMulti.Close)传入同一 map
// 即共享去重口径。遍历是单 goroutine 的,普通 map 足够。
func walkDepth(h slog.Handler, visit func(slog.Handler) error, visited map[uint64]struct{}, depth int) error {
	// 针对自引用 unwrapHandler 环的硬终止保证,
	// 独立于任何身份/去重逻辑。
	if h == nil || depth > maxUnwrapDepth {
		return nil
	}
	// 内置 handler 按稳定 id 去重。无 handlerIdentifier 的外部
	// handler 不去重;其 Close 必须幂等。
	if id, ok := handlerIdentity(h); ok {
		if _, seen := visited[id]; seen {
			return nil
		}
		visited[id] = struct{}{}
	}
	if err := visit(h); err != nil {
		if err == errStopWalk {
			return nil
		}
		return err
	}
	if inner, ok := unwrapOf(h); ok {
		if err := walkDepth(inner, visit, visited, depth+1); err != nil {
			return err
		}
	}
	if sm, ok := h.(*safeMulti); ok {
		for _, hh := range sm.handlers {
			if err := walkDepth(hh, visit, visited, depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}

var (
	_ slog.Handler = (*safeMulti)(nil)
	_ io.Closer    = (*safeMulti)(nil)
)
