package mebsuta

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/iuboy/mebsuta/internal/handlerkit"
)

// SelfBufferedHandler 是自带异步缓冲的 handler 的标记接口。把这类
// handler 包进 AsyncHandler 会造成双重缓冲，在构造时即被拒绝。
type SelfBufferedHandler interface {
	SelfBuffered()
}

// asyncRecord 是 slog.Record 的异步副本。
// slog.Record 的 Attrs 只能迭代一次；必须在 Handle 中同步拷贝。
type asyncRecord struct {
	Time    time.Time
	Level   slog.Level
	Message string
	PC      uintptr
	Attrs   []slog.Attr
	inner   slog.Handler
	ctx     context.Context
}

// AsyncHandler 把日志写入委托给后台 goroutine。
// 不要包裹 syslog.Handler 或 database.Handler——它们自带异步机制。
type AsyncHandler struct {
	handlerCore
	inner        slog.Handler
	errorTimeout time.Duration
	ch           chan asyncRecord
	sendMu       sync.RWMutex // channel 发送期间 RLock；Close 的 close(ch) 期间 Lock
	wg           sync.WaitGroup
	ctx          context.Context
	cancel       context.CancelFunc
	closed       atomic.Bool
	dropped      atomic.Int64
	dropGate     handlerkit.RateGate // 丢弃上报限流：每秒至多一次，携带累计数
	// processErrors 统计内层 handler 的 Handle 失败次数；errGate
	// 把它们的上报限制为每秒一次（见 shouldReportProcessError）。
	processErrors atomic.Int64
	errGate       handlerkit.RateGate // 处理错误上报限流（与 dropGate 独立）
	errorHandler  *handlerkit.ErrorSlot
}

// findSelfBuffered 检查 handler 图中是否含 SelfBufferedHandler,经
// walkHandlers 统一口径(unwrap 链 + fanout 展开 + 去重 + 深度上限)。
// fanout 内的自缓冲 handler(如多输出里混着 database/syslog handler)
// 同样会被发现——把这类链包进 AsyncHandler 正是双重缓冲检测要拦截
// 的形态。
func findSelfBuffered(h slog.Handler) bool {
	found := false
	_ = walkHandlers(h, func(x slog.Handler) error {
		if _, ok := x.(SelfBufferedHandler); ok {
			found = true
			return errStopWalk
		}
		return nil
	})
	return found
}

// WithAsync 把 inner 包进 AsyncHandler：缓冲记录并由后台 goroutine 写出。
func WithAsync(inner slog.Handler, cfg AsyncConfig) slog.Handler {
	if inner == nil {
		return inner
	}
	if findSelfBuffered(inner) {
		handlerkit.ReportError(DefaultErrorHandler, &HandlerError{Component: "async", Operation: "init", Err: fmt.Errorf("WithAsync: wrapping %T creates double-buffering; returning inner handler directly", inner)})
		return inner
	}
	cfg, err := cfg.Validate() // 应用 ErrorTimeout 默认值，限定 BufferSize 上界
	if err != nil {
		// 直接调用 WithAsync 的调用方没有错误返回：上报配置错误并钳制，
		// 而不是分配超限缓冲。New(UseAsync(...)) 路径已在 UseAsync 中
		// 以同一个 *ConfigError 快速失败。
		handlerkit.ReportError(DefaultErrorHandler, &HandlerError{Component: "async", Operation: "init", Err: err})
		cfg.BufferSize = MaxAsyncBufferSize
	}
	bufferSize := cfg.BufferSize
	if bufferSize <= 0 {
		bufferSize = DefaultAsyncBufferSize
	}

	ctx, cancel := context.WithCancel(context.Background())

	h := &AsyncHandler{
		handlerCore:  newHandlerCore(),
		inner:        inner,
		errorTimeout: cfg.ErrorTimeout,
		ch:           make(chan asyncRecord, bufferSize),
		ctx:          ctx,
		cancel:       cancel,
		errorHandler: handlerkit.NewErrorSlot(DefaultErrorHandler),
	}
	h.wg.Add(1)
	go h.run()
	return h
}

// Enabled 实现 slog.Handler。
func (h *AsyncHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.inner.Enabled(ctx, level)
}

// Handle 实现 slog.Handler。
func (h *AsyncHandler) Handle(ctx context.Context, r slog.Record) error {
	if h.closed.Load() {
		h.dropped.Add(1)
		return fmt.Errorf("async handler is closed, log dropped")
	}
	return h.enqueueSnapshot(ctx, r, h.inner)
}

// enqueueSnapshot 剥离取消信号、物化属性快照并入队。AsyncHandler.Handle
// 与 asyncGroupHandler.Handle 共用：前者直接快照原记录，后者先经
// RecordWithGroupAttrs 应用 group 前缀与预设属性再快照。
func (h *AsyncHandler) enqueueSnapshot(ctx context.Context, r slog.Record, inner slog.Handler) error {
	// 剥离取消信号但保留值：记录可能比请求活得久（在 Close 的排空期
	// 间被缓冲），已取消的请求 ctx 会让感知 ctx 的内层 handler 丢弃
	// 最后的刷写。值被保留，因此源自 ctx 的属性仍然有效。永不可取消
	// 的 context（Done() == nil，如 Background）跳过包装——否则只是
	// 每条记录一次无意义的分配。
	if ctx.Done() != nil {
		ctx = context.WithoutCancel(ctx)
	}
	ar := asyncRecord{
		Time:    r.Time,
		Level:   r.Level,
		Message: r.Message,
		PC:      r.PC,
		inner:   inner,
		ctx:     ctx,
	}
	if n := r.NumAttrs(); n > 0 {
		// 预设副本容量：单靠 append 会在切片增长时反复扩容。
		ar.Attrs = make([]slog.Attr, 0, n)
	}
	r.Attrs(func(attr slog.Attr) bool {
		ar.Attrs = append(ar.Attrs, snapshotAsyncAttr(attr))
		return true
	})
	return h.sendRecordInner(ar)
}

// snapshotAsyncAttr 返回 attr，其中调用方拥有的可变内存已被拷贝。
// 持有 []byte 的 slog.Any 值会别名引用调用方的缓冲；记录可能比日志
// 调用活得久（缓冲至 Close 的排空期），复用字节切片的调用方（如池化
// 读缓冲）会在事后破坏已入队的记录。拷贝可堵住该漏洞。其他 KindAny
// 载荷（map、结构体、嵌套切片）仍是别名引用——在热路径上做完整深拷
// 贝超出了范围；持有这类值的调用方应在记录日志前通过 LogValuer 或
// 显式克隆做快照。
func snapshotAsyncAttr(attr slog.Attr) slog.Attr {
	attr.Value = attr.Value.Resolve()
	if attr.Value.Kind() != slog.KindAny {
		return attr
	}
	b, ok := attr.Value.Any().([]byte)
	if !ok {
		return attr
	}
	cp := make([]byte, len(b))
	copy(cp, b)
	attr.Value = slog.AnyValue(cp)
	return attr
}

// shouldReportDrop 判断是否应立即上报丢弃（每秒至多一次，携带累计数）。
// 若无限流，缓冲溢出的洪峰会为每条丢弃记录触发一次带锁 stderr 写入
// ——对攻击流量的 1:1 放大。
func (h *AsyncHandler) shouldReportDrop() int64 {
	if !h.dropGate.Allow() {
		return 0
	}
	return h.dropped.Load()
}

func (h *AsyncHandler) sendRecordInner(ar asyncRecord) error {
	// sendMu 与 database.Handler 一致：发送持读锁（可并发），Close 在
	// close(ch) 周围持写锁。这让 close 与发送的竞争对 race 检测器干净，
	// 无需依赖 recover——只要任一发送者持有读锁，Close 就无法关闭
	// channel，向已关闭 channel 发送的 panic 在结构上不可能发生。
	h.sendMu.RLock()
	report, err := h.enqueueLocked(ar)
	h.sendMu.RUnlock()

	// 在锁外上报——与 filerotate.Writer 轮转错误（M4）相同的纪律：
	// 若 ErrorHandler 重入本 handler（如 Close，或把被上报的错误经同一
	// 条链记录日志），会与回调期间仍持有的读锁死锁。
	if report != nil {
		h.errorHandler.Report(report)
	}
	return err
}

// enqueueLocked 在 sendMu 读锁持有期间执行 channel 发送。
// 错误上报从不在行内发出：而是返回给调用方，由其在释放锁后分发。
func (h *AsyncHandler) enqueueLocked(ar asyncRecord) (*HandlerError, error) {
	if h.closed.Load() {
		h.dropped.Add(1)
		return nil, fmt.Errorf("async handler is closed, log dropped")
	}

	// Error 与 Audit（LevelAudit > LevelError）记录：阻塞发送，受
	// ErrorTimeout 限定。其他级别用非阻塞发送，缓冲满即丢弃。
	if ar.Level >= slog.LevelError {
		// 先尝试非阻塞发送，避免常见路径上的定时器分配。
		select {
		case h.ch <- ar:
			return nil, nil
		case <-h.ctx.Done():
			return nil, fmt.Errorf("async handler is closed, log dropped")
		default:
		}

		timer := time.NewTimer(h.errorTimeout)
		defer timer.Stop()
		select {
		case h.ch <- ar:
			return nil, nil
		case <-h.ctx.Done():
			return nil, fmt.Errorf("async handler is closed, log dropped")
		case <-timer.C:
			h.dropped.Add(1)
			err := fmt.Errorf("mebsuta: buffer full timeout for %v record after %v, dropped (total: %d)", ar.Level, h.errorTimeout, h.dropped.Load())
			if total := h.shouldReportDrop(); total > 0 {
				return &HandlerError{Component: "async", Operation: "process", Err: err, Dropped: total}, err
			}
			return nil, err
		}
	}

	select {
	case h.ch <- ar:
		return nil, nil
	case <-h.ctx.Done():
		return nil, fmt.Errorf("async handler is closed, log dropped")
	default:
		h.dropped.Add(1)
		if total := h.shouldReportDrop(); total > 0 {
			return &HandlerError{Component: "async", Operation: "send", Err: fmt.Errorf("buffer full, log dropped (total dropped: %d)", total), Dropped: total}, nil
		}
		return nil, nil
	}
}

// WithAttrs 实现 slog.Handler。
func (h *AsyncHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &asyncAttrsHandler{
		AsyncHandler: h,
		attrs:        attrs,
	}
}

// WithGroup 实现 slog.Handler。
func (h *AsyncHandler) WithGroup(name string) slog.Handler {
	return &asyncGroupHandler{
		AsyncHandler: h,
		group:        name,
		groupInner:   h.inner.WithGroup(name),
	}
}

// Close 实现 io.Closer。
//
// 先排空再取消：close(ch) 让 run() 处理每条已缓冲记录，wg.Wait() 在
// 最终写完成后才返回。早先 cancel() 优先的顺序会让感知 ctx 的内层
// handler 在排空期间看到已取消的 context 而丢弃最后一批。sendMu
// （close(ch) 周围持写锁）保证没有在途发送者会撞上已关闭的 channel，
// 因此排空起点与 database.Handler 一样对 race 检测器干净。
//
// 在 CAS 竞争中落败的 Close（并发的第二次 Close）仍会等待 wg：契约
// 是 Close 只在它之前接受的每条记录都被刷写后才返回，因此落败者在
// 胜者的排空仍在进行时不得返回。worker 退出后 wg.Wait 是幂等的，
// cancel 也容忍重复调用，两条路径收敛于同一收尾。
func (h *AsyncHandler) Close() error {
	if h.closed.CompareAndSwap(false, true) {
		h.sendMu.Lock()
		close(h.ch) // 安全：写锁排除所有在途发送者
		h.sendMu.Unlock()
	}
	h.wg.Wait()
	h.cancel()
	return nil
}

func (h *AsyncHandler) setErrorHandler(fn ErrorHandler) {
	h.errorHandler.Store(fn)
}

func (h *AsyncHandler) unwrapHandler() slog.Handler {
	return h.inner
}

// Dropped 返回因缓冲溢出而丢弃的记录总数。
func (h *AsyncHandler) Dropped() int64 {
	return h.dropped.Load()
}

func (h *AsyncHandler) run() {
	defer h.wg.Done()
	for ar := range h.ch {
		r := slog.NewRecord(ar.Time, ar.Level, ar.Message, ar.PC)
		r.AddAttrs(ar.Attrs...)
		h.processRecord(ar, r)
	}
}

// processRecord 带 panic 恢复地分发单条记录。safeMulti 的
// handleWithRecovery 只保护同步路径；当用户把第三方 handler 直接包进
// WithAsync 时，内层 panic 不能杀死后台 goroutine（以及整个进程）。
//
// 内层失败与缓冲丢弃同样限流（每秒一次上报，与 shouldReportDrop 同
// 节奏，但用独立的闸）：损坏的内层（磁盘满、连接断）会让每条缓冲
// 记录都失败，每条记录 1:1 上报会把一次突发放大为带锁 stderr 写入
// 风暴。该 goroutine 不持锁，上报天然在 sendMu 之外。
func (h *AsyncHandler) processRecord(ar asyncRecord, r slog.Record) {
	err := h.handleInner(ar, r)
	if err == nil {
		return
	}
	if total := h.shouldReportProcessError(); total > 0 {
		h.errorHandler.Report(&HandlerError{
			Component: "async",
			Operation: "process",
			Err:       fmt.Errorf("%v (total process errors: %d)", err, total),
		})
	}
}

// shouldReportProcessError 把内层写入失败的上报限制为每秒至多一次，
// 携带累计处理错误数。镜像 shouldReportDrop 但用独立闸（errGate 与
// dropGate 分离）：若混用，缓冲满洪峰会压制用户真正需要看到的内层
// 失败上报（或反过来）。
func (h *AsyncHandler) shouldReportProcessError() int64 {
	total := h.processErrors.Add(1)
	if !h.errGate.Allow() {
		return 0
	}
	return total
}

func (h *AsyncHandler) handleInner(ar asyncRecord, r slog.Record) (err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("inner handler panic recovered: %v", p)
		}
	}()
	return ar.inner.Handle(ar.ctx, r)
}

// asyncAttrsHandler 让预设属性穿越异步边界得以保留。
type asyncAttrsHandler struct {
	*AsyncHandler
	attrs []slog.Attr
}

func (h *asyncAttrsHandler) Handle(ctx context.Context, r slog.Record) error {
	// 克隆而非修改调用方的记录（slog 契约）。fanout 路径可能让多个
	// handler 共享同一条记录；对原始记录 AddAttrs 会把预设属性泄漏
	// 给兄弟 handler。
	grouped := handlerkit.RecordWithGroupAttrs(r, "", h.attrs)
	return h.AsyncHandler.Handle(ctx, grouped)
}

func (h *asyncAttrsHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &asyncAttrsHandler{
		AsyncHandler: h.AsyncHandler,
		attrs:        handlerkit.MergeAttrs(h.attrs, attrs, ""),
	}
}

func (h *asyncAttrsHandler) WithGroup(name string) slog.Handler {
	return &asyncGroupHandler{
		AsyncHandler: h.AsyncHandler,
		group:        name,
		attrs:        h.attrs,
		groupInner:   h.inner.WithGroup(name),
	}
}

// asyncGroupHandler 让预设属性与 group 前缀穿越异步边界得以保留。
type asyncGroupHandler struct {
	*AsyncHandler
	group      string
	attrs      []slog.Attr
	groupInner slog.Handler // 缓存的 WithGroup 结果，避免每次 Handle 分配
}

func (h *asyncGroupHandler) Handle(ctx context.Context, r slog.Record) error {
	if h.closed.Load() {
		h.dropped.Add(1) // 与 AsyncHandler.Handle 对齐：关闭后的丢弃也计数
		return fmt.Errorf("async handler is closed, log dropped")
	}
	// 用 RecordWithGroupAttrs 只给记录属性加 group 前缀，同时把预设
	// 属性（h.attrs）保留在根层级。这符合 slog 契约：在 WithGroup
	// 之前添加的属性不在 group 内。转发给未分组的 inner（h.inner）
	// 而非 h.groupInner，因为 RecordWithGroupAttrs 已手工应用了前缀。
	// 取消剥离与属性快照由共用的 enqueueSnapshot 完成——group 路径
	// 此前转发原始请求 ctx，导致感知 ctx 的内层 handler 丢弃 Close
	// 排空期间入队的记录（正是普通路径修复过的 bug）。
	grouped := handlerkit.RecordWithGroupAttrs(r, h.group, h.attrs)
	return h.AsyncHandler.enqueueSnapshot(ctx, grouped, h.inner)
}

func (h *asyncGroupHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &asyncAttrsHandler{
		AsyncHandler: h.AsyncHandler,
		attrs:        handlerkit.MergeAttrs(h.attrs, attrs, h.group),
	}
}

func (h *asyncGroupHandler) WithGroup(name string) slog.Handler {
	// slog：WithGroup("") 是 no-op——原样返回 h 可避免尾部带点的
	// group（"a" + "" + "." 得到 "a."）。与 AttrsSub/GroupSub 及
	// contractJSONHandler 的先例一致。
	if name == "" {
		return h
	}
	// 拼接到空 group 上不得产生前导带点的 group
	// （"" + "." + name = ".name"）。
	combined := name
	if h.group != "" {
		combined = h.group + "." + name
	}
	return &asyncGroupHandler{
		AsyncHandler: h.AsyncHandler,
		group:        combined,
		attrs:        h.attrs,
		groupInner:   h.inner.WithGroup(combined),
	}
}

// unwrapHandler 返回带 group 前缀的内层 handler，使 CloseAll 能正确
// 穿过 group 层。从 AsyncHandler 继承的 unwrapHandler 返回 h.inner，
// 会跳过 group 包装。
func (h *asyncGroupHandler) unwrapHandler() slog.Handler {
	return h.groupInner
}

// AsyncDropped 从 handler 链中的 AsyncHandler 提取丢弃记录总数。
func AsyncDropped(h slog.Handler) int64 {
	switch v := h.(type) {
	case *AsyncHandler:
		return v.Dropped()
	case *asyncAttrsHandler:
		return v.Dropped()
	case *asyncGroupHandler:
		return v.Dropped()
	default:
		return 0
	}
}

var (
	_ slog.Handler     = (*AsyncHandler)(nil)
	_ slog.Handler     = (*asyncAttrsHandler)(nil)
	_ slog.Handler     = (*asyncGroupHandler)(nil)
	_ io.Closer        = (*AsyncHandler)(nil)
	_ handlerUnwrapper = (*AsyncHandler)(nil)
	_ handlerUnwrapper = (*asyncAttrsHandler)(nil)
	_ handlerUnwrapper = (*asyncGroupHandler)(nil)
)
