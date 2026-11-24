// Package mbta 提供一个 slog.Handler，通过 MBTA 二进制传输协议将日志
// 记录外发到 mebsuta-forwarder 服务。
package mbta

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	mbtago "github.com/iuboy/mbta-go"
	"github.com/iuboy/mbta-go/core"
	v1 "github.com/iuboy/mbta-go/v1"

	"github.com/iuboy/mebsuta"
	"github.com/iuboy/mebsuta/internal/handlerkit"
)

const (
	defaultBufferSize   = 1000
	defaultFlushPeriod  = 5 * time.Second
	defaultBatchSize    = 100
	defaultMaxRetries   = 3
	defaultRetryDelay   = 1 * time.Second
	defaultCloseTimeout = 5 * time.Second
	maxBufferSize       = 10000
	connectTimeout      = 10 * time.Second

	// maxAttrDepth 限制 recordToSignal 中组展平的递归深度，与
	// attrutil 的深度上限一致。超出后渲染为 "<max-depth>"。
	maxAttrDepth = 16

	// stateReady 与 mbta-go 的 core.StateReady.String() 一致，用于
	// 门控重连尝试。
	stateReady = "READY"

	// 传递给 mbta-go ResultHandler 的 RESULT 级别字符串：
	// corepb.ResultLevel 枚举名加上客户端合成的 "timeout"
	//（internal/protocol 在在途槽位到期且无终态
	// RESULT 时触发）。
	resultLevelRejected = "RESULT_LEVEL_REJECTED"
	resultLevelReleased = "RESULT_LEVEL_RELEASED"
	resultLevelTimeout  = "timeout"

	// defaultFlushTimeout 用于 Flush 以 timeout <= 0 调用时。
	defaultFlushTimeout = 5 * time.Second
)

// connState 是一条已建立的连接：client 与其拨号 context 的取消函数
// 成对持有、成对替换（原子指针）。拨号 context 独立派生自 handler
// 生命周期 ctx——quic-go 从拨号 context 派生连接 context（conn.run
// 监视其 Done），连接存活期间不得取消；替换或关闭该连接时调用
// cancel 拆除底层传输。mbta-go 的 Client 是一次性实例：会话断开后
// 处于关闭态，同一实例再调 Connect 恒报 "single-use; create a new
// instance"——重连必须 Dial 新实例整体换入，这正是 conn 以原子指针
// 持有的原因（tryReconnect 换入、sendBatch/Close 无锁读取）。
type connState struct {
	client *mbtago.Client
	cancel context.CancelFunc
}

// Handler 通过 MBTA 协议将日志记录外发到 mebsuta-forwarder。
// 它实现 slog.Handler、io.Closer 与 mebsuta.SelfBufferedHandler。
type Handler struct {
	level handlerkit.LevelGate
	cfg   Config
	conn  atomic.Pointer[connState]
	// connectMu 串行化 Connect 尝试。mbta-go 的绑定层在单用途
	// 客户端上收敛并发 Connect 的方式是关闭胜者的
	// 连接（应用错误 0x1 "conn closed"）——初始连接仍在途时
	// 触发的重连曾把负载下的每个活跃
	// 会话都杀掉。TryLock 让重入变成 no-op。
	connectMu *sync.Mutex
	// pendingResults 跟踪已写上线但终态 RESULT 尚未到达的 seq
	//（sendBatch 成功 → handleResult 可见）。
	// Close 在发送 CLOSE 前等待该集合：控制流与数据流
	// 没有顺序保证，过早的 CLOSE 帧会让服务端在读完最后一个
	// 数据流 BATCH 前就拆除连接。
	pendingResults sync.Map
	buffer         chan *core.SignalRecord
	sendMu         sync.RWMutex // 缓冲发送期间 RLock；Close 的 close(buffer) 期间 Lock
	flushCh        chan chan struct{}
	wg             sync.WaitGroup
	ctx            context.Context
	cancel         context.CancelFunc
	closing        atomic.Bool
	dropped        atomic.Int64
	attrsDropped   atomic.Int64        // 被 wire-schema 预过滤裁掉的属性条目数
	dropGate       handlerkit.RateGate // 丢弃上报限流：每秒至多一次
	errorHandler   *handlerkit.ErrorSlot
	hostname       string
	// batchSizes 将在途批次的 seq（由 SendBatch 返回）映射到
	// 其携带的记录数，内部结果处理器据此把服务端拒绝
	// 计为丢弃记录。终态 RESULT 到达后
	// 条目即被移除。
	batchSizes sync.Map
}

// NewHandler 创建连接到 cfg 所指定 forwarder 的 Handler。
func NewHandler(cfg Config) (*Handler, error) {
	cfg, err := cfg.Validate()
	if err != nil {
		return nil, fmt.Errorf("mebsuta/mbta: %w", err)
	}

	hostname := sanitizeHostname(cfg.Hostname)
	if hostname == "" {
		hostname = "localhost"
	}

	ctx, cancel := context.WithCancel(context.Background())

	bufferSize := min(cfg.BufferSize, maxBufferSize)

	// 传递完整的 TLS 凭据集。此前只转发 InsecureSkipVerify，
	// CAFile/CertFile/KeyFile/ServerName 静默失效——
	// mTLS / 自定义 CA / SNI 配置沦为 no-op。
	if cfg.InsecureSkipVerify {
		handlerkit.ReportError(mebsuta.DefaultErrorHandler, &mebsuta.HandlerError{Component: "mbta", Operation: "init", Err: fmt.Errorf("TLS certificate verification is disabled (InsecureSkipVerify=true) — connection is vulnerable to man-in-the-middle attacks")})
	}

	h := &Handler{
		level:     handlerkit.NewLevelGate(cfg.Level),
		cfg:       cfg,
		connectMu: &sync.Mutex{},
		buffer:    make(chan *core.SignalRecord, bufferSize),
		flushCh:   make(chan chan struct{}),
		ctx:       ctx,
		cancel:    cancel,
		hostname:  hostname,
	}
	h.errorHandler = handlerkit.NewErrorSlot(mebsuta.DefaultErrorHandler)

	// 拨号：一步完成创建客户端 + 连接。持有 connectMu 与
	// tryReconnect 的串行化配合（同一时刻至多一个 Connect 在飞）。
	h.connectMu.Lock()
	conn, dialErr := h.dial()
	if dialErr != nil {
		h.connectMu.Unlock() // Dial 失败：释放串行锁，让调用方重试路径可再连
		cancel()
		return nil, fmt.Errorf("mebsuta/mbta: %w", dialErr)
	}
	h.connectMu.Unlock() // 连接成功：锁只护「同一时刻至多一个 Connect 在飞」

	// 在客户端唯一的 RESULT 槽位上注册内部结果处理器。
	// 它包装 cfg.OnResult（用户观察 RESULT 的唯一受支持方式
	//——槽位归属裁定见 Config.OnResult），并对服务端拒绝做丢弃
	// 记账，堵上“SendBatch 返回 nil 但服务端拒绝该批次”的
	// 盲区。
	conn.client.SetResultHandler(h.handleResult)
	h.conn.Store(conn)

	h.wg.Add(1)
	go h.processQueue()

	return h, nil
}

// v1Creds 汇总 Config 的 TLS 凭据集（mTLS / 自定义 CA / SNI 全量转发）。
func (h *Handler) v1Creds() v1.ClientCredentials {
	return v1.ClientCredentials{
		CAFile:             h.cfg.CAFile,
		CertFile:           h.cfg.CertFile,
		KeyFile:            h.cfg.KeyFile,
		ServerName:         h.cfg.ServerName,
		InsecureSkipVerify: h.cfg.InsecureSkipVerify,
	}
}

// dial 建立一条新连接（mbtago.Dial 完成 HELLO 握手后返回）。拨号在
// 独立 goroutine 中等待，上界 connectTimeout：拨号 context 经
// WithCancel(h.ctx) 独立派生（连接存活期间保持存活，取消 h.ctx 即
// 沿父子关系拆除连接），connectTimeout 仅限制拨号等待——超时取消
// 拨号 context 中止在途连接。成功时取消函数随 connState 返回，由
// 替换/关闭方负责调用。调用方必须持有 connectMu（NewHandler 与
// tryReconnect 串行化，同一时刻至多一个 Connect 在飞）。
func (h *Handler) dial() (*connState, error) {
	dialCtx, cancel := context.WithCancel(h.ctx)
	type dialResult struct {
		client *mbtago.Client
		err    error
	}
	dialCh := make(chan dialResult, 1)
	go func() {
		c, derr := mbtago.Dial(dialCtx, h.cfg.Server, h.cfg.AgentID, h.cfg.Token, mbtago.Version1,
			mbtago.WithV1Credentials(h.v1Creds()),
			mbtago.WithDrainTimeout(h.cfg.CloseTimeout),
		)
		dialCh <- dialResult{c, derr}
	}()
	select {
	case r := <-dialCh:
		if r.err != nil {
			cancel()
			return nil, r.err
		}
		return &connState{client: r.client, cancel: cancel}, nil
	case <-time.After(connectTimeout):
		cancel() // 中止在途拨号
		return nil, fmt.Errorf("dial timed out after %v", connectTimeout)
	}
}

// Enabled 实现 slog.Handler。
func (h *Handler) Enabled(_ context.Context, level slog.Level) bool {
	return h.level.Enabled(level)
}

// Handle 实现 slog.Handler。
func (h *Handler) Handle(_ context.Context, r slog.Record) error {
	if h.closing.Load() {
		// 统计关闭后被静默丢弃的记录，让损失至少
		// 在指标中可见，而不是不可见的 nil（与 database 一致）。
		h.dropped.Add(1)
		return nil
	}

	record, stats := recordToSignal(r)
	h.reportAttrStats(stats)
	return h.safeSend(record, r.Level)
}

// Close 实现 io.Closer。
//
// 先排空再取消：processQueue 的最终刷新（由关闭的
// channel 触发）使用 h.ctx 发送，而过去先 cancel() 的顺序
// 会让 mbta-go 以 context.Canceled 拒绝发送——在关闭时
// 静默丢弃所有缓冲记录。
func (h *Handler) Close() error {
	if !h.closing.CompareAndSwap(false, true) {
		// 并发的 Close 已接管排空。等待其排空阶段
		// 结束而非提前返回，双 Close 调用方仍能
		// 得到“缓冲已刷新”的保证（processQueue 退出后
		// wg.Wait 是幂等的）。
		h.wg.Wait()
		return nil
	}

	// sendMu 让 close(buffer) 与在途发送无竞争。
	h.sendMu.Lock()
	close(h.buffer)
	h.sendMu.Unlock()

	// 有界排空：最终刷新最多花费 MaxRetries ×（发送 deadline
	// + RetryDelay）——两者都有配置上限——但即使封顶后的最坏情况也可能
	// 超过 CloseTimeout，因此排空本身也有 deadline，剩余部分
	// 被丢弃并上报。
	drained := make(chan struct{})
	go func() {
		h.wg.Wait()
		close(drained)
	}()
	select {
	case <-drained:
	case <-time.After(h.cfg.CloseTimeout):
		h.cancel() // processQueue 经 ctx.Done 退出；sendBatch 以 ctx.Err 中止
		<-drained
		// 排空后再记账，而不是之前：processQueue 已从 channel
		// 取出的记录由 sendBatch 的 ctx 中止分支计数
		//（在途批次），事先对 channel 快照会造成
		// 重复计数。排空后 channel 已关闭且无读者，
		// len() 恰好是从未交接的记录数。
		if remaining := len(h.buffer); remaining > 0 {
			h.dropped.Add(int64(remaining))
			h.reportErr("close", fmt.Errorf("close drain timed out after %v: %d buffered records dropped (in-flight batches counted separately)", h.cfg.CloseTimeout, remaining))
		}
	}
	// 发送 CLOSE 前等待最后批次的 RESULT（见
	// waitResults）：排空的 SendBatch 只代表“已上线”。
	h.waitResults(h.cfg.CloseTimeout)

	h.cancel() // 沿拨号 context 的父子关系拆除当前连接

	if conn := h.conn.Load(); conn != nil {
		return h.closeClientBounded(conn.client)
	}
	return nil
}

// closeClientBounded 最多等待 cfg.CloseTimeout 让 mbta-go 客户端
// 完成优雅关闭。客户端内部排空即使无事可做也可能阻塞 30 秒；
// 无界的 Close 会拖住关闭流程，直到编排器
// SIGKILL 进程（排空同样会丢失）。
func (h *Handler) closeClientBounded(client *mbtago.Client) error {
	done := make(chan error, 1)
	go func() { done <- client.Close() }()
	select {
	case err := <-done:
		return err
	case <-time.After(h.cfg.CloseTimeout):
		return fmt.Errorf("mebsuta/mbta: client close did not finish within %v (graceful drain abandoned; the underlying close continues in the background)", h.cfg.CloseTimeout)
	}
}

// Flush 排空全部缓冲记录，不关闭连接。
func (h *Handler) Flush(timeout time.Duration) error {
	if h.closing.Load() {
		return nil
	}
	if timeout <= 0 {
		timeout = defaultFlushTimeout
	}
	done := make(chan struct{})
	select {
	case h.flushCh <- done:
	case <-time.After(timeout):
		return fmt.Errorf("mebsuta/mbta: flush timeout")
	}
	select {
	case <-done:
		return nil
	case <-time.After(timeout):
		return fmt.Errorf("mebsuta/mbta: flush timeout")
	}
}

// WithAttrs 实现 slog.Handler。

// SetLevel 运行时热调级别（0.1.0-14）。仅当构造期 Level 传入
// *slog.LevelVar 时生效并返回 true；固定级别返回 false（进入
// mebsuta.SetLevel 的 skipped 诚实面）。
func (h *Handler) SetLevel(level slog.Level) bool {
	return h.level.Set(level)
}
func (h *Handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &handlerkit.AttrsSub{Parent: h, Attrs: attrs}
}

// WithGroup 实现 slog.Handler。
func (h *Handler) WithGroup(name string) slog.Handler {
	return &handlerkit.GroupSub{Parent: h, Group: name}
}

// SelfBuffered 标记 Handler 内置异步缓冲。
func (*Handler) SelfBuffered() {}

func (h *Handler) reportErr(op string, err error) {
	h.errorHandler.Report(&mebsuta.HandlerError{Component: "mbta", Operation: op, Err: err})
}

// SetErrorHandler 在运行时更新错误处理器。它实现
// mebsuta.ErrorHandlerSetter，WithErrorHandler 得以传播到本
// handler；此前 SilentErrorHandler 与自定义钩子静默地
// 从未到达 mbta，其错误总是打到 stderr。
// Dropped 返回因缓冲满（或 Close 有界排空期间）而丢弃的
// 记录总数——供 mebsuta.DroppedCounter 探针使用。
func (h *Handler) Dropped() int64 {
	return h.dropped.Load()
}

func (h *Handler) SetErrorHandler(fn mebsuta.ErrorHandler) {
	h.errorHandler.Store(fn)
}

// shouldReportDrop 判断当前是否应上报丢弃：每秒至多一次
// 上报（handlerkit.RateGate），溢出缓冲的洪水才不会被放大成每条
// 丢弃记录一次错误处理器调用。
func (h *Handler) shouldReportDrop() bool {
	return h.dropGate.Allow()
}

func (h *Handler) safeSend(record *core.SignalRecord, level slog.Level) error {
	// sendMu 让 Close 的 close(buffer) 与在途发送无竞争。
	// 上报纪律（与 syslog/filerotate 一致）：持锁期间只构造待上报
	// 的错误文本，RUnlock 之后再投递——重入 Close 的用户
	// ErrorHandler 会取 sendMu 写锁，与仍持有的读锁死锁
	//（0.1.0-24 修复：此前 reportErr 在读锁内直接调用）。
	h.sendMu.RLock()
	sendErr := h.sendLocked(record, level)
	h.sendMu.RUnlock()

	if sendErr != nil && h.shouldReportDrop() {
		h.reportErr("send", sendErr)
	}
	return sendErr
}

// sendLocked 将一条记录入队到缓冲 channel。调用方必须持有
// sendMu.RLock。返回值是需要上报的错误（关门控在 safeSend 锁外做）。
func (h *Handler) sendLocked(record *core.SignalRecord, level slog.Level) error {
	if h.closing.Load() {
		// 在此计数（而非只在 Handle 的提前返回里），因为 closing 可能在
		// Handle 检查与本次检查之间翻转；两条路径互斥，
		// 每条丢弃记录恰好计一次。
		h.dropped.Add(1)
		return fmt.Errorf("mebsuta/mbta: handler closed, log dropped")
	}

	// Error 与 Audit（LevelAudit > LevelError）记录：以
	// ErrorTimeout 为上界的阻塞发送，与异步 handler 一致——先试非阻塞，
	// 健康路径就永不分配 timer，并尊重 ctx 取消，
	// 进行中的 Close 就不能把调用方拖满整个超时。
	if level >= slog.LevelError {
		select {
		case h.buffer <- record:
			return nil
		case <-h.ctx.Done():
			h.dropped.Add(1)
			return fmt.Errorf("mebsuta/mbta: handler stopped, %v record dropped (total dropped: %d)", level, h.dropped.Load())
		default:
		}

		timer := time.NewTimer(h.cfg.ErrorTimeout)
		defer timer.Stop()
		select {
		case h.buffer <- record:
			return nil
		case <-h.ctx.Done():
			h.dropped.Add(1)
			return fmt.Errorf("mebsuta/mbta: handler stopped, %v record dropped (total dropped: %d)", level, h.dropped.Load())
		case <-timer.C:
			h.dropped.Add(1)
			return fmt.Errorf("mebsuta/mbta: buffer full timeout for %v record, dropped (total dropped: %d)", level, h.dropped.Load())
		}
	}

	select {
	case h.buffer <- record:
		return nil
	default:
		h.dropped.Add(1)
		return fmt.Errorf("mebsuta/mbta: buffer full, log dropped (total dropped: %d)", h.dropped.Load())
	}
}

func (h *Handler) processQueue() {
	defer h.wg.Done()

	batch := make([]*core.SignalRecord, 0, h.cfg.BatchSize)
	ticker := time.NewTicker(h.cfg.FlushPeriod)
	defer ticker.Stop()

	flush := func() {
		if len(batch) == 0 {
			return
		}
		h.sendBatch(batch)
		batch = batch[:0]
	}

	for {
		select {
		case record, ok := <-h.buffer:
			if !ok {
				flush()
				return
			}
			batch = append(batch, record)
			if len(batch) >= h.cfg.BatchSize {
				flush()
			}

		case <-ticker.C:
			flush()

		case done := <-h.flushCh:
			flush()
			close(done)

		case <-h.ctx.Done():
			flush()
			return
		}
	}
}

func (h *Handler) sendBatch(records []*core.SignalRecord) {
	// wire-schema 门禁：mbta-go 的 SendBatch 在批次上线后即返回，
	// 不预校验就看不到将被服务端拒绝的批次。
	// recordToSignal 预过滤已满足常见预算；此探测把仍违反
	// schema 的记录（如 nil 记录）剔除，而不是毒化整个批次——
	// 服务端原子性拒绝，一条坏记录会静默丢掉全部。
	resource := core.Resource{
		// mbta-go v0.6.0 移除了按调用传递 tag/source 参数：
		// 元数据现在放在批次 resource 属性中。
		Attributes: map[string]any{
			"host.name": h.hostname,
			"service":   h.cfg.Tag,
			"source":    h.cfg.Source,
		},
	}

	valid := make([]*core.SignalRecord, 0, len(records))
	var firstErr error
	invalid := 0
	for _, rec := range records {
		probe := &core.SignalBatch{Resource: resource, Signals: []*core.SignalRecord{rec}}
		if err := probe.Validate(); err != nil {
			invalid++
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		valid = append(valid, rec)
	}
	if invalid > 0 {
		h.dropped.Add(int64(invalid))
		if h.shouldReportDrop() {
			h.reportErr("validate", fmt.Errorf("%d/%d records failed wire-schema validation and were dropped (total dropped: %d, first error: %v)", invalid, len(records), h.dropped.Load(), firstErr))
		}
	}
	if len(valid) == 0 {
		return
	}

	batch := &core.SignalBatch{
		SchemaURL: "https://mebsuta.dev/schemas/v1/logs",
		Resource:  resource,
		Scope: core.Scope{
			Name:        "mebsuta",
			Version:     "mbta-handler",
			CollectorID: h.cfg.AgentID,
		},
		Signals: valid,
	}

	for attempt := range h.cfg.MaxRetries {
		// 每次尝试都取当前连接：重连成功后下一轮重试即换用新 client。
		cur := h.conn.Load()
		if cur == nil {
			return
		}
		seq, err := cur.client.SendBatch(h.ctx, batch)
		if err == nil {
			// 此处的成功只代表“已写上线”。记下
			// 批次大小，handleResult 便能在服务端终态
			// RESULT 报告 rejected/released 时把记录数计回，
			// 并把 seq 登记为 pending，Close 便能在拆除连接前
			// 等待终态 RESULT。
			h.trackBatchSize(seq, len(valid))
			h.pendingResults.Store(seq, struct{}{})
			return
		}

		// 以 context 而非 closing 标志门控：Close 最终
		// 刷新期间 ctx 存活，重试必须继续；而 cancel()
		//（严格发生在排空结束之后）必须中止它们。
		if h.ctx.Err() != nil {
			h.dropped.Add(int64(len(valid)))
			if h.shouldReportDrop() {
				h.reportErr("send_batch", fmt.Errorf("handler stopped, %d records dropped (total dropped: %d)", len(valid), h.dropped.Load()))
			}
			return
		}

		h.reportErr("send_batch", fmt.Errorf("attempt %d/%d: %w", attempt+1, h.cfg.MaxRetries, err))

		if attempt < h.cfg.MaxRetries-1 {
			// Config.Reconnect：会话脱离 READY 时重新
			// 拨号。mbta-go 从不自行重连——没有它，
			// handler 会持续失败每个批次直到进程重启。
			// 状态取自刚刚失败的 client（cur）。
			if h.reconnectEnabled() && cur.client.State() != stateReady {
				h.tryReconnect()
			}
			select {
			case <-time.After(h.cfg.RetryDelay):
			case <-h.ctx.Done():
				h.dropped.Add(int64(len(valid)))
				if h.shouldReportDrop() {
					h.reportErr("send_batch", fmt.Errorf("handler stopped, %d records dropped (total dropped: %d)", len(valid), h.dropped.Load()))
				}
				return
			}
		}
	}

	h.dropped.Add(int64(len(valid)))
	if h.shouldReportDrop() {
		h.reportErr("send_batch", fmt.Errorf("failed after %d attempts, %d records dropped (total dropped: %d)", h.cfg.MaxRetries, len(valid), h.dropped.Load()))
	}
}

// trackBatchSize 记录一个成功写上线的批次携带的记录数。
func (h *Handler) trackBatchSize(seq uint64, n int) {
	if seq == 0 || n <= 0 {
		return
	}
	h.batchSizes.Store(seq, n)
}

// pendingCount 报告已写上线、仍在等待 RESULT 的 seq 数。
func (h *Handler) pendingCount() int {
	n := 0
	h.pendingResults.Range(func(_, _ any) bool {
		n++
		return true
	})
	return n
}

// waitResults 最多阻塞 window，等所有已写上线的 seq 收到
// RESULT 后 Close 才发送 CLOSE 帧。控制流与数据流
// 没有跨流顺序：不等待的话服务端可能先处理 CLOSE
// 并在最后一个数据流 BATCH 被读取前拆除连接，
// 静默丢弃最后一批缓冲记录。以 window 为上界
// （复用 CloseTimeout 作为预算）；丢失的 RESULT（连接已死）超时后
// 继续执行——丢弃已由 result 超时路径计数。
func (h *Handler) waitResults(window time.Duration) {
	if h.pendingCount() == 0 {
		return
	}
	deadline := time.Now().Add(window)
	for h.pendingCount() > 0 {
		if time.Now().After(deadline) {
			left := h.pendingCount()
			h.reportErr("close", fmt.Errorf("close result-wait timed out after %v: %d batch(es) without terminal RESULT", window, left))
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// takeBatchSize 取出并返回 seq 对应的跟踪记录数（未知时为 0，
// 例如非本 handler 写入的批次的通知）。
func (h *Handler) takeBatchSize(seq uint64) int {
	v, ok := h.batchSizes.LoadAndDelete(seq)
	if !ok {
		return 0
	}
	n, _ := v.(int)
	return n
}

// handleResult 是构造时注册在客户端
// 唯一槽位上的内部 RESULT 回调。它包装用户的 Config.OnResult：
// 委托之前，先把服务端的拒绝/释放折算进 Dropped 并做限频
// 上报——没有它，通过了 SendBatch fire-and-forget
// 返回的批次会无声消失。
//
// 运行在 mbta-go 的串行 result worker 上（在那里是 panic 安全的），
// 绝不在日志热路径上。
func (h *Handler) handleResult(seq uint64, level string, code uint32, correlation string) {
	// 任何 RESULT（终态或中间态）都证明服务端看到了该批次：
	// 先从 Close 的等待集合中释放 seq。
	h.pendingResults.Delete(seq)
	// 只有终态才消费批次大小：ACK_MODE_DURABLE 下 ACCEPTED 先到、
	// RELEASED 等终态后到——此前对每个 RESULT 都 LoadAndDelete，
	// 中间态把大小取走，终态看到 0，释放的批次从不被计数
	//（0.1.0-24 修复）。
	switch level {
	case resultLevelRejected, resultLevelReleased, resultLevelTimeout:
		// 重试循环看不到的终态损失（SendBatch 已
		// 返回 nil）。"timeout" 是 mbta-go 合成的 released：
		// 在途槽位到期且无终态，而我们在 result
		// 层从不重发，两种情况下批次都不可挽回。
		if n := h.takeBatchSize(seq); n > 0 {
			h.dropped.Add(int64(n))
			if h.shouldReportDrop() {
				h.reportErr("result", fmt.Errorf("server terminal result %s (code %d) for seq %d: %d records dropped (total dropped: %d)", level, code, seq, n, h.dropped.Load()))
			}
		}
	}
	if h.cfg.OnResult != nil {
		h.cfg.OnResult(seq, level, code, correlation)
	}
}

func (h *Handler) reconnectEnabled() bool {
	return h.cfg.Reconnect != nil && *h.cfg.Reconnect
}

// tryReconnect 重新拨号并整体替换失效连接。mbta-go 的 Client 是
// 一次性实例：会话断开后处于关闭态，同一实例再调 Connect 恒报
// "single-use; create a new instance"——对旧实例重连永远不会成功
// （断线后每个批次都失败直到进程重启，0.1.0-22 修复），必须 Dial
// 新实例换入。成功后旧连接被拆除并有界关闭（retireConn）。失败
// 上报后吞掉——由重试循环决定是否继续。另一个拨号在飞时
// connectMu.TryLock 会跳过：在途尝试要么到达 READY（无事可做）
// 要么失败，下一轮重试再触发。并发的第二个 Connect 会触发
// mbta-go 绑定层的双连接收敛，关闭活跃会话。
func (h *Handler) tryReconnect() {
	if h.ctx.Err() != nil || h.closing.Load() {
		return
	}
	if !h.connectMu.TryLock() {
		return
	}
	defer h.connectMu.Unlock()

	conn, err := h.dial()
	if err != nil {
		h.reportErr("reconnect", fmt.Errorf("reconnect failed: %w", err))
		return
	}
	conn.client.SetResultHandler(h.handleResult)
	if old := h.conn.Swap(conn); old != nil {
		h.retireConn(old)
	}
}

// retireConn 拆除并关闭被替换的旧连接：先取消其拨号 context
// （沿父子关系拆传输），再有界等待优雅关闭。超时则放弃等待——
// 底层关闭在后台继续，不拖住重连路径。
func (h *Handler) retireConn(old *connState) {
	old.cancel()
	done := make(chan error, 1)
	go func() { done <- old.client.Close() }()
	select {
	case err := <-done:
		if err != nil {
			h.reportErr("reconnect", fmt.Errorf("close replaced client: %w", err))
		}
	case <-time.After(h.cfg.CloseTimeout):
	}
}

// attrStats 报告 recordToSignal 的 wire-schema 预过滤对记录
// 属性做了什么。消费侧对 SignalBatch 做原子校验
// （core.SignalBatch.Validate；由 forwarder 的 sink 强制——mbta-go
// 服务端自身仅在入口检查批次信封），因此一条
// 超预算记录会让整个批次在那里被拒——
// 预过滤提前让每条记录都在服务端预算内，
// 并报告不得不裁掉的内容。
type attrStats struct {
	// droppedAttrs 统计因记录已有 core.MaxSignalAttrs 条
	//（mbta-go 的单记录上限）而被跳过的叶子条目数。
	droppedAttrs int
	// truncatedKeys 统计被截短到 core.MaxSignalAttrKeyLen
	//（在 UTF-8 rune 边界截断，与 attrutil 一致）的键数。
	truncatedKeys int
	// sanitizedKeys 统计严格控制字符（与 mbta-go 的
	// hasStrictControlChars 一致：< 0x20 或 0x7f）被替换为 '_' 的键数。
	sanitizedKeys int
}

// any 报告预过滤是否进行了干预。
func (s attrStats) any() bool {
	return s.droppedAttrs > 0 || s.truncatedKeys > 0 || s.sanitizedKeys > 0
}

// reportAttrStats 每秒至多暴露一次预过滤干预
// （共享 shouldReportDrop 门控），属性洪水才不会被放大成
// 每条记录一次错误处理器调用。
func (h *Handler) reportAttrStats(stats attrStats) {
	if !stats.any() {
		return
	}
	h.attrsDropped.Add(int64(stats.droppedAttrs))
	if h.shouldReportDrop() {
		h.reportErr("attrs", fmt.Errorf("record attributes outside server schema were pre-filtered: %d entries dropped, %d keys truncated, %d keys sanitized (attrs dropped total: %d)", stats.droppedAttrs, stats.truncatedKeys, stats.sanitizedKeys, h.attrsDropped.Load()))
	}
}

// recordToSignal 将 slog.Record 转换为 core.SignalRecord。
//
// 组被展平为点号连接的键（"request.method" 而非
// 嵌套 map）：mbta-go 的 proto 编解码器对属性值没有 map 表示，
// 会退化为 fmt.Sprintf("%v")，把嵌套 map 渲染成
// 不稳定的内部表示。叶子值保留 attrValue 的标量
// 转换（LogValuer 解析、深度上限标记）。
func recordToSignal(r slog.Record) (*core.SignalRecord, attrStats) {
	attrs := make(map[string]any)
	var stats attrStats
	r.Attrs(func(attr slog.Attr) bool {
		flattenAttr(attrs, "", attr, 0, &stats)
		return true
	})

	// 规范文本映射唯一来源(B7):AUDIT 此前内联判断,现与根包 JSON/
	// console/otlp/syslog 同源。
	severityText := mebsuta.LevelName(r.Level)

	// 日志热路径绝不 panic。uuid.NewV7 只有在系统
	// PRNG 不可用时才会失败；此时回退为从记录时间戳派生的确定性、
	// 抗碰撞 ID，而不是让调用方的 slog.Info
	// 崩溃。
	eventID := newEventID(r.Time.UnixNano())

	return &core.SignalRecord{
		SignalType:     "log",
		EventID:        eventID,
		TimeUnixNs:     r.Time.UnixNano(),
		ObservedTimeNs: time.Now().UnixNano(),
		SeverityText:   severityText,
		SeverityNumber: mebsuta.SeverityNumber(r.Level),
		Body:           r.Message,
		Attributes:     attrs,
	}, stats
}

// flattenAttr 以点号连接的组键把 attr 展平进 out，形状与
// attrutil 的展平一致（跳过空键以免产生 "prefix." 垃圾键，
// 条数以 core.MaxSignalAttrs 为上限），叶子值保留
// attrValue 的标量转换。
//
// slog 契约：handler 必须在转换前解析 LogValuer 值。
// 未解析的值会把底层结构体泄漏进编码器，
// 经 fmt 渲染成 Go 内部表示（或指针地址）。
func flattenAttr(out map[string]any, prefix string, attr slog.Attr, depth int, stats *attrStats) {
	key := attr.Key
	if prefix != "" {
		key = prefix + "." + attr.Key
	}
	v := attr.Value.Resolve()
	if v.Kind() == slog.KindGroup {
		if depth >= maxAttrDepth {
			// 与旧 attrValue 对超深值使用的标记相同，
			// 下游可区分“嵌套超限”与
			// 缺值。
			setAttrLeaf(out, key, "<max-depth>", stats)
			return
		}
		for _, a := range v.Group() {
			if a.Key == "" {
				// 拼接前跳过，组下的空子键才不会产生
				// "prefix." 这类尾点键。
				continue
			}
			flattenAttr(out, key, a, depth+1, stats)
		}
		return
	}
	setAttrLeaf(out, key, attrValue(v), stats)
}

// attrValue 将已解析、非组的 slog.Value 转换为其标量
// Go 值（原先内联在 attrValue 中的叶子转换）。
func attrValue(v slog.Value) any {
	return v.Any()
}

// setAttrLeaf 在 key 下插入转换后的叶子值，强制执行服务端的
// 属性预算（条数、键长、严格控制字符）。
func setAttrLeaf(out map[string]any, key string, val any, stats *attrStats) {
	if key == "" {
		return
	}
	if len(out) >= core.MaxSignalAttrs {
		stats.droppedAttrs++
		return
	}
	out[sanitizeAttrKey(key, stats)] = val
}

// sanitizeAttrKey 把一个属性键修整进 mbta-go 的 schema：严格
// 控制字符替换为 '_'（保留键的信息而非丢弃），
// 再在合法 UTF-8 rune 边界截断到 core.MaxSignalAttrKeyLen
// 长度内。
func sanitizeAttrKey(key string, stats *attrStats) string {
	if strings.ContainsFunc(key, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		key = strings.Map(func(r rune) rune {
			if r < 0x20 || r == 0x7f {
				return '_'
			}
			return r
		}, key)
		stats.sanitizedKeys++
	}
	if len(key) > core.MaxSignalAttrKeyLen {
		key = truncateValidUTF8(key, core.MaxSignalAttrKeyLen)
		stats.truncatedKeys++
	}
	return key
}

// truncateValidUTF8 将 s 截到至多 maxLen 字节且不拆散
// 多字节 rune（算法与 attrutil 的未导出辅助函数相同）。
func truncateValidUTF8(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	for maxLen > 0 && !utf8.RuneStart(s[maxLen]) {
		maxLen--
	}
	return s[:maxLen]
}

// sanitizeHostname 将主机名（静态或系统）规约到
// [a-zA-Z0-9.-] 字符集，使其不能把控制字符或其他
// 注入带进 resource 属性。
func sanitizeHostname(static string) string {
	if static == "" {
		static, _ = os.Hostname()
	}
	var b strings.Builder
	b.Grow(len(static))
	for _, r := range static {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
		if b.Len() >= 255 {
			break
		}
	}
	return b.String()
}

// newEventID 返回 UUIDv7 字符串，UUID 生成失败时回退为
// 时间戳派生的 ID，日志路径因此绝不 panic。
func newEventID(fallbackSeed int64) string {
	if id, err := uuid.NewV7(); err == nil {
		return id.String()
	}
	// 兜底：确定性、单调、非零。仅 PRNG 故障时运行的兜底路径
	// 在实际中不可能发生碰撞。
	//
	// 布局遵循 UUIDv7：8-4-4-4-12 十六进制。第 3 组是 "7" + 12 位（版本
	// 7）。第 4 组是 RFC 4122 variant 字段：高半字节是 0x8|2 位
	//（因此以 8/9/a/b 开头），与 12 位数据打包成恰好 4 个
	// 十六进制字符。此前的 "%x%04x" 形式会产生可变宽度的 variant
	// 半字节加 4 个固定字符，形成 5 字符组与
	// 37 字符（非 UUID）字符串。
	seed := uint64(fallbackSeed)
	return fmt.Sprintf("00000000-0000-7%03x-%04x-%012x",
		(seed>>40)&0xfff,           // 第 3 组：版本半字节后的 12 位
		0x8000|((seed>>24)&0x0fff), // 第 4 组：variant 半字节（8）+ 12 位数据
		seed&0xffffffffffff)        // 第 5 组：48 位
}

var (
	_ slog.Handler                = (*Handler)(nil)
	_ io.Closer                   = (*Handler)(nil)
	_ mebsuta.SelfBufferedHandler = (*Handler)(nil)
)

// UseMBTA 是便捷函数，创建 MBTA handler 并返回
// 可用于 mebsuta.New() 的 mebsuta.HandlerOption。
//
// 用法：
//
//	logger, _ := mebsuta.New(
//	    mebsuta.UseStdout(mebsuta.StdoutConfig{}),
//	    mbta.UseMBTA(mbta.Config{Server: "localhost:7400", AgentID: "my-app"}),
//	)
func UseMBTA(cfg Config) (mebsuta.HandlerOption, error) {
	h, err := NewHandler(cfg)
	if err != nil {
		return nil, err
	}
	return mebsuta.WithHandler(h), nil
}
