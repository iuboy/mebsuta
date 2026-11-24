package syslog

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/iuboy/mebsuta"
	"github.com/iuboy/mebsuta/internal/attrutil"
	"github.com/iuboy/mebsuta/internal/handlerkit"
	"github.com/iuboy/mebsuta/internal/textutil"
)

const (
	maxRetries             = 5
	writeTimeout           = 3 * time.Second
	dialerTimeout          = 5 * time.Second
	reconnectCheckInterval = 5 * time.Second // 独立于 RetryDelay，避免频繁唤醒
	maxHostnameLength      = 255
	defaultBufferSize      = 1000
	maxBufferSize          = 10000
	maxMsgSize             = 4 * 1024
	maxReconnectDelay      = 5 * time.Minute
	maxBackoffExp          = 20

	// RFC5424 structured-data 预算。结构化路径直接从记录属性构建 SD
	//（attrutil 的条数/大小上限只作用于 JSON
	// 路径），没有这些边界，单条攻击者可控属性就可能
	// 产出数 MB 的帧。
	maxSDParams     = 128       // 每个 SD-ELEMENT 的 PARAM 数上限
	maxSDNameLen    = 32        // RFC5424：SD-NAME 为 1*32 PRINTUSASCII
	maxSDValueBytes = 4 * 1024  // 单个 PARAM-VALUE
	maxSDBudget     = 32 * 1024 // SD-ELEMENT 总字节数
	// sdMaxGroupDepth 限制 SD 组展平深度；与 attrutil 的 maxFlattenDepth 一致，
	// 自引用的 LogValuer→组链才不会无限递归。
	sdMaxGroupDepth = 16
	// maxMarshalEchoBytes 限制 marshal 失败错误报告中回显的
	// 原始消息长度。无界回显会让单条超长/
	// 病态记录经 ReportError 淹没 stderr
	//（根包 fallbackEntry 以 1024 采用同一思路）。
	maxMarshalEchoBytes = 512
	// sdTruncationMark 是省略标记专用的保留 PARAM-NAME；
	// 清洗后同名用户参数会被跳过（计入计数）。
	sdTruncationMark = "_truncated"
	// rfc5424TimeLayout 是固定 6 位小数的 RFC3339——RFC5424 的
	// TIME-SECFRAC 至多 6 位，RFC3339Nano 会输出到 9 位，
	// 严格的接收端会拒绝该帧。
	rfc5424TimeLayout = "2006-01-02T15:04:05.000000Z07:00"

	// closeDrainTimeout 限制 Close 等待后台队列
	// 刷出缓冲消息的时长，超时即取消并丢弃剩余部分。
	// 若无上限，黑洞对端（每条消息 3s 写超时 ×
	// 10000 条缓冲）可能拖住 Close 数小时。
	closeDrainTimeout = 10 * time.Second

	// defaultFlushTimeout 用于 Flush 以 timeout <= 0 调用时。
	defaultFlushTimeout = 5 * time.Second
)

var spaceRe = regexp.MustCompile(`\s+`)

// Handler 将日志记录写入 syslog 服务，内置缓冲、TLS 支持与自动重连。
type Handler struct {
	level            handlerkit.LevelGate
	cfg              Config
	reconnectEnabled bool // 构造时从 cfg.Reconnect *bool 解析
	conn             net.Conn
	connMu           sync.RWMutex
	dialer           net.Dialer
	tlsCfg           *tls.Config
	hostname         string
	buffer           chan []byte
	sendMu           sync.RWMutex // 缓冲发送期间 RLock；Close 的 close(buffer) 期间 Lock
	// drainDone 由赢得 closing CAS 的那个 Close 在其排空与
	// 连接清理完成后关闭；落败的 Close 在其上等待，因此
	// 第二个 Close 也只在 handler 完全落定后返回。
	// 在 NewHandler 发布前写入一次——无并发访问。
	drainDone      chan struct{}
	flushCh        chan chan struct{}
	wg             sync.WaitGroup
	ctx            context.Context
	cancel         context.CancelFunc
	closing        atomic.Bool
	attrDropWarned atomic.Bool // RFC3164 属性丢弃的一次性告警
	dropped        atomic.Int64
	dropGate       handlerkit.RateGate // 丢弃上报限流：每秒至多一次
	location       *time.Location
	errorHandler   *handlerkit.ErrorSlot
}

// NewHandler 创建连接到 cfg 所指定 syslog 服务的 Handler。
func NewHandler(cfg Config) (*Handler, error) {
	cfg, err := cfg.Validate()
	if err != nil {
		return nil, fmt.Errorf("mebsuta/syslog: %w", err)
	}
	bufferSize := cfg.BufferSize
	if bufferSize <= 0 {
		bufferSize = defaultBufferSize
	} else if bufferSize > maxBufferSize {
		bufferSize = maxBufferSize
	}

	hostname, err := generateHostname(cfg.StaticHost)
	if err != nil {
		return nil, fmt.Errorf("mebsuta/syslog: %w", err)
	}

	loc, err := time.LoadLocation(cfg.TimeZone)
	if err != nil {
		handlerkit.ReportError(mebsuta.DefaultErrorHandler, &mebsuta.HandlerError{Component: "syslog", Operation: "init", Err: fmt.Errorf("invalid timezone %q, using UTC: %w", cfg.TimeZone, err)})
		loc = time.UTC
	}

	ctx, cancel := context.WithCancel(context.Background())

	h := &Handler{
		level:            handlerkit.NewLevelGate(cfg.Level),
		cfg:              cfg,
		reconnectEnabled: cfg.Reconnect != nil && *cfg.Reconnect,
		dialer:           net.Dialer{Timeout: dialerTimeout},
		hostname:         hostname,
		buffer:           make(chan []byte, bufferSize),
		flushCh:          make(chan chan struct{}),
		drainDone:        make(chan struct{}),
		ctx:              ctx,
		cancel:           cancel,
		location:         loc,
	}
	h.errorHandler = handlerkit.NewErrorSlot(mebsuta.DefaultErrorHandler)

	if cfg.Secure {
		h.tlsCfg = &tls.Config{
			InsecureSkipVerify: cfg.TLSSkipVerify,
			MinVersion:         tls.VersionTLS12,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			},
		}
		if cfg.TLSSkipVerify {
			handlerkit.ReportError(mebsuta.DefaultErrorHandler, &mebsuta.HandlerError{Component: "syslog", Operation: "init", Err: fmt.Errorf("TLS certificate verification is disabled (InsecureSkipVerify=true) — connection is vulnerable to man-in-the-middle attacks")})
		}
	}

	if cfg.Network == "udp" {
		handlerkit.ReportError(mebsuta.DefaultErrorHandler, &mebsuta.HandlerError{Component: "syslog", Operation: "init", Err: fmt.Errorf("UDP transport sends logs in plaintext without delivery guarantees — consider using TCP with TLS for production use")})
	}

	if err := h.connect(); err != nil {
		cancel()
		return nil, fmt.Errorf("mebsuta/syslog: initial connection failed: %w", err)
	}

	h.wg.Add(1)
	go h.processQueue()

	return h, nil
}

// Enabled 实现 slog.Handler。
func (h *Handler) Enabled(_ context.Context, level slog.Level) bool {
	return h.level.Enabled(level)
}

// Handle 实现 slog.Handler。
func (h *Handler) Handle(ctx context.Context, r slog.Record) error {
	if h.closing.Load() {
		// 统计关闭后被静默丢弃的记录，让损失至少
		// 在指标中可见，而不是不可见的 nil（与
		// database.Handler 一致）。
		h.dropped.Add(1)
		return nil
	}

	entry := recordToLogEntry(r)
	msg := h.formatMessage(entry)
	data := []byte(msg)
	return h.safeSend(data, r.Level)
}

// Close 实现 io.Closer。
//
// 排空缓冲至多 closeDrainTimeout：黑洞对端让每条
// 缓冲消息付出一次 3s 写超时，无界排空可能
// 阻塞 Close（进而阻塞进程退出）数小时。超时时
// 剩余消息被丢弃并上报。

// SetLevel 运行时热调级别（0.1.0-14）。仅当构造期 Level 传入
// *slog.LevelVar 时生效并返回 true；固定级别返回 false（进入
// mebsuta.SetLevel 的 skipped 诚实面）。
func (h *Handler) SetLevel(level slog.Level) bool {
	return h.level.Set(level)
}
func (h *Handler) Close() error {
	if !h.closing.CompareAndSwap(false, true) {
		// 另一个 Close 正在运行（或已完成）：等待——上界为第一个
		// Close 自身遵守的同一 closeDrainTimeout——而不是在
		// 缓冲可能仍在排空时返回，调用方才能依赖
		// Close 意味着“完全落定”。幂等待：drainDone
		// 恰好由 CAS 胜者关闭一次。零值 Handler
		//（未经 NewHandler 构造）没有 drainDone，也没有可等的
		// 意义，立即返回。
		drainDone := h.drainDone
		if drainDone != nil {
			select {
			case <-drainDone:
			case <-time.After(closeDrainTimeout):
				// 第一个 Close 自持有上界；此分支只是
				// 防止卡死的排空永久阻塞调用方。
			}
		}
		return nil
	}
	if h.drainDone != nil {
		defer close(h.drainDone)
	}

	// sendMu（close 周围的写锁）让 close 与发送在竞争检测器下
	// 干净：没有在途 safeSend 会触碰已关闭的 channel。
	h.sendMu.Lock()
	close(h.buffer)
	h.sendMu.Unlock()

	drained := make(chan struct{})
	go func() {
		h.wg.Wait()
		close(drained)
	}()
	select {
	case <-drained:
	case <-time.After(closeDrainTimeout):
		remaining := len(h.buffer)
		h.cancel() // writeWithRetry 的 ctx 门控让剩余消息成为 no-op
		select {
		case <-drained:
		case <-time.After(closeDrainTimeout):
			// 宽限上界：processQueue 可能卡在用户 ErrorHandler 重入
			// Close 的调用栈里（wg.Wait 等待自身 goroutine），cancel
			// 无法中断它——放弃等待；该调用栈返回后 goroutine 自行
			// 退出，不构成泄漏。此前这里无上界，重入场景会永久挂死
			// 调用方（0.1.0-24 修复）。
		}
		if remaining > 0 {
			h.dropped.Add(int64(remaining))
			h.errorHandler.Report(&mebsuta.HandlerError{Component: "syslog", Operation: "close", Err: fmt.Errorf("close drain timed out after %v: %d buffered records dropped", closeDrainTimeout, remaining), Dropped: int64(remaining)})
		}
	}
	h.cancel()

	h.connMu.Lock()
	if h.conn != nil {
		if err := h.conn.Close(); err != nil {
			h.errorHandler.Report(&mebsuta.HandlerError{Component: "syslog", Operation: "connect", Err: fmt.Errorf("close old connection in connect: %w", err)})
		}
		h.conn = nil
	}
	h.connMu.Unlock()

	return nil
}

// Flush 排空全部缓冲消息，不关闭连接。
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
		return fmt.Errorf("mebsuta/syslog: flush timeout")
	}
	select {
	case <-done:
		return nil
	case <-time.After(timeout):
		return fmt.Errorf("mebsuta/syslog: flush timeout")
	}
}

func (h *Handler) drainBuffer() {
	for {
		select {
		case msg, ok := <-h.buffer:
			if !ok {
				return
			}
			h.writeWithRetry(msg)
		default:
			return
		}
	}
}

// WithAttrs 实现 slog.Handler。
func (h *Handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &handlerkit.AttrsSub{Parent: h, Attrs: attrs}
}

// WithGroup 实现 slog.Handler。
func (h *Handler) WithGroup(name string) slog.Handler {
	return &handlerkit.GroupSub{Parent: h, Group: name}
}

// SetErrorHandler 在运行时更新错误处理器。它实现
// mebsuta.ErrorHandlerSetter，WithErrorHandler 得以传播到本
// handler（仅包内的 setErrorhandler 从其他
// 包无法触达）。
// Dropped 返回因缓冲满（或 Close 有界排空期间）而丢弃的
// 记录总数——供 mebsuta.DroppedCounter 探针使用。
func (h *Handler) Dropped() int64 {
	return h.dropped.Load()
}

func (h *Handler) SetErrorHandler(fn mebsuta.ErrorHandler) {
	h.errorHandler.Store(fn)
}

func (h *Handler) dialLocked() (net.Conn, error) {
	var conn net.Conn
	var err error
	if h.tlsCfg != nil {
		conn, err = tls.DialWithDialer(&h.dialer, h.cfg.Network, h.cfg.Address, h.tlsCfg)
	} else {
		conn, err = h.dialer.Dial(h.cfg.Network, h.cfg.Address)
	}
	if err != nil {
		return nil, err
	}
	if tc, ok := conn.(*net.TCPConn); ok {
		if err := tc.SetKeepAlive(true); err != nil {
			h.errorHandler.Report(&mebsuta.HandlerError{Component: "syslog", Operation: "connect", Err: fmt.Errorf("set keep-alive: %w", err)})
		} else if err := tc.SetKeepAlivePeriod(3 * time.Minute); err != nil {
			h.errorHandler.Report(&mebsuta.HandlerError{Component: "syslog", Operation: "connect", Err: fmt.Errorf("set keep-alive period: %w", err)})
		}
	}
	return conn, nil
}

func (h *Handler) connect() error {
	h.connMu.Lock()
	defer h.connMu.Unlock()

	conn, err := h.dialLocked()
	if err != nil {
		return err
	}

	if h.conn != nil {
		if err := h.conn.Close(); err != nil {
			h.errorHandler.Report(&mebsuta.HandlerError{Component: "syslog", Operation: "connect", Err: fmt.Errorf("close old connection in connect: %w", err)})
		}
	}
	h.conn = conn
	return nil
}

func (h *Handler) reconnect() {
	h.connMu.Lock()
	defer h.connMu.Unlock()
	if h.closing.Load() {
		return
	}

	conn, err := h.dialLocked()
	if err != nil {
		h.errorHandler.Report(&mebsuta.HandlerError{Component: "syslog", Operation: "reconnect", Err: fmt.Errorf("reconnect failed: %w", err)})
		return
	}

	if h.conn != nil {
		if closeErr := h.conn.Close(); closeErr != nil {
			h.errorHandler.Report(&mebsuta.HandlerError{Component: "syslog", Operation: "reconnect", Err: fmt.Errorf("close old connection in reconnect: %w", closeErr)})
		}
	}
	h.conn = conn
}

func (h *Handler) isConnected() bool {
	h.connMu.RLock()
	defer h.connMu.RUnlock()
	return h.conn != nil
}

func (h *Handler) write(p []byte) error {
	h.connMu.RLock()
	defer h.connMu.RUnlock()
	if h.conn == nil {
		return net.ErrClosed
	}
	if err := h.conn.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
		return fmt.Errorf("set write deadline: %w", err)
	}
	_, err := h.conn.Write(p)
	return err
}

// writeWithRetry 带重试写出一条消息。0.1.0-24 起的语义：
//   - 重连失败/关闭（无连接）时立即按丢弃处理——此前剩余重试与
//     RetryDelay 逐条空转，断连时每条记录阻塞约 maxRetries × RetryDelay
//   - 最终失败携带底层原因并计入 Dropped——此前只报尝试次数，网络
//     故障导致的丢失在 Dropped 观测面不可见
//   - 最后一次尝试后不再休眠 RetryDelay
func (h *Handler) writeWithRetry(msg []byte) {
	// context 门控：Close 排空 deadline 触发并取消 ctx 后，
	// 立即跳过剩余消息，而不是每条再付出一次 3s 写
	// 超时——这正是 deadline 之后排空的有界保证。
	if h.ctx.Err() != nil {
		return
	}
	if !h.isConnected() && !h.closing.Load() && h.reconnectEnabled {
		h.reconnect()
	}
	var lastErr error
	for i := range maxRetries {
		lastErr = h.write(msg)
		if lastErr == nil {
			return
		}
		if h.closing.Load() {
			h.dropped.Add(1)
			return
		}
		// 仅在首次失败时断开并重连。后续重试复用同一连接，避免在
		// 瞬时写错误（如未断 TCP 会话的短暂网络抖动）上反复折腾。
		// 重连后仍无连接（Reconnect=false 或重连失败）：继续重试只会
		// 逐条空转 RetryDelay——立即按丢弃处理。
		if i == 0 {
			h.disconnect()
			if h.reconnectEnabled {
				h.reconnect()
			}
			if !h.isConnected() {
				break
			}
		}
		if i == maxRetries-1 {
			break // 最后一次尝试后不再休眠
		}
		// 可中断休眠：Close 排空 deadline 取消 ctx 后，
		// 在途重试不得傻等完整 RetryDelay——否则
		// 10s 的 Close 上界会被 RetryDelay 软化。
		select {
		case <-time.After(h.cfg.RetryDelay):
		case <-h.ctx.Done():
			return
		}
	}
	h.dropped.Add(1)
	if h.shouldReportDrop() {
		// 本上报发生在 worker(processQueue)goroutine 内：用户
		// ErrorHandler 若重入 Close，同步调用会以 wg.Wait 等待本
		// worker 退出而自死锁——只能撞满排空上界(10s)。异步投递后
		// 重入方按 CAS 败者路径立即返回，排空照常完成(0.1.0-24)。
		// 回调顺序不再保证(限频本就每秒至多一次)。goroutine 归属：
		// 一次性上报，生命周期 = 回调自身，无泄漏面。
		he := &mebsuta.HandlerError{Component: "syslog", Operation: "write", Err: fmt.Errorf("write failed after %d attempts: %w (total dropped: %d)", maxRetries, lastErr, h.dropped.Load()), Dropped: h.dropped.Load()}
		go h.errorHandler.Report(he)
	}
}

func (h *Handler) disconnect() {
	h.connMu.Lock()
	defer h.connMu.Unlock()
	if h.conn != nil {
		if err := h.conn.Close(); err != nil {
			h.errorHandler.Report(&mebsuta.HandlerError{Component: "syslog", Operation: "connect", Err: fmt.Errorf("close old connection in connect: %w", err)})
		}
		h.conn = nil
	}
}

func backoffDelay(retries int32) time.Duration {
	r := retries
	if r > maxBackoffExp {
		r = maxBackoffExp
	}
	base := time.Second << min(r, 30)
	base = min(base, maxReconnectDelay)
	jitter := time.Duration(rand.Int64N(int64(base) / 2))
	return base/2 + jitter
}

func (h *Handler) processQueue() {
	defer h.wg.Done()

	reconnector := time.NewTicker(reconnectCheckInterval)
	defer reconnector.Stop()

	var retryCount atomic.Int32

	for {
		select {
		case msg, ok := <-h.buffer:
			if !ok {
				return
			}
			h.writeWithRetry(msg)

		case done := <-h.flushCh:
			h.drainBuffer()
			close(done)

		case <-reconnector.C:
			if !h.isConnected() && h.reconnectEnabled {
				delay := backoffDelay(retryCount.Load())
				select {
				case <-time.After(delay):
				case <-h.ctx.Done():
					return
				case msg, ok := <-h.buffer:
					if !ok {
						return
					}
					h.writeWithRetry(msg)
					continue
				}
				// 重连前复查连接状态以避免 TOCTOU 竞争：
				// writeWithRetry 可能在退避延迟期间已完成重连。
				if !h.isConnected() {
					h.reconnect()
					retryCount.Add(1)
				} else {
					retryCount.Store(0)
				}
			} else {
				retryCount.Store(0)
			}

		case <-h.ctx.Done():
			return
		}
	}
}

// shouldReportDrop 判断当前是否应上报丢弃：每秒至多一次
// 上报（handlerkit.RateGate），溢出缓冲的洪水才不会被放大成每条
// 丢弃记录一次带锁的 stderr 写。调用方总是会计数丢弃。
func (h *Handler) shouldReportDrop() bool {
	return h.dropGate.Allow()
}

func (h *Handler) safeSend(data []byte, level slog.Level) error {
	// sendMu 让 Close 的 close(buffer) 与在途发送无竞争
	//（与 database.Handler 同一模式；recover 防护已不再
	// 需要，且即便捕获了 panic 也曾是 -race 数据竞争）。
	//
	// 错误报告在持锁期间收集，但在 RUnlock 之后投递：
	// 重入 Close 的用户 ErrorHandler 会取
	// sendMu.Lock，与我们自己的 RLock 死锁（与 filerotate 的
	// reportRotateErrors 同一的锁外上报纪律）。
	h.sendMu.RLock()
	if h.closing.Load() {
		h.sendMu.RUnlock()
		return fmt.Errorf("mebsuta/syslog: handler closed, log dropped")
	}
	report, err := h.sendLocked(data, level)
	h.sendMu.RUnlock()

	if report != nil {
		h.errorHandler.Report(report)
	}
	return err
}

// sendLocked 将一个帧入队到缓冲 channel。调用方必须持有
// sendMu.RLock。第一个返回值携带待上报的 HandlerError（若有）；
// 由调用方在释放锁后投递（见 safeSend）。
//
// Error+ 记录获得有界阻塞发送：先非阻塞尝试
// （缓冲有空间的常见路径就不付 timer 分配），再用
// 尊重 ctx 取消的 timer 有界等待——与
// async.Handler 的 Error 发送同构。其他级别从不阻塞。
func (h *Handler) sendLocked(data []byte, level slog.Level) (*mebsuta.HandlerError, error) {
	if level >= slog.LevelError {
		select {
		case h.buffer <- data:
			return nil, nil
		default:
		}

		timer := time.NewTimer(h.cfg.ErrorTimeout)
		defer timer.Stop()
		select {
		case h.buffer <- data:
			return nil, nil
		case <-h.ctx.Done():
			h.dropped.Add(1)
			return nil, fmt.Errorf("mebsuta/syslog: handler closing, %v record dropped", level)
		case <-timer.C:
			h.dropped.Add(1)
			if h.shouldReportDrop() {
				return &mebsuta.HandlerError{Component: "syslog", Operation: "write", Err: fmt.Errorf("buffer full timeout for %v record, dropped (total dropped: %d)", level, h.dropped.Load()), Dropped: h.dropped.Load()}, fmt.Errorf("mebsuta/syslog: buffer full timeout for %v record", level)
			}
			return nil, fmt.Errorf("mebsuta/syslog: buffer full timeout for %v record", level)
		}
	}

	select {
	case h.buffer <- data:
		return nil, nil
	default:
		h.dropped.Add(1)
		if h.shouldReportDrop() {
			return &mebsuta.HandlerError{Component: "syslog", Operation: "write", Err: fmt.Errorf("buffer full, log dropped (total dropped: %d)", h.dropped.Load()), Dropped: h.dropped.Load()}, fmt.Errorf("mebsuta/syslog: buffer full")
		}
		return nil, fmt.Errorf("mebsuta/syslog: buffer full")
	}
}

func (h *Handler) formatMessage(entry logEntry) string {
	timestamp := entry.Time.In(h.location)
	severity := h.levelToSeverity(entry.Level)
	priority := h.cfg.Facility*8 + severity
	procid := os.Getpid()
	host := h.getCleanHost()

	if h.cfg.JSONInMessage {
		return h.formatJSONMessage(entry, timestamp, priority, host, procid)
	}
	return h.formatStructuredMessage(entry, timestamp, priority, host, procid)
}

func (h *Handler) formatJSONMessage(entry logEntry, ts time.Time, priority int, host string, procid int) string {
	attributes := make(map[string]any)
	for _, attr := range entry.Attrs {
		attrutil.FlattenAttr(attributes, "", attr, attrutil.NaNSafe)
	}
	level := entry.Level.String()
	if entry.Level == mebsuta.LevelAudit {
		level = "AUDIT"
	}
	logData := map[string]any{
		"time":       ts.Format(time.RFC3339Nano),
		"level":      level,
		"message":    entry.Message,
		"attributes": attributes,
	}

	jsonBytes, err := json.Marshal(logData)
	if err != nil {
		// 截断回显消息：marshal 失败的记录本身可能
		// 任意大，无界的 %q 回显会把一条
		// 坏记录变成数 MB 的 stderr 写。
		echo := entry.Message
		if len(echo) > maxMarshalEchoBytes {
			echo = textutil.TruncateUTF8(echo, maxMarshalEchoBytes)
		}
		h.errorHandler.Report(&mebsuta.HandlerError{Component: "syslog", Operation: "marshal", Err: fmt.Errorf("marshal log entry (msg=%q, level=%v): %w", echo, entry.Level, err)})
		safeData := map[string]any{
			"time":       logData["time"],
			"level":      logData["level"],
			"message":    entry.Message,
			"attributes": map[string]any{"_error": "field marshaling failed"},
		}
		jsonBytes, _ = json.Marshal(safeData)
	}
	cleaned := string(jsonBytes)
	if len(cleaned) > maxMsgSize {
		cleaned = truncateJSON(cleaned, maxMsgSize)
	}

	if h.cfg.RFC5424 {
		return fmt.Sprintf(`<%d>1 %s %s %s %d - - %s`,
			priority, ts.Format(rfc5424TimeLayout), host, h.cfg.Tag, procid, cleaned) + "\n"
	}
	return fmt.Sprintf(`<%d>%s %s %s[%d]: %s`,
		priority, ts.Format("Jan _2 15:04:05"), host, h.cfg.Tag, procid, cleaned) + "\n"
}

func (h *Handler) formatStructuredMessage(entry logEntry, ts time.Time, priority int, host string, procid int) string {
	msgContent := safeMessageForLog(entry.Message)
	if len(msgContent) > maxMsgSize {
		msgContent = textutil.TruncateUTF8(msgContent, maxMsgSize)
	}

	if h.cfg.RFC5424 {
		var sd strings.Builder
		written, skipped := 0, 0
		if len(entry.Attrs) == 0 {
			sd.WriteByte('-')
		} else {
			sd.WriteString("[mebsuta")
			// 先解析 LogValuer 值并展平 KindGroup 属性，
			// 与 JSON 路径一致（attrutil.FlattenAttr 把组展开
			// 为点号子键并在渲染前解析）。不做
			// Resolve，包在 LogValuer 中的敏感字段（如用于
			// 脱敏）会经 fmt 序列化为内部结构体
			// 表示而非脱敏值。
			params := make([]sdParam, 0, len(entry.Attrs))
			for _, attr := range entry.Attrs {
				collectSDParams(attr, "", 0, &params, &skipped)
			}
			// RFC5424 §6.3.2 要求 SD-ELEMENT 内的 PARAM-NAME
			// 唯一；清洗可能让不同键碰撞（"a/b" 与
			// "a_b" 都变成 "a_b"），严格的接收端会因重复
			// 拒绝整个帧。清洗后去重，落败者计入
			// 截断标记。
			seen := make(map[string]struct{}, len(params))
			for _, p := range params {
				name := sanitizeSDName(p.name)
				if name == "" || name == sdTruncationMark {
					// 截断标记名是保留名，标记本身
					// 绝不会与用户参数冲突。
					skipped++
					continue
				}
				if _, dup := seen[name]; dup {
					skipped++
					continue
				}
				seen[name] = struct{}{}
				// 强制条数与总大小预算：结构化路径
				// 没有 attrutil 上限，无界属性（如原始
				// 请求体）会产出在 UDP 上分片、在接收端
				// 放大内存的帧。大小检查累加该参数转义
				// 后的长度（先转义后截断，全引号值才不会翻倍
				// 越过上限），而非渲染前检查——对渲染前
				// 长度先查后写仍可能让预算
				// 超出一个完整参数。
				value := truncateSDValue(escapeSDValue(p.value), maxSDValueBytes)
				paramLen := len(name) + len(value) + 3 // ' ' + 两个引号
				if written >= maxSDParams || sd.Len()+paramLen > maxSDBudget {
					skipped++
					continue
				}
				fmt.Fprintf(&sd, " %s=\"%s\"", name, value)
				written++
			}
			if skipped > 0 {
				fmt.Fprintf(&sd, " %s=\"%d params omitted\"", sdTruncationMark, skipped)
			}
			sd.WriteByte(']')
		}
		sdStr := sd.String()

		return fmt.Sprintf(`<%d>1 %s %s %s %d - %s %s`,
			priority, ts.Format(rfc5424TimeLayout), host, h.cfg.Tag, procid, sdStr, msgContent) + "\n"
	}

	// RFC3164 没有 structured-data 字段：属性被静默丢弃。
	// 告警一次，让运维察觉，而不是误以为属性已外发。
	if len(entry.Attrs) > 0 && h.attrDropWarned.CompareAndSwap(false, true) {
		h.errorHandler.Report(&mebsuta.HandlerError{Component: "syslog", Operation: "format", Err: fmt.Errorf("RFC3164 non-JSON mode discards attributes (first occurrence; %d attrs on this record) — enable RFC5424 or JSONInMessage to preserve them", len(entry.Attrs))})
	}

	return fmt.Sprintf(`<%d>%s %s %s[%d]: %s`,
		priority, ts.Format("Jan _2 15:04:05"), host, h.cfg.Tag, procid, msgContent) + "\n"
}

func (h *Handler) levelToSeverity(level slog.Level) int {
	switch {
	case level >= mebsuta.LevelAudit:
		return 2
	case level >= slog.LevelError:
		return 3
	case level >= slog.LevelWarn:
		return 4
	case level >= slog.LevelInfo:
		return 6
	default:
		return 7
	}
}

func (h *Handler) getCleanHost() string {
	return h.hostname // 已在 generateHostname 中清洗并校验
}

func generateHostname(static string) (string, error) {
	if static != "" {
		static = strings.TrimSpace(static)
		static = cleanHostname(static)
		if static == "" {
			return "", fmt.Errorf("invalid static hostname")
		}
		if len(static) > maxHostnameLength {
			static = static[:maxHostnameLength]
		}
		return static, nil
	}
	hostname, err := os.Hostname()
	if err != nil {
		handlerkit.ReportError(mebsuta.DefaultErrorHandler, &mebsuta.HandlerError{Component: "syslog", Operation: "init", Err: fmt.Errorf("get hostname: %w", err)})
		return "unknown", nil
	}
	hostname = cleanHostname(hostname)
	if hostname == "" {
		return "localhost", nil
	}
	if len(hostname) > maxHostnameLength {
		hostname = hostname[:maxHostnameLength]
	}
	return hostname, nil
}

func cleanHostname(hostname string) string {
	var clean strings.Builder
	for _, r := range hostname {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '.':
			clean.WriteRune(r)
		default:
			clean.WriteRune('-')
		}
	}
	if ip := net.ParseIP(clean.String()); ip != nil {
		return ip.String()
	}
	return clean.String()
}

var builderPool = sync.Pool{
	New: func() any { return new(strings.Builder) },
}

// escapeSDValue 按 RFC5424 转义 PARAM-VALUE（"、\、]），关键的是
// 把控制字符替换为空格。RFC5424 没有针对它们的转义语法，
// SD-PARAM 中的裸 LF/CR 会在 LF 分帧的 TCP 传输上提前终止帧，
// 让攻击者可控的属性值走私整条伪造的 syslog 消息
// （msg smuggling）。
func escapeSDValue(s string) string {
	b := builderPool.Get().(*strings.Builder)
	defer func() {
		b.Reset()
		builderPool.Put(b)
	}()
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == '"':
			b.WriteString(`\"`)
		case r == '\\':
			b.WriteString(`\\`)
		case r == ']':
			b.WriteString(`\]`)
		case r < 0x20 || r == 0x7f:
			b.WriteByte(' ')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// sdParam 是一个展平后的 SD-PARAM 候选：点号属性路径作 name，
// 已解析的值作字符串。
type sdParam struct {
	name  string
	value string
}

// collectSDParams 解析 attr 的值（LogValuer）并把 KindGroup
// 值展平为点号路径参数，与 JSON 路径的 FlattenAttr 一致
// （组展开为 "grp.child" 条目；值在渲染前解析）。
// 递归有深度上限（sdMaxGroupDepth，同 attrutil 的展平），自引用的
// LogValuer→组链才不会死循环；输出有
// 条数上限（maxSDParams），宽组才不会撑爆切片；
// 溢出与不可解析的值计入 skipped。Resolve 之后仍是
// LogValuer 的值是自引用的（Resolve 只应用一层），跳过而非
// 格式化成内部表示泄漏。
func collectSDParams(attr slog.Attr, prefix string, depth int, out *[]sdParam, skipped *int) {
	if depth >= sdMaxGroupDepth {
		*skipped++
		return
	}
	if len(*out) >= maxSDParams {
		*skipped++
		return
	}
	attr.Value = attr.Value.Resolve()
	if attr.Value.Kind() == slog.KindLogValuer {
		*skipped++
		return
	}
	key := attr.Key
	if prefix != "" {
		key = prefix + "." + key
	}
	if attr.Value.Kind() == slog.KindGroup {
		for _, child := range attr.Value.Group() {
			collectSDParams(child, key, depth+1, out, skipped)
		}
		return
	}
	if key == "" {
		*skipped++
		return
	}
	*out = append(*out, sdParam{name: key, value: attr.Value.String()})
}

// truncateSDValue 将已转义的 PARAM-VALUE 限制在 maxBytes 内，并保持 UTF-8
// rune 边界。截断发生在转义之后（先转义后截断，与 2026-11
// 审计前的顺序相反）：转义会让全引号/括号的值翻倍，
// 先截断再转义会让每个参数渲染出约 2×
// maxBytes。切口可能落在 `\\`/`\"`/`\]` 转义的
// 两半之间；悬空的反斜杠会与 "..." 后缀组成非法的
// RFC5424 转义序列，因此被剥离。
func truncateSDValue(s string, maxBytes int) string {
	t := textutil.TruncateUTF8(s, maxBytes)
	if n := len(t) - len(strings.TrimRight(t, `\`)); n%2 == 1 {
		t = t[:len(t)-1]
	}
	return t
}

// sanitizeSDName 将属性键映射为合法 SD-NAME（PRINTUSASCII 子集，
// 上限为 RFC5424 的 32 字符限制）。输入没有可用字符时返回 ""；
// 调用方整体跳过这类参数——空的 SD-NAME
// 会渲染出严格接收端拒绝的非法 ` ="value"` PARAM。
func sanitizeSDName(key string) string {
	b := builderPool.Get().(*strings.Builder)
	defer func() {
		b.Reset()
		builderPool.Put(b)
	}()
	b.Grow(min(len(key), maxSDNameLen))
	for _, r := range key {
		if b.Len() >= maxSDNameLen {
			break
		}
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-', r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}

func safeMessageForLog(msg string) string {
	cleaned := strings.Map(func(r rune) rune {
		if r >= 0 && r <= 31 {
			return ' '
		}
		return r
	}, msg)
	return strings.TrimSpace(spaceRe.ReplaceAllString(cleaned, " "))
}

func truncateJSON(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}

	// walkJSON 跟踪 s 前缀的括号深度与字符串状态，
	// 返回括号栈以及是否结束于字符串内部。
	walkJSON := func(prefix string) (stack []byte, inStr bool) {
		escaped := false
		for i := 0; i < len(prefix); i++ {
			c := prefix[i]
			if escaped {
				escaped = false
				continue
			}
			if c == '\\' && inStr {
				escaped = true
				continue
			}
			if c == '"' {
				inStr = !inStr
				continue
			}
			if inStr {
				continue
			}
			switch c {
			case '{', '[':
				stack = append(stack, c)
			case '}':
				if len(stack) > 0 && stack[len(stack)-1] == '{' {
					stack = stack[:len(stack)-1]
				}
			case ']':
				if len(stack) > 0 && stack[len(stack)-1] == '[' {
					stack = stack[:len(stack)-1]
				}
			}
		}
		return
	}

	// 第一遍：以宽松预算截断以估算后缀长度。
	// 至少为 "..." 加闭引号与闭括号预留 3 字节。
	budget := maxBytes - 3
	if budget < 3 {
		budget = 3
	}
	truncated := s[:textutil.RuneBoundary(s, budget)]
	stack, inStr := walkJSON(truncated)

	// 构建后缀并测量其确切长度。
	suffixLen := 3 // "..."
	if inStr {
		suffixLen++ // 闭 '"'
	}
	suffixLen += len(stack) // 闭括号

	// 第二遍：用精确后缀长度做精确截断。
	// 循环以防新截断点改变括号状态
	//（只会让所需后缀变短）。
	for {
		preciseBudget := maxBytes - suffixLen
		if preciseBudget < 0 {
			preciseBudget = 0
		}
		truncated = s[:textutil.RuneBoundary(s, preciseBudget)]
		stack, inStr = walkJSON(truncated)

		newSuffixLen := 3
		if inStr {
			newSuffixLen++
		}
		newSuffixLen += len(stack)
		if newSuffixLen <= suffixLen {
			// 后缀已稳定（只会变短）。直接跳出，不再
			// 重新赋值 suffixLen——循环后不再读取它。
			break
		}
		suffixLen = newSuffixLen
	}

	var suffix strings.Builder
	suffix.WriteString("...")
	if inStr {
		suffix.WriteByte('"')
	}
	for i := len(stack) - 1; i >= 0; i-- {
		if stack[i] == '{' {
			suffix.WriteByte('}')
		} else {
			suffix.WriteByte(']')
		}
	}
	return truncated + suffix.String()
}

// logEntry 是 slog.Record 的扁平化表示，供本包序列化：字段与
// slog.Record 相同，但 Attrs 物化为切片而非回调。此前从根包导出、
// 再移入 internal/handlerkit，始终仅 syslog 消费——最终归属消费者包。
type logEntry struct {
	Time    time.Time
	Level   slog.Level
	Message string
	Attrs   []slog.Attr
}

// recordToLogEntry 将 slog.Record 转换为 logEntry，把 attrs 回调物化
// 为具体切片。
func recordToLogEntry(r slog.Record) logEntry {
	e := logEntry{
		Time:    r.Time,
		Level:   r.Level,
		Message: r.Message,
		// 预分配切片，避免 append 过程中的多次扩容。
		Attrs: make([]slog.Attr, 0, r.NumAttrs()),
	}
	r.Attrs(func(attr slog.Attr) bool {
		e.Attrs = append(e.Attrs, attr)
		return true
	})
	return e
}

// SelfBuffered 标记 Handler 内置异步缓冲。
func (*Handler) SelfBuffered() {}

var (
	_ slog.Handler                = (*Handler)(nil)
	_ io.Closer                   = (*Handler)(nil)
	_ mebsuta.SelfBufferedHandler = (*Handler)(nil)
)
