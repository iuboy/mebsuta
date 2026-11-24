package database

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/iuboy/mebsuta"
	"github.com/iuboy/mebsuta/internal/attrutil"
	"github.com/iuboy/mebsuta/internal/handlerkit"
	"github.com/iuboy/mebsuta/internal/textutil"
	"go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/trace"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

const (
	finalFlushTimeout = 10 * time.Second
	finalFlushRetries = 3

	// insertChunkRows 限制一次 flush 批次内单条 INSERT 语句的行数。
	// PostgreSQL 线协议每条语句至多允许 65535 个绑定参数，每行
	// 贡献 15 列，因此不拆分的 maxBatchSize（10000）行批次会超出
	// 上限（150000 个参数）并让每次 flush 都失败。1000 行 → 15000 个
	// 参数——对 PostgreSQL/openGauss 稳妥低于上限，也在 SQLite 默认
	// 32766 变量限制之内。
	insertChunkRows = 1000
)

// shouldReportDrop 判断当前是否应上报丢弃：每秒至多一次
// （handlerkit.RateGate）。调用方无论如何都必须递增 h.dropped——
// 计数器记录每次丢失，限流器只管上报。
func (h *Handler) shouldReportDrop() bool {
	return h.dropGate.Allow()
}

// dbLogEntry 已移至 schema.go（OTel 对齐的 v2 形态）。

// Handler 经 GORM 将日志记录批量写入 PostgreSQL 或 openGauss 数据库。
type Handler struct {
	level    handlerkit.LevelGate
	cfg      Config
	db       *gorm.DB
	table    string
	entries  chan dbLogEntry
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	closed   atomic.Bool
	sendMu   sync.RWMutex // channel 发送期间 RLock；close 期间 Lock
	errCount atomic.Int64
	dropped  atomic.Int64
	dropGate handlerkit.RateGate // 丢弃上报限流：每秒至多一次
	// 事务双写：relay 目标（一致性关闭时为 nil）与扫描器停止
	// 信号。scanStop 在 Close 中于 wg.Wait 之前关闭，扫描器
	// goroutine 无需等待 cancel() 即可退出（cancel() 只在 wg.Wait
	// 之后触发——在此处关闭信号避免了那个死锁）。
	relayTo   log.LoggerProvider
	relayLog  log.Logger
	relayOnce sync.Once
	scanStop  chan struct{}
	// signSkipped 统计因签名失败（规范编码错误或 IntegritySigner 错误）
	// 而未签名落库的记录。每一计数都对应一行会被 VerifyRecord 以
	// ErrUnsignedRecord 拒绝的数据，审计人员可据此对账未签名行。
	signSkipped  atomic.Int64
	flushMu      sync.Mutex
	flushErr     error // 最后一次批次丢失错误，由 Close 呈现
	errorHandler *handlerkit.ErrorSlot
}

// NewHandler 创建连接到 cfg 所指定数据库的 Handler。
func NewHandler(cfg Config) (*Handler, error) {
	cfg, err := cfg.Validate()
	if err != nil {
		return nil, fmt.Errorf("database: %w", err)
	}

	gdb, sqlDB, err := OpenGorm(cfg.Driver, cfg.DSN, PoolConfig{
		MaxIdleConns:    cfg.MaxIdleConns,
		MaxOpenConns:    cfg.MaxOpenConns,
		MaxConnLifetime: cfg.MaxConnLifetime,
	})
	if err != nil {
		return nil, err
	}
	_ = sqlDB

	ctx, cancel := context.WithCancel(context.Background())

	h := &Handler{
		level:   handlerkit.NewLevelGate(cfg.Level),
		cfg:     cfg,
		db:      gdb,
		table:   cfg.Table,
		entries: make(chan dbLogEntry, cfg.BatchSize*10),
		ctx:     ctx,
		cancel:  cancel,
		relayTo: cfg.RelayTo,
	}
	eh := mebsuta.DefaultErrorHandler
	h.errorHandler = handlerkit.NewErrorSlot(eh)

	if cfg.warnNoTLS {
		handlerkit.ReportError(eh, &mebsuta.HandlerError{Component: "database", Operation: "init", Err: fmt.Errorf("database connection has no TLS/SSL configured — log data will be transmitted in plaintext")})
	}

	h.wg.Add(1)
	go h.run(cfg.BatchSize, cfg.BatchInterval, cfg.RetryDelay)

	if cfg.Consistency.Enabled && cfg.Consistency.RelayScanInterval > 0 {
		h.scanStop = make(chan struct{})
		h.wg.Add(1)
		go h.runRelayScanner(cfg.Consistency.RelayScanInterval, cfg.Consistency.RelayBatch)
	}

	return h, nil
}

// newGORMConfig 返回经 NewHandler 打开的每个数据库会话共享的
// gorm 会话配置。
//
// gorm 内置日志被显式静默（logger.Discard）。默认日志器
// 以 Warn 级别、200ms 慢查询阈值记录并写 stdout，用 ExplainSQL
// 插值渲染慢或失败的语句——包含批次中每个绑定值：对 flush 级
// 批次，这在最糟糕的时刻让峰值内存翻倍，并把未脱敏的记录
// 内容（可能敏感）直写 stdout，绕过本 handler 应用的每一层
// 脱敏。真实的数据库错误并不会因此被隐藏：CreateInBatches
// 会返回它们，flush 的重试/上报路径会呈现（经 sanitizeDBError
// 脱敏）。
func newGORMConfig() *gorm.Config {
	return &gorm.Config{Logger: logger.Discard}
}

// Enabled 实现 slog.Handler。
func (h *Handler) Enabled(_ context.Context, level slog.Level) bool {
	return h.level.Enabled(level)
}

// Handle 实现 slog.Handler。
func (h *Handler) Handle(ctx context.Context, r slog.Record) error {
	if h.closed.Load() {
		// 统计关闭后被静默丢弃的记录，让损失至少
		// 在指标中可见，而不是不可见的 nil。
		h.dropped.Add(1)
		return nil
	}

	entry := h.recordToDBEntry(ctx, r)
	return h.sendEntry(entry, r.Level)
}

// sendEntry 将条目发送到后台 channel。
//
// 使用 RWMutex：发送取读锁（并发——多个 goroutine
// 可同时发送），Close 取写锁（独占——等待在途
// 发送结束后再关闭 channel）。这消除了旧的 closeMu 方案——它把所有
// 发送串行化在单一互斥锁之后，每条 Error 级记录最多
// 阻塞 Close 5 秒。
func (h *Handler) sendEntry(entry dbLogEntry, level slog.Level) error {
	if h.closed.Load() {
		h.dropped.Add(1)
		return nil
	}

	h.sendMu.RLock()
	defer h.sendMu.RUnlock()

	if h.closed.Load() {
		h.dropped.Add(1)
		return nil
	}

	if level >= slog.LevelError {
		// 先尝试非阻塞发送，常见路径避免 timer 分配。
		select {
		case h.entries <- entry:
			return nil
		default:
		}

		timer := time.NewTimer(h.cfg.ErrorTimeout)
		defer timer.Stop()
		select {
		case h.entries <- entry:
			return nil
		case <-timer.C:
			// 此时持有 sendMu（读锁），Close 无法并发关闭 channel。
			// 到达这里的唯一原因就是积压已满。
			h.errCount.Add(1)
			h.dropped.Add(1)
			if h.shouldReportDrop() {
				h.errorHandler.Report(&mebsuta.HandlerError{Component: "database", Operation: "write", Err: fmt.Errorf("backlog full: %v record dropped after %v wait (buffer: %d/%d, total dropped: %d)", level, h.cfg.ErrorTimeout, len(h.entries), cap(h.entries), h.dropped.Load()), Dropped: h.dropped.Load()})
			}
			return nil
		}
	}

	// 非 Error 级别：非阻塞发送，缓冲满即丢弃。
	select {
	case h.entries <- entry:
		return nil
	default:
		h.errCount.Add(1)
		h.dropped.Add(1)
		if h.shouldReportDrop() {
			h.errorHandler.Report(&mebsuta.HandlerError{Component: "database", Operation: "write", Err: fmt.Errorf("backlog full: log dropped (buffer: %d/%d, total dropped: %d)", len(h.entries), cap(h.entries), h.dropped.Load()), Dropped: h.dropped.Load()})
		}
		return nil
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

// Close 实现 io.Closer。
//
// 取写锁等待所有在途 sendEntry 调用结束，
// 再关闭 channel。这在竞争检测器下干净（不同于基于 recover 的
// 方案），且允许并发发送（读锁共享）。channel 关闭
// 通知 run() 以存活的 context 排空并刷出剩余记录；
// cancel() 最后调用。若最终 flush 永久丢失了
// 批次，该错误从 Close 返回而非凭空消失。
func (h *Handler) Close() error {
	if !h.closed.CompareAndSwap(false, true) {
		// 幂等但非即时：等待赢得 CAS 的那个 Close 完成其
		// 排空+刷盘。每个调用方都必须得到相同的完成
		// 契约——“Close 返回时，缓冲记录已持久化”——
		// 而不只是赢得竞争的那一个；第二个 Close 提前返回
		// 会让调用方在最终 flush 落库前就读库。
		h.wg.Wait()
		return nil
	}
	h.sendMu.Lock()
	close(h.entries) // 安全：写锁保证没有并发发送
	h.sendMu.Unlock()
	// 在 wg.Wait 之前通知 relay 扫描器：它若等待
	// cancel()（只在 wg.Wait 之后触发）会让 Close 死锁。
	// 扫描器的停止路径会做一次有界的最终扫描。
	if h.scanStop != nil {
		close(h.scanStop)
	}
	h.wg.Wait()
	h.cancel()

	h.flushMu.Lock()
	flushErr := h.flushErr
	h.flushMu.Unlock()

	var errs []error
	if flushErr != nil {
		errs = append(errs, flushErr)
	}
	sqlDB, err := h.db.DB()
	if err != nil {
		errs = append(errs, fmt.Errorf("database: get database connection for close: %w", err))
		return errors.Join(errs...)
	}
	if err := sqlDB.Close(); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func (h *Handler) run(batchSize int, batchInterval, retryDelay time.Duration) {
	defer h.wg.Done()

	ticker := time.NewTicker(batchInterval)
	defer ticker.Stop()

	var batch []dbLogEntry

	// run() 只经 channel 关闭（!ok 路径）退出。它不监听
	// h.ctx.Done()，这样 Close() 才能：(1) close(h.entries) 通知
	// run 退出，(2) wg.Wait() 等待排空+刷盘以存活的
	// context 完成，(3) h.cancel() 释放资源。若 run() 经
	// ctx.Done() 退出，最终 flush 会使用已取消的 context 并丢数据。
	for {
		select {
		case entry, ok := <-h.entries:
			if !ok {
				h.setFlushErr(h.flush(batch, retryDelay))
				return
			}
			batch = append(batch, entry)

			if len(batch) >= batchSize {
				h.setFlushErr(h.flush(batch, retryDelay))
				batch = nil
			}

		case <-ticker.C:
			if len(batch) > 0 {
				h.setFlushErr(h.flush(batch, retryDelay))
				batch = nil
			}
		}
	}
}

func (h *Handler) setFlushErr(err error) {
	if err == nil {
		return
	}
	h.flushMu.Lock()
	h.flushErr = err
	h.flushMu.Unlock()
}

// flush 插入一个批次并重试瞬时失败。只在批次永久
// 丢失时返回错误，Close 才能呈现数据丢失。
func (h *Handler) flush(batch []dbLogEntry, retryDelay time.Duration) error {
	if len(batch) == 0 {
		return nil
	}

	// 每次尝试都在事务内执行，部分失败才不会
	// 留下孤儿行。没有事务时，若 CreateInBatches 把批次
	// 拆成多条 INSERT 语句且中途某条失败，重试会把
	// 已持久化的行再插一遍，产生重复。
	//
	// 残余重复风险：若事务已在服务端提交但客户端
	// 先超时（结果模糊），重试会重新插入该批次。
	// 表没有天然的幂等键——去重需要唯一约束或
	// 事件 ID 列，这是留给运维的 schema 决策。
	for i := range finalFlushRetries {
		ctx, cancel := context.WithTimeout(h.ctx, finalFlushTimeout)
		dbErr := h.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
			return tx.Table(h.table).CreateInBatches(batch, insertChunkRows).Error
		})
		cancel()

		if dbErr == nil {
			// 事务双写实时路径：把已提交批次继续
			// relay 出去（除非 Consistency.SyncRelay，否则为 no-op）。此处
			// h.ctx 仍存活——cancel() 只在 run() 退出后执行。
			h.relayBatch(h.ctx, batch)
			return nil
		}
		h.errCount.Add(1)
		h.errorHandler.Report(&mebsuta.HandlerError{Component: "database", Operation: "batch", Err: batchAttemptError(i+1, dbErr)})
		if i < finalFlushRetries-1 {
			// 关停期间尊重 context 取消，避免用无条件休眠
			// 阻塞 Close()。
			//
			// 防御性：当前生命周期下该分支是死代码——
			// h.ctx 只在 Close 的 wg.Wait() 收割 run 循环之后才被取消，
			// 且 run() 排空时无视 context。它存在的意义是
			// 让未来的生命周期改动无法静默吞掉
			// 批次：被取消的重试计为丢弃，记入
			// flushErr 并返回，Close 呈现丢失而不是
			// 报告成功。
			select {
			case <-time.After(retryDelay):
			case <-h.ctx.Done():
				lost := fmt.Errorf("database: batch of %d records lost: shutdown cancelled flush retry", len(batch))
				h.dropped.Add(int64(len(batch)))
				h.setFlushErr(lost)
				h.errorHandler.Report(&mebsuta.HandlerError{Component: "database", Operation: "batch", Err: lost, Dropped: h.dropped.Load()})
				return lost
			}
		}
	}
	// 重试耗尽：整批不可挽回地丢失——计入 dropped 并在 HandlerError
	// 上携带幅值（与上方被取消路径的记账对齐），丢弃指标才能呈现
	// 这条最大的丢失路径。
	h.dropped.Add(int64(len(batch)))
	err := fmt.Errorf("database: batch of %d records lost after %d failed attempts", len(batch), finalFlushRetries)
	h.errorHandler.Report(&mebsuta.HandlerError{Component: "database", Operation: "batch", Err: err, Dropped: h.dropped.Load(), Records: len(batch)})
	return err
}

// batchAttemptError 为 flush 构建逐次尝试的失败报告。原始
// 数据库错误在离开 handler 前经 sanitizeDBError 处理：
// 驱动错误可能回显 DSN 片段（“user:password@host”、
// “password=...”），NewHandler 的连接路径已经脱敏——
// 重试路径绝不能成为唯一的泄漏点。错误被渲染成字符串
// 而非用 %w 包装，因为脱敏必然替换掉
// 原始错误值。
func batchAttemptError(attempt int, dbErr error) error {
	return fmt.Errorf("batch insert failed (attempt %d/%d): %s", attempt, finalFlushRetries, sanitizeDBError(dbErr))
}

// fieldsMapPool 回收逐记录的属性 map：高流量下每条日志
// 记录一次 map 分配是可测的 GC 压力，且 map 一旦
// 编码进 entry.Fields 就死了。
var fieldsMapPool = sync.Pool{
	New: func() any { return make(map[string]any, 16) },
}

func (h *Handler) recordToDBEntry(ctx context.Context, r slog.Record) dbLogEntry {
	entry := dbLogEntry{
		ID:             newRecordID(),
		Time:           r.Time,
		ObservedTime:   time.Now().UTC(),
		Level:          r.Level.String(),
		SeverityNumber: mebsuta.SeverityNumber(r.Level),
		Message:        r.Message,
		ServiceName:    h.cfg.ServiceName,
	}
	// 日志-链路关联：与 OTLP 路径原生获取的提取一致。
	// span 之外两半都保持为空。
	if sc := trace.SpanContextFromContext(ctx); sc.IsValid() {
		entry.TraceID = sc.TraceID().String()
		entry.SpanID = sc.SpanID().String()
	}

	fields, _ := fieldsMapPool.Get().(map[string]any)
	if fields == nil {
		fields = make(map[string]any, 16)
	}
	defer func() {
		for k := range fields {
			delete(fields, k)
		}
		fieldsMapPool.Put(fields)
	}()

	r.Attrs(func(attr slog.Attr) bool {
		// FlattenAttrMarked: 任一 attr 触发截断/丢弃上限时给记录补
		// `_truncated` 标记（与 syslog/JSON 路径的标记语义一致）。
		if attrutil.FlattenAttrMarked(fields, "", attr, attrutil.NaNString) {
			fields["_truncated"] = true
		}
		return true
	})
	if len(fields) > 0 {
		data, err := json.Marshal(fields)
		if err != nil {
			h.errorHandler.Report(&mebsuta.HandlerError{Component: "database", Operation: "marshal", Err: fmt.Errorf("marshal fields: %w", err)})
			data = []byte("{}")
		}
		entry.Fields = json.RawMessage(data)
	}

	// 在签名之前执行单记录大小上界，签名覆盖的
	// 才是实际持久化并被截断后的内容。
	h.applyRecordLimit(&entry)

	// 完整性保护：配置了 signer 时，对记录的规范形
	// 签名。失败并非致命——计数跳过、
	// 限频上报，并以无签名形式持久化记录，
	// 而不是丢弃它。
	if h.cfg.IntegritySigner != nil {
		// 把存储时间戳截到规范精度，签名形才能在
		// 数据库往返后幸存：PostgreSQL 与 openGauss 的
		// timestamptz 只保留微秒，否则亚微秒位会被列
		// 静默丢弃，之后每次对未篡改记录的校验
		// 都会失败。
		entry.Time = entry.Time.Truncate(canonicalPrecision)
		canonical, err := CanonicalBytes(entry.Time, entry.Level, entry.Message, entry.Fields)
		if err != nil {
			h.signSkipped.Add(1)
			if h.shouldReportDrop() {
				h.errorHandler.Report(&mebsuta.HandlerError{
					Component: "database", Operation: "sign",
					Err: fmt.Errorf("integrity sign skipped, record persisted unsigned: %w", err),
				})
			}
		} else {
			recordHash, sig, signErr := h.cfg.IntegritySigner.Sign(canonical)
			if signErr != nil {
				h.signSkipped.Add(1)
				if h.shouldReportDrop() {
					h.errorHandler.Report(&mebsuta.HandlerError{
						Component: "database", Operation: "sign",
						Err: fmt.Errorf("integrity sign failed, record persisted unsigned: %w", signErr),
					})
				}
			} else {
				entry.RecordHash = hex.EncodeToString(recordHash)
				entry.Signature = sig
				entry.SignAlgo = h.cfg.IntegritySigner.Algorithm()
			}
		}
	}

	return entry
}

// truncatedFieldsJSON 是记录超过 Config.MaxRecordBytes 时存储的占位。
// 任意字段文档的 JSON 安全截断通常做不到——切在字符串或容器内部会
// 产生非法 JSON，更糟的是产生合法却悄悄歪曲记录的
// JSON——因此 fields 列被整体替换为标记对象，截断后的
// 消息承载大小证据。运维可直接查询该标记
// （fields->>'mebsuta_truncated'）找到受影响的行。
var truncatedFieldsJSON = json.RawMessage(`{"mebsuta_truncated":true}`)

// applyRecordLimit 对单条记录的编码大小（消息长度 +
// fields JSON 长度）强制 cfg.MaxRecordBytes。超限记录保留
// 消息——UTF-8 安全截断到放得下——但丢失
// fields，替换为 mebsuta_truncated 标记；丢失计入
// Dropped 并经限频丢弃报告呈现，与积压丢弃
// 路径一致。
//
// 没有该上界，积压（BatchSize*10 条无界大小）可因单条
// 超大属性（如原始请求体）膨胀到数百 GB 常驻内存，
// 并在 flush 时随批切片加 INSERT 缓冲的物化
// 再翻三倍。
//
// cfg.MaxRecordBytes 为零时跳过检查：只可能出现在
// NewHandler 之外构建的 Handler（测试），因为 Validate 会把
// 该字段钳制到 [1, MaxRecordBytesCap]。
func (h *Handler) applyRecordLimit(entry *dbLogEntry) {
	maxBytes := h.cfg.MaxRecordBytes
	if maxBytes <= 0 {
		return
	}
	if len(entry.Message)+len(entry.Fields) <= maxBytes {
		return
	}
	entry.Fields = truncatedFieldsJSON
	entry.Message = textutil.TruncateUTF8(entry.Message, maxBytes-len(entry.Fields))
	h.errCount.Add(1)
	h.dropped.Add(1)
	if h.shouldReportDrop() {
		h.errorHandler.Report(&mebsuta.HandlerError{
			Component: "database", Operation: "write",
			Err:     fmt.Errorf("record exceeds MaxRecordBytes (%d bytes): fields replaced with truncation marker, message truncated (total dropped: %d)", maxBytes, h.dropped.Load()),
			Dropped: h.dropped.Load(),
		})
	}
}

// SetLevel 运行时热调级别（0.1.0-14）。仅当构造期 Level 传入
// *slog.LevelVar 时生效并返回 true；固定级别返回 false（进入
// mebsuta.SetLevel 的 skipped 诚实面）。
func (h *Handler) SetLevel(level slog.Level) bool {
	return h.level.Set(level)
}

// SetErrorHandler 在运行时更新错误处理器。它实现
// mebsuta.ErrorHandlerSetter，WithErrorHandler 得以传播到本 handler。
func (h *Handler) SetErrorHandler(fn mebsuta.ErrorHandler) {
	h.errorHandler.Store(fn)
}

// SelfBuffered 标记 Handler 内置异步缓冲。
func (*Handler) SelfBuffered() {}

// Dropped 返回本 handler 丢失的记录总数：积压满、
// Close 后写入，以及超过 MaxRecordBytes 的记录（原始
// fields 内容被替换为截断标记，因此未截断形态的丢失
// 也计入此处）。它是 mebsuta.AsyncDropped 在 database 侧的
// 对应物，此前只计数但不可读。
func (h *Handler) Dropped() int64 {
	return h.dropped.Load()
}

// SignSkipped 返回因签名失败而未签名落库的记录数——
// 要么 CanonicalBytes 拒绝了记录（如 fields 嵌套超过规范
// 深度上限），要么 IntegritySigner.Sign 返回错误。仅在
// 设置 Config.IntegritySigner 时有意义：每个被跳过的行都会被
// VerifyRecord 以 ErrUnsignedRecord 拒绝，审计人员可据此
// 计数器对账未签名行，而无需逐行
// 排查。
func (h *Handler) SignSkipped() int64 {
	return h.signSkipped.Load()
}

func closeSQLDB(gdb *gorm.DB) {
	if db, err := gdb.DB(); err == nil {
		_ = db.Close()
	}
}

// dsnCredRe 匹配 DSN 派生错误消息中常见的凭据模式：
// “user:pass@host” / “user:pass@tcp(host)” 的密码段，
// 以及 key=value 形式的参数（password、passwd、sslpassword、pwd）。
//
// 密码段模式为 :[^@/]*@——它允许密码内出现 ':'（此前的
// :[^:@/]+@ 变体会泄漏内嵌 ':' 之后的全部内容），并在第一个
// '@' 或 '/' 处停止。包含 '@' 的密码无法仅靠正则从
// 主机分隔符中可靠剥离；此类 DSN 应由驱动侧解析。
// 这是面向错误消息的尽力而为脱敏器，不是解析器。
var dsnCredRe = regexp.MustCompile(`:[^@/]*@|(?:password|passwd|sslpassword|pwd)=[^&;\s]+`)

// redactCredentials 以对所有调用方（数据库错误与 Config 的
// String/GoString/Sanitize 输出中渲染的 DSN）一致的规则，
// 移除 s 中类凭据子串。
func redactCredentials(s string) string {
	return dsnCredRe.ReplaceAllStringFunc(s, func(m string) string {
		// “user:pass@” 形式——保留冒号分隔符形状。
		if strings.HasSuffix(m, "@") {
			return ":***@"
		}
		// “key=value” 形式——保留键，脱敏值。
		eq := strings.IndexByte(m, '=')
		if eq < 0 {
			return "***"
		}
		return m[:eq+1] + "***"
	})
}

// sanitizeDBError 移除数据库错误消息中类凭据的子串。
func sanitizeDBError(err error) string {
	if err == nil {
		return "<nil>"
	}
	return redactCredentials(err.Error())
}

var (
	_ slog.Handler                = (*Handler)(nil)
	_ io.Closer                   = (*Handler)(nil)
	_ mebsuta.SelfBufferedHandler = (*Handler)(nil)
)
