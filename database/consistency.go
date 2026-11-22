package database

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/iuboy/mebsuta"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/trace"
)

// relayLoggerName 在 OTel 管线中为 relay 记录划定作用域，
// 使其可与 otlp handler 直接发出的记录区分。
const relayLoggerName = "github.com/iuboy/mebsuta/database/relay"

// ConsistencyConfig 配置事务双写：以数据库为
// 事实来源，OTLP 投递经 outbox 列中转，
// 而非两条彼此独立的 handler 链。
//
// 诚实的边界——这不是两阶段提交。OTLP 端点无法
// 在分布式事务中投票；本模式保证的是：
//
//   - 数据库写入按 flush 批次原子（既有行为），投递
//     标记（relayed_at）就在同一批行里，“已持久化”与
//     “待投递”是同一个状态机；
//   - 记录只在其批次提交后才被 relay（DB 把守
//     OTLP 侧——任何数据都不会只存在于 OTLP 侧）；
//   - 投递是 at-least-once：实时路径在提交后同步
//     relay，后台扫描器对账一切仍待处理的行
//     （标记 UPDATE 失败、提交与 relay 之间崩溃、SyncRelay
//     被禁用），消费者按 ULID id 去重。
//
// 适用于签名存储中的记录完整性比写入延迟更重要的
// 合规/审计负载：flush 路径每条记录多一次 emit，
// 每批次多一次标记 UPDATE。
type ConsistencyConfig struct {
	// Enabled 开启事务双写。默认 false：
	// handler 行为与之前完全一致（纯 sink，relayed_at 保持
	// NULL 且不运行扫描器）。
	Enabled bool
	// SyncRelay 在 flush 路径上立即 relay 每个已提交批次
	//（默认 true）。吞吐优先模式可禁用：投递
	// 只按 RelayScanInterval 节奏进行。
	SyncRelay *bool
	// RelayScanInterval 是仍待 relay 行的后台对账间隔
	//（默认 30s）。0 表示完全禁用内置
	// 扫描器——对账交由外部消费者
	//（如 mebsuta-forwarder 的 database source 读取
	// "relayed_at IS NULL"）。SyncRelay=false 且无扫描器意味着行
	// 保持待处理，直到外部消费者取走。
	RelayScanInterval time.Duration
	// RelayBatch 限制每次对账扫描的行数（默认 500）。
	RelayBatch int
}

// validate 填充默认值，由 Config.Validate 调用；
// RelayTo 的交叉要求在那里，因为它是 Config 字段。
func (c ConsistencyConfig) validate() ConsistencyConfig {
	if !c.Enabled {
		return c
	}
	if c.SyncRelay == nil {
		yes := true
		c.SyncRelay = &yes
	}
	if c.RelayScanInterval == 0 {
		c.RelayScanInterval = 30 * time.Second
	}
	if c.RelayBatch <= 0 {
		c.RelayBatch = 500
	}
	return c
}

// syncRelay 判断已提交批次是否在 flush 路径上 relay。
func (c ConsistencyConfig) syncRelay() bool {
	return c.Enabled && (c.SyncRelay == nil || *c.SyncRelay)
}

// relayEmit 将一行存储行还原为 OTel 日志记录并经
// relay provider 发出。存储的 trace_id/span_id
// 通过在发出 context 上重建只读 span context 重新
// 注入——与日志 SDK 关联原生发出记录的机制
// 相同，relay 记录因此保留链路关联。
func (h *Handler) relayEmit(ctx context.Context, logger log.Logger, e dbLogEntry) {
	var rec log.Record
	rec.SetTimestamp(e.Time)
	rec.SetObservedTimestamp(e.ObservedTime)
	if e.SeverityNumber > 0 {
		rec.SetSeverity(log.Severity(e.SeverityNumber))
	}
	if e.Level != "" {
		rec.SetSeverityText(e.Level)
	}
	rec.SetBody(attribute.StringValue(e.Message))
	if len(e.Fields) > 0 {
		rec.AddAttributes(jsonAttrs(e.Fields)...)
	}
	logger.Emit(withStoredSpanContext(ctx, e), rec)
}

// withStoredSpanContext 在两半十六进制 id 都可解析时，从存储的
// id 重建合法 span context；否则原样放行 context，
// 记录无关联地外发，而不是伪造一个关联。
func withStoredSpanContext(ctx context.Context, e dbLogEntry) context.Context {
	if e.TraceID == "" || e.SpanID == "" {
		return ctx
	}
	tb, err1 := hex.DecodeString(e.TraceID)
	sb, err2 := hex.DecodeString(e.SpanID)
	if err1 != nil || err2 != nil || len(tb) != 16 || len(sb) != 8 {
		return ctx
	}
	var tid trace.TraceID
	var sid trace.SpanID
	copy(tid[:], tb)
	copy(sid[:], sb)
	sc := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    tid,
		SpanID:     sid,
		TraceFlags: trace.FlagsSampled,
	})
	return trace.ContextWithSpanContext(ctx, sc)
}

// jsonAttrs 将展平的属性文档解码回 OTel
// 属性。文档由 attrutil 展平生成，值都是
// 标量；嵌套/异类值退化为 fmt 形式而非
// 被丢弃。
func jsonAttrs(fields json.RawMessage) []attribute.KeyValue {
	var m map[string]any
	if err := json.Unmarshal(fields, &m); err != nil {
		return nil
	}
	out := make([]attribute.KeyValue, 0, len(m))
	for k, v := range m {
		switch t := v.(type) {
		case string:
			out = append(out, attribute.String(k, t))
		case bool:
			out = append(out, attribute.Bool(k, t))
		case float64:
			out = append(out, attribute.Float64(k, t))
		default:
			out = append(out, attribute.String(k, fmt.Sprintf("%v", t)))
		}
	}
	return out
}

// relayBatch relay 一个刚提交的批次（事务双写
// 实时路径）并将行标记为已投递。本层的 Emit 不会失败
// （OTel 日志 API 是 fire-and-forget；provider 自身的批处理器负责
// 导出重试），因此失败只来自标记 UPDATE——
// 它让行保持待处理等扫描器处理：at-least-once，绝不
// 丢失，绝不只存在于 OTLP 侧。
func (h *Handler) relayBatch(ctx context.Context, batch []dbLogEntry) {
	if !h.cfg.Consistency.syncRelay() || len(batch) == 0 {
		return
	}
	logger := h.relayLogger()
	if logger == nil { // RelayTo 未设置：测试构造的 handler，无处可 relay
		return
	}
	ids := make([]string, 0, len(batch))
	for _, e := range batch {
		h.relayEmit(ctx, logger, e)
		ids = append(ids, e.ID)
	}
	h.markRelayed(ctx, ids)
}

// markRelayed 为已投递的行设置 relayed_at。失败会上报
// 但不致命：扫描器（或外部消费者）会重新投递，
// 下游按 id 去重吸收重复。
func (h *Handler) markRelayed(ctx context.Context, ids []string) {
	if len(ids) == 0 {
		return
	}
	if err := h.db.WithContext(ctx).Table(h.table).Where("id IN ?", ids).Update("relayed_at", time.Now()).Error; err != nil {
		h.errCount.Add(1)
		h.errorHandler.Report(&mebsuta.HandlerError{
			Component: "database", Operation: "relay-mark",
			Err: fmt.Errorf("mark %d rows relayed (they stay pending for reconciliation): %s", len(ids), sanitizeDBError(err)),
		})
	}
}

// runRelayScanner 周期性对账仍待 relay 的行：
// 崩溃恢复、失败的标记 UPDATE，以及吞吐模式
// （SyncRelay=false）。它在 scanStop 上退出并做最后一次有界扫描，
// Close 返回时一切要么已投递、要么已上报待处理。
func (h *Handler) runRelayScanner(interval time.Duration, batch int) {
	defer h.wg.Done()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-h.scanStop:
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			h.scanOnce(ctx, batch)
			cancel()
			return
		case <-ticker.C:
			h.scanOnce(h.scanCtx(), batch)
		}
	}
}

// scanCtx 为扫描提供存活的 context：h.ctx 只在
// Close 的 wg.Wait() 收割本 goroutine 之后才被取消，因此
// 每次扫描时它都存活——用它让扫描受关停约束，
// 而不是无界后台工作。
func (h *Handler) scanCtx() context.Context { return h.ctx }

// scanChunkRows 限制一次扫描内每条水化查询物化的行数；
// scanByteBudget 限制累计载荷。每行的 Fields 文档
// 可达 MaxRecordBytesCap（8MiB），仅按行数
// 限制会让单次扫描物化 RelayBatch × 8MiB
// （默认 4GB）——第五轮审计的 P2 发现。预算让本轮
// 提前停止；剩余行保持待处理，下一轮从其后
// 继续（ULID id 顺序单调，截断可续扫，
// 绝不丢数据）。
const scanChunkRows = 50

// scanByteBudget 用 var 是为了让安全测试能缩小它；生产
// 默认 32MiB。理由见 scanOnce。
var scanByteBudget = 32 << 20

// scanOnce 投递一页有界的待处理行，最旧优先（ULID
// 顺序 = 创建顺序），在累计字节预算内以小块
// 水化。
func (h *Handler) scanOnce(ctx context.Context, batch int) {
	logger := h.relayLogger()
	if logger == nil {
		return
	}
	var (
		delivered []string
		bytes     int
		lastID    string
		budgetHit bool
	)
	for len(delivered) < batch && !budgetHit {
		chunk := min(scanChunkRows, batch-len(delivered))
		var page []dbLogEntry
		q := h.db.WithContext(ctx).Table(h.table).Where("relayed_at IS NULL")
		if lastID != "" {
			q = q.Where("id > ?", lastID)
		}
		if err := q.Order("id ASC").Limit(chunk).Find(&page).Error; err != nil {
			h.errCount.Add(1)
			h.errorHandler.Report(&mebsuta.HandlerError{
				Component: "database", Operation: "relay-scan",
				Err: fmt.Errorf("query pending relay rows: %s", sanitizeDBError(err)),
			})
			break
		}
		if len(page) == 0 {
			break
		}
		for _, e := range page {
			lastID = e.ID
			if bytes+len(e.Fields) > scanByteBudget && len(delivered) > 0 {
				budgetHit = true
				break
			}
			h.relayEmit(ctx, logger, e)
			delivered = append(delivered, e.ID)
			bytes += len(e.Fields)
			if len(delivered) >= batch {
				break
			}
		}
	}
	h.markRelayed(ctx, delivered)
}

// relayLogger 经配置的 provider（Config.RelayTo）
// 惰性绑定 relay 作用域。
func (h *Handler) relayLogger() log.Logger {
	h.relayOnce.Do(func() {
		if h.relayTo != nil {
			h.relayLog = h.relayTo.Logger(relayLoggerName)
		}
	})
	return h.relayLog
}
