// span 与 metric exporter：traces 与
// metrics 信号的 database 后端（部署模式 B——“mebsuta 写数据库”）。两个
// exporter 都是调用方持有 gorm 会话之上的纯 sink：
// telemetry 引导负责拨号（OpenGorm）与关闭；exporter
// 绝不自行关闭会话。
package database

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/iuboy/mebsuta"
	"github.com/iuboy/mebsuta/internal/handlerkit"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	sdkmetricdata "go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdkresource "go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.43.0"
	"gorm.io/gorm"
)

// semconvServiceNameKey 是每个 exporter 都读取的 resource 键。
var semconvServiceNameKey = semconv.ServiceNameKey

// telemetry database 后端的默认表名。
const (
	DefaultTracesTable  = "mebsuta_traces"
	DefaultMetricsTable = "mebsuta_metrics"
)

// exporterChunkRows 限制一次导出内单条 INSERT 的行数，与
// 日志 handler 的线协议上限推理一致。
const exporterChunkRows = 1000

// validateTable 应用与日志 handler 相同的表名规则。
func validateTable(table, field string) error {
	if !tableNameRe.MatchString(table) {
		return &mebsuta.ConfigError{Field: field, Msg: "table name must match [a-zA-Z0-9_](.[a-zA-Z0-9_])?"}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Span exporter
// ---------------------------------------------------------------------------

// SpanRow 是一个 span 的持久化形态，与 OTLP trace
// 数据模型对齐：身份三件套（trace/span/parent id）、时序（start/end/
// duration）、状态，以及属性与事件的 jsonb 文档。
// ULID id 列保持与日志表一致的游标语义。
type SpanRow struct {
	ID           string          `gorm:"column:id"`
	TraceID      string          `gorm:"column:trace_id"`
	SpanID       string          `gorm:"column:span_id"`
	ParentSpanID string          `gorm:"column:parent_span_id"`
	Name         string          `gorm:"column:name"`
	Kind         string          `gorm:"column:kind"`
	StartTime    time.Time       `gorm:"column:start_ts"`
	EndTime      time.Time       `gorm:"column:end_ts"`
	DurationMS   float64         `gorm:"column:duration_ms"`
	StatusCode   string          `gorm:"column:status_code"`
	StatusMsg    string          `gorm:"column:status_message"`
	Attributes   json.RawMessage `gorm:"column:attributes;type:jsonb"`
	Events       json.RawMessage `gorm:"column:events;type:jsonb"`
	ServiceName  string          `gorm:"column:service_name"`
}

// SpansTableDDL 是 span 表的参考 CREATE TABLE
// （DDL 由运维负责；契约模式同 LogsTableDDL）。
const SpansTableDDL = `CREATE TABLE IF NOT EXISTS %s (
	id             TEXT NOT NULL,
	trace_id       TEXT NOT NULL,
	span_id        TEXT NOT NULL,
	parent_span_id TEXT NOT NULL DEFAULT '',
	name           TEXT NOT NULL,
	kind           TEXT NOT NULL DEFAULT '',
	start_ts       TIMESTAMPTZ NOT NULL,
	end_ts         TIMESTAMPTZ NOT NULL,
	duration_ms    DOUBLE PRECISION NOT NULL DEFAULT 0,
	status_code    TEXT NOT NULL DEFAULT '',
	status_message TEXT NOT NULL DEFAULT '',
	attributes     JSONB,
	events         JSONB,
	service_name   TEXT NOT NULL DEFAULT ''
);
CREATE UNIQUE INDEX IF NOT EXISTS %s_id_uk ON %s (id);
CREATE INDEX IF NOT EXISTS %s_trace_ix ON %s (trace_id);
CREATE INDEX IF NOT EXISTS %s_start_ix ON %s (start_ts);`

// SpanExporter 实现 sdktrace.SpanExporter，将 span 批量
// 插入配置的表。并发安全（SDK 同步
// 调用 ExportSpans，但 Shutdown 可能与之竞争）。
type SpanExporter struct {
	db           *gorm.DB
	table        string
	closed       atomic.Bool
	errorHandler *handlerkit.ErrorSlot
}

// NewSpanExporter 在调用方持有的 db 会话上将 span 写入 table。
func NewSpanExporter(db *gorm.DB, table string) (*SpanExporter, error) {
	if db == nil {
		return nil, fmt.Errorf("database: NewSpanExporter: nil db")
	}
	if err := validateTable(table, "Table"); err != nil {
		return nil, fmt.Errorf("database: %w", err)
	}
	e := &SpanExporter{db: db, table: table}
	e.errorHandler = handlerkit.NewErrorSlot(mebsuta.DefaultErrorHandler())
	return e, nil
}

// ExportSpans 分块地把批次插入单个事务；部分
// 失败不产生孤儿行（与日志 flush 同理）。
func (e *SpanExporter) ExportSpans(ctx context.Context, spans []sdktrace.ReadOnlySpan) error {
	if e.closed.Load() || len(spans) == 0 {
		return nil
	}
	rows := make([]SpanRow, 0, len(spans))
	for _, sp := range spans {
		rows = append(rows, spanToRow(sp))
	}
	err := e.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		return tx.Table(e.table).CreateInBatches(rows, exporterChunkRows).Error
	})
	if err != nil {
		return fmt.Errorf("database: span export to %s: %s", e.table, sanitizeDBError(err))
	}
	return nil
}

// Shutdown 幂等且不释放任何资源——db 会话归
// 调用方所有。
func (e *SpanExporter) Shutdown(context.Context) error {
	e.closed.Store(true)
	return nil
}

// SetErrorHandler 接入 mebsuta 错误处理器链。
func (e *SpanExporter) SetErrorHandler(fn mebsuta.ErrorHandler) {
	e.errorHandler.Store(fn)
}

var _ sdktrace.SpanExporter = (*SpanExporter)(nil)

func spanToRow(sp sdktrace.ReadOnlySpan) SpanRow {
	sc := sp.SpanContext()
	parent := sp.Parent()
	row := SpanRow{
		ID:           newRecordID(),
		TraceID:      sc.TraceID().String(),
		SpanID:       sc.SpanID().String(),
		ParentSpanID: parent.SpanID().String(),
		Name:         sp.Name(),
		Kind:         sp.SpanKind().String(),
		StartTime:    sp.StartTime(),
		EndTime:      sp.EndTime(),
		DurationMS:   float64(sp.EndTime().Sub(sp.StartTime())) / float64(time.Millisecond),
		StatusCode:   sp.Status().Code.String(),
		StatusMsg:    sp.Status().Description,
		Attributes:   attrsJSON(sp.Attributes()),
		ServiceName:  resourceServiceName(sp.Resource()),
	}
	if events := sp.Events(); len(events) > 0 {
		type flatEvent struct {
			Name       string          `json:"name"`
			Time       time.Time       `json:"time"`
			Attributes json.RawMessage `json:"attributes,omitempty"`
		}
		flat := make([]flatEvent, 0, len(events))
		for _, ev := range events {
			flat = append(flat, flatEvent{Name: ev.Name, Time: ev.Time, Attributes: attrsJSON(ev.Attributes)})
		}
		if data, err := json.Marshal(flat); err == nil {
			row.Events = data
		}
	}
	return row
}

// ---------------------------------------------------------------------------
// Metric exporter
// ---------------------------------------------------------------------------

// MetricRow 是一个 metric 数据点的持久化形态。gauge 与
// sum 填充 Value；histogram 填充 Sum/Count（Value 保持 NULL）。
// 该形态面向低基数、审计向的指标——高频
// 高基数 telemetry 属于 OTLP 路径（模式 A）。
type MetricRow struct {
	ID          string          `gorm:"column:id"`
	Name        string          `gorm:"column:name"`
	Kind        string          `gorm:"column:kind"`
	Monotonic   bool            `gorm:"column:monotonic"`
	Temporality string          `gorm:"column:temporality"`
	Value       *float64        `gorm:"column:value"`
	Sum         *float64        `gorm:"column:sum"`
	Count       *int64          `gorm:"column:count"`
	Attributes  json.RawMessage `gorm:"column:attributes;type:jsonb"`
	ServiceName string          `gorm:"column:service_name"`
	StartTS     time.Time       `gorm:"column:start_ts"`
	TS          time.Time       `gorm:"column:ts"`
}

// MetricsTableDDL 是 metric 表的参考 CREATE TABLE。
const MetricsTableDDL = `CREATE TABLE IF NOT EXISTS %s (
	id          TEXT NOT NULL,
	name        TEXT NOT NULL,
	kind        TEXT NOT NULL,
	monotonic   BOOLEAN NOT NULL DEFAULT FALSE,
	temporality TEXT NOT NULL DEFAULT '',
	value       DOUBLE PRECISION,
	sum         DOUBLE PRECISION,
	count       BIGINT,
	attributes  JSONB,
	service_name TEXT NOT NULL DEFAULT '',
	start_ts    TIMESTAMPTZ,
	ts          TIMESTAMPTZ NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS %s_id_uk ON %s (id);
CREATE INDEX IF NOT EXISTS %s_name_ts_ix ON %s (name, ts);`

// MetricExporter 实现 sdkmetric.Exporter，把采集到的每个
// 数据点写成一行。Temporality 强制为 Cumulative：SQL 消费方
// 按游标轮询，累积值每行自含，而
// delta 流需要表无法表达的窗口聚合。
type MetricExporter struct {
	db           *gorm.DB
	table        string
	closed       atomic.Bool
	errorHandler *handlerkit.ErrorSlot
}

// NewMetricExporter 在调用方持有的 db 会话上把 metric
// 数据点写入 table。
func NewMetricExporter(db *gorm.DB, table string) (*MetricExporter, error) {
	if db == nil {
		return nil, fmt.Errorf("database: NewMetricExporter: nil db")
	}
	if err := validateTable(table, "Table"); err != nil {
		return nil, fmt.Errorf("database: %w", err)
	}
	e := &MetricExporter{db: db, table: table}
	e.errorHandler = handlerkit.NewErrorSlot(mebsuta.DefaultErrorHandler())
	return e, nil
}

// Export 把一次采集摊平成行，并在单个
// 事务中插入。
func (e *MetricExporter) Export(ctx context.Context, rm *sdkmetricdata.ResourceMetrics) error {
	if e.closed.Load() || rm == nil {
		return nil
	}
	svc := resourceServiceName(rm.Resource)
	var rows []MetricRow
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			rows = append(rows, metricRows(m, svc)...)
		}
	}
	if len(rows) == 0 {
		return nil
	}
	err := e.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		return tx.Table(e.table).CreateInBatches(rows, exporterChunkRows).Error
	})
	if err != nil {
		return fmt.Errorf("database: metric export to %s: %s", e.table, sanitizeDBError(err))
	}
	return nil
}

// Temporality 对每种仪器类型强制 Cumulative（见
// MetricExporter 文档）。
func (e *MetricExporter) Temporality(sdkmetric.InstrumentKind) sdkmetricdata.Temporality {
	return sdkmetricdata.CumulativeTemporality
}

// Aggregation 委托给 SDK 默认选择器。
func (e *MetricExporter) Aggregation(k sdkmetric.InstrumentKind) sdkmetric.Aggregation {
	return sdkmetric.DefaultAggregationSelector(k)
}

// ForceFlush 是 no-op：导出是同步插入。
func (e *MetricExporter) ForceFlush(context.Context) error { return nil }

// Shutdown 幂等且不释放任何资源——db 会话归
// 调用方所有。
func (e *MetricExporter) Shutdown(context.Context) error {
	e.closed.Store(true)
	return nil
}

// SetErrorHandler 接入 mebsuta 错误处理器链。
func (e *MetricExporter) SetErrorHandler(fn mebsuta.ErrorHandler) {
	e.errorHandler.Store(fn)
}

var _ sdkmetric.Exporter = (*MetricExporter)(nil)

func metricRows(m sdkmetricdata.Metrics, svc string) []MetricRow {
	attrs := func(a attribute.Set) json.RawMessage {
		if a.Len() == 0 {
			return nil
		}
		kvs := a.ToSlice()
		return attrsJSON(kvs)
	}
	switch data := m.Data.(type) {
	case sdkmetricdata.Sum[int64]:
		rows := make([]MetricRow, 0, len(data.DataPoints))
		for _, dp := range data.DataPoints {
			v := float64(dp.Value)
			rows = append(rows, MetricRow{
				ID: newRecordID(), Name: m.Name, Kind: "sum", Monotonic: data.IsMonotonic,
				Temporality: data.Temporality.String(), Value: &v,
				Attributes: attrs(dp.Attributes), ServiceName: svc, StartTS: dp.StartTime, TS: dp.Time,
			})
		}
		return rows
	case sdkmetricdata.Sum[float64]:
		rows := make([]MetricRow, 0, len(data.DataPoints))
		for _, dp := range data.DataPoints {
			v := dp.Value
			rows = append(rows, MetricRow{
				ID: newRecordID(), Name: m.Name, Kind: "sum", Monotonic: data.IsMonotonic,
				Temporality: data.Temporality.String(), Value: &v,
				Attributes: attrs(dp.Attributes), ServiceName: svc, StartTS: dp.StartTime, TS: dp.Time,
			})
		}
		return rows
	case sdkmetricdata.Gauge[int64]:
		rows := make([]MetricRow, 0, len(data.DataPoints))
		for _, dp := range data.DataPoints {
			v := float64(dp.Value)
			rows = append(rows, MetricRow{
				ID: newRecordID(), Name: m.Name, Kind: "gauge",
				Value: &v, Attributes: attrs(dp.Attributes), ServiceName: svc, TS: dp.Time,
			})
		}
		return rows
	case sdkmetricdata.Gauge[float64]:
		rows := make([]MetricRow, 0, len(data.DataPoints))
		for _, dp := range data.DataPoints {
			v := dp.Value
			rows = append(rows, MetricRow{
				ID: newRecordID(), Name: m.Name, Kind: "gauge",
				Value: &v, Attributes: attrs(dp.Attributes), ServiceName: svc, TS: dp.Time,
			})
		}
		return rows
	case sdkmetricdata.Histogram[int64]:
		return histogramRows(m.Name, intHistogramToFloat(data), svc)
	case sdkmetricdata.Histogram[float64]:
		return histogramRows(m.Name, data, svc)
	default:
		// 指数直方图与异构聚合不会被 database
		// 后端持久化；请为它们使用 OTLP 路径。
		return nil
	}
}

func intHistogramToFloat(h sdkmetricdata.Histogram[int64]) sdkmetricdata.Histogram[float64] {
	dps := make([]sdkmetricdata.HistogramDataPoint[float64], 0, len(h.DataPoints))
	for _, dp := range h.DataPoints {
		sum := float64(dp.Sum)
		dps = append(dps, sdkmetricdata.HistogramDataPoint[float64]{
			Attributes:   dp.Attributes,
			StartTime:    dp.StartTime,
			Time:         dp.Time,
			Count:        dp.Count,
			Bounds:       dp.Bounds,
			BucketCounts: dp.BucketCounts,
			Sum:          sum,
			// Min/Max 极值不持久化；见 histogramRows。
		})
	}
	return sdkmetricdata.Histogram[float64]{DataPoints: dps, Temporality: h.Temporality}
}

func histogramRows(name string, h sdkmetricdata.Histogram[float64], svc string) []MetricRow {
	rows := make([]MetricRow, 0, len(h.DataPoints))
	for _, dp := range h.DataPoints {
		// G115（第五轮审计 P4）：uint64 Count → int64 列钳制。
		// 超过 MaxInt64 的观测计数物理上不可达；
		// 钳制的存在使转换不会静默回绕。
		count := int64(dp.Count) // #nosec G115——由下方钳制防护；gosec 看不到该防护
		if dp.Count > uint64(math.MaxInt64) {
			count = math.MaxInt64
		}
		sum := dp.Sum
		rows = append(rows, MetricRow{
			ID: newRecordID(), Name: name, Kind: "histogram",
			Temporality: h.Temporality.String(), Sum: &sum, Count: &count,
			Attributes: attrSetJSON(dp.Attributes), ServiceName: svc, StartTS: dp.StartTime, TS: dp.Time,
		})
	}
	return rows
}

// attrsJSON 将键值对序列化为展平的 jsonb 文档；
// 输入为空时为 nil。
func attrsJSON(kvs []attribute.KeyValue) json.RawMessage {
	if len(kvs) == 0 {
		return nil
	}
	m := make(map[string]any, len(kvs))
	for _, kv := range kvs {
		m[string(kv.Key)] = exportAttrValue(kv.Value)
	}
	data, err := json.Marshal(m)
	if err != nil {
		return nil
	}
	return data
}

// exportAttrValue 把 otel 属性值转换为 jsonb 可直接存储的原生 JSON
// 类型。此前经 deprecated 的 Emit()——一切值都落成字符串，数值与
// 布尔在 jsonb 消费方的类型匹配查询里查不到。NaN/Inf 不是合法
// JSON，转字符串保留信息；[]byte 以 UTF-8 字符串存储（与 slog 管线
// 的字节处理一致）。其余类型（string/int64/bool/切片等）是 JSON
// 原生形态，原样通过。
func exportAttrValue(v attribute.Value) any {
	switch av := v.AsInterface().(type) {
	case float64:
		if math.IsNaN(av) || math.IsInf(av, 0) {
			return strconv.FormatFloat(av, 'g', -1, 64)
		}
		return av
	case []byte:
		return string(av)
	default:
		return av
	}
}

// resourceServiceName 从 OTel resource 提取 service.name；
// 缺失时为空字符串（行随后依赖表默认值）。
func resourceServiceName(res *sdkresource.Resource) string {
	if res == nil {
		return ""
	}
	if v, ok := res.Set().Value(semconvServiceNameKey); ok {
		return v.AsString()
	}
	return ""
}

func attrSetJSON(set attribute.Set) json.RawMessage {
	if set.Len() == 0 {
		return nil
	}
	return attrsJSON(set.ToSlice())
}

// AutoMigrateTables 依据行结构体创建 span/metric 表
// （与驱动无关；兼容 sqlite）。供无法运行
// PG 风格参考 DDL 的会话使用。
func AutoMigrateTables(db *gorm.DB, spanTable, metricTable string) error {
	if db == nil {
		return fmt.Errorf("database: AutoMigrateTables: nil db")
	}
	// 与 EnsureTables/NewSpanExporter 相同的表名规则：gorm 的
	// 标识符转义是外墙，这是纵深防御的
	// 内墙（第五轮审计 P3——两兄弟不能不一致）。
	for _, t := range []string{spanTable, metricTable} {
		if err := validateTable(t, "Table"); err != nil {
			return fmt.Errorf("database: %w", err)
		}
	}
	if err := db.Table(spanTable).AutoMigrate(&SpanRow{}); err != nil {
		return fmt.Errorf("database: auto migrate %s: %s", spanTable, sanitizeDBError(err))
	}
	if err := db.Table(metricTable).AutoMigrate(&MetricRow{}); err != nil {
		return fmt.Errorf("database: auto migrate %s: %s", metricTable, sanitizeDBError(err))
	}
	return nil
}

// renderDDL 以 table 填充 DDL 模板的全部 %s 槽位。槽位数按模板
// 计数、不由调用方传参：SpansTableDDL 与 MetricsTableDDL 的槽位数
// 不同（7 与 5），此前的固定 7 参数让 metrics 表渲染出 %!(EXTRA…)
// 并在真实 PostgreSQL/openGauss 上必然执行失败。
func renderDDL(ddl, table string) (string, error) {
	n := strings.Count(ddl, "%s")
	if n == 0 {
		return "", fmt.Errorf("ddl template has no %%s placeholders")
	}
	args := make([]any, n)
	for i := range args {
		args[i] = table
	}
	return fmt.Sprintf(ddl, args...), nil
}

// EnsureTables 用参考 DDL 在表缺失时创建 span/metric 表。
// 表名必须已校验（Validate /
// NewSpanExporter 语义）。面向 telemetry database
// 后端的 EnsureSchema 默认；偏好显式 schema
// 管理的运维可在此退出并自行执行 DDL。
func EnsureTables(db *gorm.DB, spanTable, metricTable string) error {
	if db == nil {
		return fmt.Errorf("database: EnsureTables: nil db")
	}
	for _, t := range []string{spanTable, metricTable} {
		if err := validateTable(t, "Table"); err != nil {
			return fmt.Errorf("database: %w", err)
		}
	}
	stmts := []struct{ ddl, table string }{
		{SpansTableDDL, spanTable},
		{MetricsTableDDL, metricTable},
	}
	for _, s := range stmts {
		// DDL 模板自带索引语句，含多个 %s 槽位用于（已校验的）
		// 表名；槽位数由 renderDDL 按模板填充。
		sqlText, err := renderDDL(s.ddl, s.table)
		if err != nil {
			return fmt.Errorf("database: ensure table %s: %w", s.table, err)
		}
		if err := db.Exec(sqlText).Error; err != nil {
			return fmt.Errorf("database: ensure table %s: %s", s.table, sanitizeDBError(err))
		}
	}
	return nil
}
