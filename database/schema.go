package database

import (
	"encoding/json"
	"time"
)

// dbLogEntry 是一条日志记录的持久化形态，与
// OpenTelemetry 日志数据模型对齐：经典 mebsuta 列（time、level、
// msg、fields、完整性三件套）之外，还有 id（ULID 身份/游标）、
// observed_time、severity_number、trace_id/span_id（十六进制）、service_name
// 与 relayed_at（事务双写 outbox 标记，NULL = 待
// relay）。DDL 由运维负责——LogsTableDDL 是参考契约。
type dbLogEntry struct {
	// ID 是 ULID 记录身份：消费方的幂等键，
	// 也是增量 relay/消费的单调游标。
	ID string `gorm:"column:id"`
	// Time 是事件时间（slog Record.Time）。
	Time time.Time `gorm:"column:time"`
	// ObservedTime 是摄入时间（mebsuta 处理该记录时）。
	ObservedTime time.Time `gorm:"column:observed_time"`
	// Level 是严重度的文本形式（"INFO"、"WARN"、"AUDIT" 等）。
	Level string `gorm:"column:level"`
	// SeverityNumber 是规范的 OTel 数值严重度
	//（mebsuta.SeverityNumber；LevelAudit 映射为 21）。
	SeverityNumber int `gorm:"column:severity_number"`
	// Message 是记录主体。
	Message string `gorm:"column:msg"`
	// Fields 是展平后的属性文档（jsonb）。
	Fields json.RawMessage `gorm:"column:fields;type:jsonb"`
	// TraceID / SpanID 携带发出上下文的日志-链路关联
	//（十六进制，span 外记录时为空）。
	TraceID string `gorm:"column:trace_id"`
	SpanID  string `gorm:"column:span_id"`
	// ServiceName 为 OTel 语义的消费者标记行（resource
	// service.name）；Config.ServiceName 未设置时为空。
	ServiceName string `gorm:"column:service_name"`
	// RelayedAt 标记事务双写投递：NULL = 待
	// relay，已设置 = 已投递到 OTLP 侧。不使用
	// 一致性模式的消费者可以忽略该列。
	RelayedAt *time.Time `gorm:"column:relayed_at"`
	// 完整性保护——设置 Config.IntegritySigner 时填充。
	// id、observed_time、severity_number、trace_id、span_id、service_name
	// 与 relayed_at 刻意排除在签名的规范形之外：
	// 它们是路由/关联元数据，且 relayed_at 必须可变
	// 以支持重投。覆盖范围见 CanonicalBytes。
	RecordHash string `gorm:"column:record_hash;default:''"`
	Signature  []byte `gorm:"column:signature;type:bytea"`
	SignAlgo   string `gorm:"column:sign_algo;size:32;default:''"`
}

// LogsTableDDL 是日志表的参考 CREATE TABLE。DDL
// 由运维负责；此契约的存在是为了让 mebsuta 写入方与
// 外部消费者（mebsuta-forwarder 的 database source、审计工具）
// 无需读 Go 结构体就能对列达成一致。%s 是（已校验的）
// 表名——只能用通过了 Validate 的 Config.Table 去
// fmt.Sprintf，绝不接受用户输入。
//
// id 上的唯一索引把模糊提交重复窗口（见 flush 的
// 文档说明）转化为插入冲突而非静默
// 重复；relayed_at 上的部分索引让对账
// 扫描保持廉价。
const LogsTableDDL = `CREATE TABLE IF NOT EXISTS %s (
	id              TEXT NOT NULL,
	time            TIMESTAMPTZ NOT NULL,
	observed_time   TIMESTAMPTZ NOT NULL,
	level           TEXT NOT NULL,
	severity_number INTEGER NOT NULL DEFAULT 0,
	msg             TEXT NOT NULL,
	fields          JSONB,
	trace_id        TEXT NOT NULL DEFAULT '',
	span_id         TEXT NOT NULL DEFAULT '',
	service_name    TEXT NOT NULL DEFAULT '',
	relayed_at      TIMESTAMPTZ,
	record_hash     TEXT NOT NULL DEFAULT '',
	signature       BYTEA,
	sign_algo       TEXT NOT NULL DEFAULT ''
);
CREATE UNIQUE INDEX IF NOT EXISTS %s_id_uk ON %s (id);
CREATE INDEX IF NOT EXISTS %s_relay_pending_ix ON %s (id) WHERE relayed_at IS NULL;`
