package database

import (
	"fmt"
	"log/slog"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/iuboy/mebsuta"
	"go.opentelemetry.io/otel/log"
)

// tableNameRe 校验 SQL 表名。允许字母数字与
// 下划线，首位可以是数字（PostgreSQL 与 openGauss 经引号
// 转义后均支持）。带 schema 的限定名
// （schema.table）也被接受。显式允许数字开头是因为
// 它在两个受支持的数据库中都是合法表名。
var tableNameRe = regexp.MustCompile(`^[a-zA-Z0-9_]+(\.[a-zA-Z0-9_]+)?$`)

const (
	// maxBatchSize 限制批次大小，防止调用方误配超大
	// BatchSize 时产生无界的 channel/批次分配。
	maxBatchSize = 10000

	// DefaultMaxRecordBytes 是 Config.MaxRecordBytes 未设置时
	// 应用的单记录大小上界。256KiB 容纳丰富的结构化
	// 记录（深层 JSON 文档），同时保证最坏情况下的积压
	// 占用有界：积压保存 BatchSize*10 条，因此默认
	// 批次大小下的上限是 1000 × 256KiB = 256MiB——与 syslog
	// handler 的 maxMsgSize 帧上界同一防御层级，针对
	// 合法携带结构化文档的记录放大了尺寸。
	DefaultMaxRecordBytes = 256 * 1024

	// MaxRecordBytesCap 限制 Config.MaxRecordBytes 上限。对
	// jsonb 类型记录足够宽裕，但对“就一个大字段”式配置是硬墙——
	// 否则该字段要防止的无界积压占用会死灰复燃。
	MaxRecordBytesCap = 8 * 1024 * 1024

	// MaxRetryDelay 限制 Config.RetryDelay，与 syslog handler 一致：
	// 每次失败的刷盘尝试都等待 RetryDelay，误配成数分钟的
	// 延迟会成倍放大最坏刷盘时间，并让 Close 的排空
	// 每次重试都拖那么久。
	MaxRetryDelay = 30 * time.Second
)

// Config 保存 database 日志输出的配置。
type Config struct {
	Driver        string        // 必填："postgres" 或 "opengauss"。
	DSN           string        // 必填：数据库连接串。
	Table         string        // 必填：日志表名。
	Level         slog.Leveler  // 日志级别过滤。默认 slog.LevelInfo。
	BatchSize     int           // 每批记录数。0 → 100。
	BatchInterval time.Duration // 刷盘间隔。0 → 5s。
	// MaxConnLifetime 是连接的最大生命周期。0 = 不限（与其他
	// 字段 0 表示“用默认值”不同，这里遵循 database/sql 的约定：
	// 0 表示不限）。
	MaxConnLifetime time.Duration // 连接最大生命周期。0 = 不限。
	MaxOpenConns    int           // 最大打开连接数。0 → 10。
	MaxIdleConns    int           // 最大空闲连接数。0 → 5。
	RetryDelay      time.Duration // 重试间隔。0 → 500ms，以 MaxRetryDelay 封顶。
	// MaxRecordBytes 限制允许进入积压的单条记录编码后大小
	//（消息长度 + fields JSON 长度）。超过限制的记录保留
	// 消息——UTF-8 安全截断到放得下——但丢失
	// fields：fields 列被替换为
	// {"mebsuta_truncated":true} 标记，丢失计入
	// Handler.Dropped 并经限频丢弃报告上报。
	//
	// 没有该上界，积压（BatchSize*10 条无界大小）可因单条
	// 超大属性膨胀到数百 GB 常驻内存。0 → DefaultMaxRecordBytes；
	// Validate 会把超过 MaxRecordBytesCap 的值钳制。
	MaxRecordBytes int
	// ErrorTimeout 限制 Error 及以上级别的记录在积压 channel
	// 满时阻塞调用方 goroutine 的时长，超过即丢弃
	// 该记录。0 → 1s。保持较小值：请求处理器同步调用
	// slog，这里阻塞太久会让慢数据库把 Error
	// 尖峰放大成整个服务的停顿。
	ErrorTimeout time.Duration
	// IntegritySigner 可选地提供逐记录 hash+签名，用于
	// 防篡改。nil 表示禁用签名（默认，向后兼容）。
	// 设置后，每条记录在批量插入前填充 record_hash /
	// signature / sign_algo 列。handler 与算法无关。
	//
	// signer 必须并发安全（记录会从多个
	// goroutine 签名）。签名还会把存储时间戳截到微秒
	// 精度，保证数据库往返后签名仍可校验
	//（见 CanonicalBytes）。
	IntegritySigner IntegritySigner
	// ServiceName 为持久化行（service_name 列）标记资源
	// 身份，供 OTel 语义消费者使用。可选；为空
	// 存储 ''。
	ServiceName string
	// RelayTo 是事务双写（Consistency.Enabled）用来把已提交
	// 行继续投递出去的 OTel logs 管线——通常是
	// telemetry 引导出的 LoggerProvider。Consistency.Enabled
	// 时必填；否则被忽略。
	RelayTo log.LoggerProvider
	// Consistency 配置事务双写（DB 为事实来源，
	// outbox 标记的 relay）。默认关闭——确切的保证与
	// 显式的非 2PC 边界见 ConsistencyConfig。
	Consistency ConsistencyConfig
	warnNoTLS   bool // 内部：DSN 缺少 TLS 参数时由 Validate 设置。
}

// Validate 检查必填字段，并返回应用默认值后的规范化副本。
func (c Config) Validate() (Config, error) {
	if c.Driver == "" {
		return Config{}, &mebsuta.ConfigError{Field: "Driver", Msg: "driver is required"}
	}
	if c.Driver != "postgres" && c.Driver != "opengauss" {
		return Config{}, &mebsuta.ConfigError{Field: "Driver", Msg: "unsupported driver: " + c.Driver + " (supported: postgres, opengauss)"}
	}
	if c.DSN == "" {
		return Config{}, &mebsuta.ConfigError{Field: "DSN", Msg: "data source name is required"}
	}
	if c.Table == "" {
		return Config{}, &mebsuta.ConfigError{Field: "Table", Msg: "table name is required"}
	}
	if !tableNameRe.MatchString(c.Table) {
		return Config{}, &mebsuta.ConfigError{Field: "Table", Msg: "table name must match [a-zA-Z0-9_](.[a-zA-Z0-9_])?"}
	}
	// M9：PostgreSQL 与 openGauss 的 NAMEDATALEN-1 = 63。
	const maxTableLen = 63
	if len(c.Table) > maxTableLen {
		return Config{}, &mebsuta.ConfigError{Field: "Table", Msg: fmt.Sprintf("table name too long (max %d, got %d)", maxTableLen, len(c.Table))}
	}
	if c.Level == nil {
		c.Level = slog.LevelInfo
	}
	if c.BatchSize <= 0 {
		c.BatchSize = 100
	} else if c.BatchSize > maxBatchSize {
		c.BatchSize = maxBatchSize
	}
	if c.BatchInterval <= 0 {
		c.BatchInterval = 5 * time.Second
	}
	if c.MaxOpenConns <= 0 {
		c.MaxOpenConns = 10
	}
	if c.MaxIdleConns <= 0 {
		c.MaxIdleConns = 5
	}
	// 确保空闲池不超过打开连接上限。
	if c.MaxIdleConns > c.MaxOpenConns {
		c.MaxIdleConns = c.MaxOpenConns
	}
	if c.RetryDelay <= 0 {
		c.RetryDelay = 500 * time.Millisecond
	}
	if c.RetryDelay > MaxRetryDelay {
		c.RetryDelay = MaxRetryDelay
	}
	if c.MaxRecordBytes <= 0 {
		c.MaxRecordBytes = DefaultMaxRecordBytes
	} else if c.MaxRecordBytes > MaxRecordBytesCap {
		c.MaxRecordBytes = MaxRecordBytesCap
	}
	if c.ErrorTimeout <= 0 {
		c.ErrorTimeout = time.Second
	}
	c.Consistency = c.Consistency.validate()
	if c.Consistency.Enabled && c.RelayTo == nil {
		return Config{}, &mebsuta.ConfigError{Field: "RelayTo", Msg: "Consistency.Enabled requires RelayTo (the OTel logs pipeline to relay through)"}
	}

	c.warnNoTLS = !dsnHasTLS(c.DSN)

	return c, nil
}

// dsnHasTLS 检查 DSN 是否包含 TLS/SSL 连接参数。
//
// 这只是尽力而为的启发式，仅用于决定是否发出
// 无 TLS 告警，并不构成任何安全门控。两个方向都可能
// 误判：密码中内嵌的 "sslmode=" 子串会在实际是明文的
// 连接上压制告警（漏报），而 sslmode=prefer 在告警被
// 跳过后仍可能静默回退到明文。把告警当作提示，
// 而非证明。
func dsnHasTLS(dsn string) bool {
	// PostgreSQL key=value DSN：除 "disable" 外的任何 sslmode 都启用
	// TLS（require、verify-ca、verify-full、prefer、allow）。
	dsnLower := strings.ToLower(dsn)
	if !strings.Contains(dsnLower, "sslmode=") {
		return false
	}
	return !strings.Contains(dsnLower, "sslmode=disable")
}

// Sanitize 返回 DSN 中类凭据片段已脱敏的配置副本，规则与
// database 错误消息一致（见 dsnCredRe）。该副本可以安全嵌入
// 日志、错误文本与结构化输出；它不能用于连接——请把原始
// Config 传给 NewHandler。与错误脱敏本身一样，这是尽力而为的
// 文本改写而非 DSN 解析器：包含 '@' 的密码无法用正则从
// 主机分隔符中剥离，只能部分覆盖。
func (c Config) Sanitize() Config {
	if c.DSN != "" {
		c.DSN = redactCredentials(c.DSN)
	}
	return c
}

// String 实现 fmt.Stringer，DSN 凭据已脱敏，因此
// 用 %v 或 %+v 打印 Config 不会泄漏数据库密码。其他
// 字段正常渲染。
func (c Config) String() string {
	level, signer := c.renderAux()
	return fmt.Sprintf(
		"{Driver:%s DSN:%s Table:%s Level:%s BatchSize:%d BatchInterval:%s MaxConnLifetime:%s MaxOpenConns:%d MaxIdleConns:%d RetryDelay:%s ErrorTimeout:%s MaxRecordBytes:%d IntegritySigner:%s}",
		c.Driver, strconv.Quote(c.Sanitize().DSN), c.Table, level,
		c.BatchSize, c.BatchInterval, c.MaxConnLifetime,
		c.MaxOpenConns, c.MaxIdleConns, c.RetryDelay, c.ErrorTimeout,
		c.MaxRecordBytes, signer,
	)
}

// GoString 实现 fmt.GoStringer，脱敏与 String 一致，因此
// %#v 输出（调试器、错误模板）也不会泄漏 DSN 凭据。
// 时长以人类可读形式渲染，而非原始
// 纳秒。
func (c Config) GoString() string {
	level, signer := c.renderAux()
	return fmt.Sprintf(
		"database.Config{Driver:%q, DSN:%s, Table:%q, Level:%q, BatchSize:%d, BatchInterval:%s, MaxConnLifetime:%s, MaxOpenConns:%d, MaxIdleConns:%d, RetryDelay:%s, ErrorTimeout:%s, MaxRecordBytes:%d, IntegritySigner:%s}",
		c.Driver, strconv.Quote(c.Sanitize().DSN), c.Table, level,
		c.BatchSize, c.BatchInterval, c.MaxConnLifetime,
		c.MaxOpenConns, c.MaxIdleConns, c.RetryDelay, c.ErrorTimeout,
		c.MaxRecordBytes, signer,
	)
}

// renderAux 返回 String 与 GoString 共享的 Level 与 IntegritySigner
// 字段渲染。nil Leveler 打印为 "<nil>"；已设置的 signer 打印
// 其算法标识（signer 本身从不渲染）。
func (c Config) renderAux() (level, signer string) {
	level = "<nil>"
	if c.Level != nil {
		// slog.Level 渲染为 "INFO"/"WARN"/…；自定义 Leveler
		// 回退到其自身的 fmt 格式化。
		level = fmt.Sprintf("%v", c.Level)
	}
	signer = "<nil>"
	if c.IntegritySigner != nil {
		signer = c.IntegritySigner.Algorithm()
	}
	return level, signer
}
