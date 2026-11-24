package telemetry

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/iuboy/mebsuta"
	"github.com/iuboy/mebsuta/database"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	sdkmetricdata "go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"gorm.io/gorm"
)

// DatabaseConfig 为 traces 与 metrics 信号选择数据库后端（部署模式 B——
// "mebsuta 写数据库"）。日志有自己的第一等数据库通路（mebsuta 的 database
// slog handler，支持事务性双写）；telemetry 的 Logs 信号只走 OTLP，因此
// 设置了 Database 而未设 Endpoint 时，LoggerProvider 保持 no-op。
//
// 当 Database 与 Endpoint 同时设置时，traces 与 metrics 双写（同一
// provider 下挂 OTLP exporter + 数据库 exporter），日志照常走 OTLP。
type DatabaseConfig struct {
	// Driver："postgres" 或 "opengauss"（与 log handler 规则相同）。
	Driver string
	// DSN 是连接串。
	DSN string
	// TracesTable / MetricsTable 选择目标表。
	// "" → database.DefaultTracesTable / DefaultMetricsTable。
	TracesTable  string
	MetricsTable string
	// EnsureSchema 在表缺失时用参考 DDL 建表（CREATE TABLE IF NOT
	// EXISTS——幂等）。nil → true。显式管理 schema 的运维人员将其
	// 置为 false。
	EnsureSchema *bool
	// 连接池设置；零值字段保持 database/sql 默认。
	MaxOpenConns    int
	MaxIdleConns    int
	MaxConnLifetime time.Duration

	// db 供包内测试注入会话（sqlite），而非拨号真实的 PostgreSQL。
	db *gorm.DB
}

// validate 校验数据库后端字段并填充默认表名。
func (c *DatabaseConfig) validate() error {
	if c.Driver == "" {
		return &mebsuta.ConfigError{Field: "Database.Driver", Msg: "必填"}
	}
	if c.Driver != "postgres" && c.Driver != "opengauss" {
		return &mebsuta.ConfigError{Field: "Database.Driver", Msg: fmt.Sprintf("%q 不受支持（支持 postgres / opengauss）", c.Driver)}
	}
	// 注入会话（测试）自带连接；DSN 仅在 telemetry 自行拨号时必填。
	if c.db == nil && c.DSN == "" {
		return &mebsuta.ConfigError{Field: "Database.DSN", Msg: "必填"}
	}
	if c.TracesTable == "" {
		c.TracesTable = database.DefaultTracesTable
	}
	if c.MetricsTable == "" {
		c.MetricsTable = database.DefaultMetricsTable
	}
	return nil
}

// openDatabase 解析会话：优先用注入的测试会话，否则由 Telemetry 自行
// 拨号并持有（负责关闭）。
func (c *DatabaseConfig) openDatabase() (*gorm.DB, *sql.DB, error) {
	if c.db != nil {
		return c.db, nil, nil
	}
	gdb, sqlDB, err := database.OpenGorm(c.Driver, c.DSN, database.PoolConfig{
		MaxOpenConns:    c.MaxOpenConns,
		MaxIdleConns:    c.MaxIdleConns,
		MaxConnLifetime: c.MaxConnLifetime,
	})
	if err != nil {
		return nil, nil, err
	}
	return gdb, sqlDB, nil
}

// String 实现 fmt.Stringer 并脱敏(B19):DatabaseConfig 此前没有任何
// 渲染方法,%v / slog.Any 直接打印原始 DSN——外层 telemetry.Config 的
// String/GoString 挡不住这一条渲染路径。DSN 整体掩码(与 render.go 的
// dsnMask 同一口径:telemetry 从不需要从渲染字符串重新连接)。
func (c DatabaseConfig) String() string {
	return c.renderBody()
}

// GoString 实现 fmt.GoStringer,与 String 同样的脱敏,使 %#v 输出
// (调试器、错误模板)也无法泄漏 DSN。
func (c DatabaseConfig) GoString() string {
	return "telemetry.DatabaseConfig{" + c.renderBody() + "}"
}

// MarshalJSON 渲染脱敏副本:json.Marshal 此前走默认反射序列化,
// 原始 DSN 原样落进任何结构化输出。
func (c DatabaseConfig) MarshalJSON() ([]byte, error) {
	// 类型转换剥掉 MarshalJSON 方法,避免递归。
	type plain DatabaseConfig
	p := plain(c)
	// 裸 ***(不带 dsnMask 的引号装饰):JSON 值自带引号,双层引号
	// ("***")对消费方是噪声。
	p.DSN = "***"
	return json.Marshal(p)
}

func (c DatabaseConfig) renderBody() string {
	return fmt.Sprintf("Driver:%s DSN:%s TracesTable:%q MetricsTable:%q EnsureSchema:%v MaxOpenConns:%d MaxIdleConns:%d MaxConnLifetime:%s",
		c.Driver, dsnMask(c.DSN), c.TracesTable, c.MetricsTable,
		c.EnsureSchema, c.MaxOpenConns, c.MaxIdleConns, c.MaxConnLifetime)
}

// spanFanout 导出到其下所有 span exporter；在 OTLP 端点与数据库后端
// 同时配置时使用。
type spanFanout []sdktrace.SpanExporter

func (f spanFanout) ExportSpans(ctx context.Context, spans []sdktrace.ReadOnlySpan) error {
	var errs []error
	for _, e := range f {
		if err := e.ExportSpans(ctx, spans); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (f spanFanout) Shutdown(ctx context.Context) error {
	var errs []error
	for _, e := range f {
		if err := e.Shutdown(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// metricFanout 是 spanFanout 在 metric 一侧的等价物。
type metricFanout []sdkmetric.Exporter

func (f metricFanout) Export(ctx context.Context, data *sdkmetricdata.ResourceMetrics) error {
	var errs []error
	for _, e := range f {
		if err := e.Export(ctx, data); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (f metricFanout) Temporality(k sdkmetric.InstrumentKind) sdkmetricdata.Temporality {
	if len(f) > 0 {
		return f[0].Temporality(k)
	}
	return sdkmetricdata.CumulativeTemporality
}

func (f metricFanout) Aggregation(k sdkmetric.InstrumentKind) sdkmetric.Aggregation {
	if len(f) > 0 {
		return f[0].Aggregation(k)
	}
	return sdkmetric.DefaultAggregationSelector(k)
}

func (f metricFanout) ForceFlush(ctx context.Context) error {
	var errs []error
	for _, e := range f {
		if err := e.ForceFlush(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (f metricFanout) Shutdown(ctx context.Context) error {
	var errs []error
	for _, e := range f {
		if err := e.Shutdown(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// ensureSchemaSQLiteAware 创建后端表：对自行拨号的 PostgreSQL/openGauss
// 会话用参考 DDL；对无法执行 PG 风格 DDL 的注入（测试、sqlite）会话用
// 基于结构体的迁移。
func ensureSchemaSQLiteAware(gdb *gorm.DB, cfg *DatabaseConfig) error {
	if cfg.db != nil {
		return database.AutoMigrateTables(gdb, cfg.TracesTable, cfg.MetricsTable)
	}
	return database.EnsureTables(gdb, cfg.TracesTable, cfg.MetricsTable)
}
