package telemetry

import (
	"context"
	"testing"
	"time"

	"github.com/iuboy/mebsuta/database"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// TestStart_DatabaseBackend 端到端覆盖部署模式 B：span 与指标落入注入会话
// 的表中，LoggerProvider 保持 no-op（日志属于 slog 数据库 handler 通路），
// 且 Shutdown 在返回前完成冲刷。
func TestStart_DatabaseBackend(t *testing.T) {
	gdb, err := gorm.Open(sqlite.Open(t.TempDir()+"/telemetry.db"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, database.AutoMigrateTables(gdb, "t_spans", "t_metrics"))

	no := false
	tel, err := Start(context.Background(), Config{
		ServiceName: "db-mode-svc",
		Signals:     Traces | Metrics,
		SetGlobal:   &no,
		Database: &DatabaseConfig{
			Driver:      "postgres", // 注入会话；DSN 未用到
			TracesTable: "t_spans", MetricsTable: "t_metrics",
			db: gdb,
		},
		MetricExportInterval: 50 * time.Millisecond,
	})
	require.NoError(t, err)
	require.True(t, tel.Enabled())

	// Logs 信号只走 OTLP：无 endpoint 时该 provider 为 no-op。
	require.NotNil(t, tel.LoggerProvider())

	ctx := context.Background()
	_, span := tel.TracerProvider().Tracer("t").Start(ctx, "db-mode-op")
	span.End()
	ctr, err := tel.MeterProvider().Meter("m").Int64Counter("db_mode_total")
	require.NoError(t, err)
	ctr.Add(ctx, 2)

	require.NoError(t, tel.Shutdown(context.Background()))

	var spans []struct {
		Name        string
		ServiceName string
	}
	require.NoError(t, gdb.Table("t_spans").Find(&spans).Error)
	require.Len(t, spans, 1)
	require.Equal(t, "db-mode-op", spans[0].Name)
	require.Equal(t, "db-mode-svc", spans[0].ServiceName)

	var metrics []struct {
		Name        string
		Kind        string
		Value       *float64
		ServiceName string
	}
	require.NoError(t, gdb.Table("t_metrics").Find(&metrics).Error)
	require.Len(t, metrics, 1)
	require.Equal(t, "db_mode_total", metrics[0].Name)
	require.Equal(t, "sum", metrics[0].Kind)
	require.NotNil(t, metrics[0].Value)
	require.Equal(t, 2.0, *metrics[0].Value)
	require.Equal(t, "db-mode-svc", metrics[0].ServiceName)
}

// TestStart_DatabaseConfigValidation 钉住跨字段规则。
func TestStart_DatabaseConfigValidation(t *testing.T) {
	_, err := Start(context.Background(), Config{
		ServiceName: "s",
		Database:    &DatabaseConfig{Driver: "mysql", DSN: "x"},
	})
	require.ErrorContains(t, err, "Driver")

	_, err = Start(context.Background(), Config{
		ServiceName: "s",
		Database:    &DatabaseConfig{Driver: "postgres"},
	})
	require.ErrorContains(t, err, "DSN")

	// 已填充默认值：表名。
	cfg := Config{ServiceName: "s", Database: &DatabaseConfig{Driver: "postgres", DSN: "host=localhost"}}
	_, err = cfg.Validate()
	require.NoError(t, err)
	require.Equal(t, "mebsuta_traces", cfg.Database.TracesTable)
	require.Equal(t, "mebsuta_metrics", cfg.Database.MetricsTable)

	// 两个后端都未设置时，no-op 模式保持不变。
	noop, err := Start(context.Background(), Config{})
	require.NoError(t, err)
	require.False(t, noop.Enabled())
}
