//go:build integration

package database

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/iuboy/mebsuta"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/gaussdb"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func openGormDB(driver, dsn string) (*gorm.DB, error) {
	switch driver {
	case "opengauss":
		return gorm.Open(gaussdb.Open(dsn), &gorm.Config{})
	default: // "postgres"
		return gorm.Open(postgres.Open(dsn), &gorm.Config{})
	}
}

// jsonbRow 镜像带 JSONB fields 列的日志表——即 json →
// jsonb 迁移产生的形态。
type jsonbRow struct {
	Time       time.Time       `gorm:"column:time"`
	Level      string          `gorm:"column:level"`
	Message    string          `gorm:"column:msg"`
	Fields     json.RawMessage `gorm:"column:fields;type:jsonb"`
	RecordHash string          `gorm:"column:record_hash"`
	Signature  []byte          `gorm:"column:signature"`
	SignAlgo   string          `gorm:"column:sign_algo"`
	// OTel 对齐的 v2 列（不进入下方断言——往返
	// 只检验已签名的规范核心）。
	ID             string     `gorm:"column:id"`
	ObservedTime   time.Time  `gorm:"column:observed_time"`
	SeverityNumber int        `gorm:"column:severity_number"`
	TraceID        string     `gorm:"column:trace_id"`
	SpanID         string     `gorm:"column:span_id"`
	ServiceName    string     `gorm:"column:service_name"`
	RelayedAt      *time.Time `gorm:"column:relayed_at"`
}

func (jsonbRow) TableName() string { return "logs_jsonb_test" }

// TestIntegrity_JsonbRoundTrip 端到端证明规范化的 jsonb
// 透明性：写入时签名的记录（含 Go 以指数形式渲染的
// 浮点值，如 1e+21）在 PostgreSQL 的 jsonb 把数字字面量
// 改写为纯小数后仍校验通过。
func TestIntegrity_JsonbRoundTrip(t *testing.T) {
	gdb, err := gorm.Open(postgres.Open(postgresDSN()), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, _ := gdb.DB()
	defer sqlDB.Close()

	require.NoError(t, gdb.Migrator().DropTable("logs_jsonb_test"))
	// 先用 json 列创建，再原地迁移——同时覆盖
	//“生来就是 jsonb”与“从 json 迁移”两种部署。
	require.NoError(t, gdb.Exec(`CREATE TABLE logs_jsonb_test (
		id TEXT NOT NULL, time TIMESTAMPTZ NOT NULL, observed_time TIMESTAMPTZ NOT NULL,
		level TEXT NOT NULL, severity_number INTEGER NOT NULL DEFAULT 0, msg TEXT NOT NULL,
		fields JSON, trace_id TEXT NOT NULL DEFAULT '', span_id TEXT NOT NULL DEFAULT '',
		service_name TEXT NOT NULL DEFAULT '', relayed_at TIMESTAMPTZ,
		record_hash TEXT NOT NULL DEFAULT '', signature BYTEA, sign_algo TEXT NOT NULL DEFAULT '')`).Error)

	h, err := NewHandler(Config{
		Driver: "postgres", DSN: postgresDSN(), Table: "logs_jsonb_test",
		Level: slog.LevelDebug, BatchSize: 10, BatchInterval: 100 * time.Millisecond,
		IntegritySigner: mockSigner{},
	})
	require.NoError(t, err)

	logger := slog.New(h)
	logger.Info("big numbers",
		"big", 1e21, // Go 序列化为 1e+21 → jsonb 改写为纯小数
		"amount", 9007199254740993, // 2^53+1：float64 孪生边界，必须保持精确
		"ratio", 12.5,
	)
	require.NoError(t, h.Close())

	// 原地迁移：json → jsonb 改写存储的数字写法。
	require.NoError(t, gdb.Exec(`ALTER TABLE logs_jsonb_test ALTER COLUMN fields TYPE JSONB USING fields::jsonb`).Error)

	var rows []jsonbRow
	require.NoError(t, gdb.Find(&rows).Error)
	require.NotEmpty(t, rows, "signed record must be persisted")
	require.Len(t, rows, 1)

	row := rows[0]
	t.Logf("fields after jsonb migration: %s", string(row.Fields))

	rec := StoredRecord{
		Time: row.Time, Level: row.Level, Message: row.Message,
		Fields: row.Fields, SignAlgo: row.SignAlgo,
	}
	require.NoError(t, VerifyRecord(rec, row.RecordHash, row.Signature, &mockVerifier{}),
		"untampered record must verify after json→jsonb migration")

	// 迁移后篡改仍能被发现：把 amount 改成它的
	// float64 孪生值（9007199254740992）。
	var tamperedText string
	require.NoError(t, gdb.Raw(`SELECT replace(fields::text, '9007199254740993', '9007199254740992')::jsonb FROM logs_jsonb_test`).Scan(&tamperedText).Error)
	rec.Fields = json.RawMessage(tamperedText)
	err = VerifyRecord(rec, row.RecordHash, row.Signature, &mockVerifier{})
	require.ErrorIs(t, err, ErrHashMismatch, "float64-twin tampering must be detected after migration")

}

func postgresDSN() string {
	if dsn := os.Getenv("MEBSUTA_POSTGRES_DSN"); dsn != "" {
		return dsn
	}
	return "host=127.0.0.1 port=5432 user=test password=test dbname=logs sslmode=disable"
}

func newPostgresHandler(t *testing.T) (*Handler, *gorm.DB) {
	t.Helper()

	table := "logs_pg_" + time.Now().Format("20060102150405")

	h, err := NewHandler(Config{
		Driver:        "postgres",
		DSN:           postgresDSN(),
		Table:         table,
		Level:         slog.LevelDebug,
		BatchSize:     10,
		BatchInterval: 200 * time.Millisecond,
		RetryDelay:    100 * time.Millisecond,
	})
	require.NoError(t, err, "NewHandler postgres")

	gdb, err := openGormDB("postgres", postgresDSN())
	require.NoError(t, err, "open verification db")
	require.NoError(t, gdb.Table(table).AutoMigrate(&dbLogEntry{}), "auto migrate")
	t.Cleanup(func() {
		h.Close()
		gdb.Exec("DROP TABLE IF EXISTS " + table)
		sqlDB, _ := gdb.DB()
		if sqlDB != nil {
			sqlDB.Close()
		}
	})

	return h, gdb
}

func TestIntegration_Postgres_WriteAndRead(t *testing.T) {
	h, gdb := newPostgresHandler(t)

	r := slog.NewRecord(time.Date(2026, 1, 15, 10, 30, 0, 0, time.UTC), slog.LevelInfo, "hello postgres", 0)
	r.AddAttrs(slog.String("key", "value"))
	require.NoError(t, h.Handle(context.Background(), r), "Handle")

	require.Eventually(t, func() bool {
		var count int64
		gdb.Table(h.table).Count(&count)
		return count >= 1
	}, 5*time.Second, 100*time.Millisecond, "record should appear in PostgreSQL")

	var entries []dbLogEntry
	require.NoError(t, gdb.Table(h.table).Find(&entries).Error)
	require.Len(t, entries, 1)
	require.Equal(t, "hello postgres", entries[0].Message)
	require.Equal(t, "INFO", entries[0].Level)

	var fields map[string]any
	require.NoError(t, json.Unmarshal(entries[0].Fields, &fields))
	require.Equal(t, "value", fields["key"])
}

func TestIntegration_Postgres_BatchWrite(t *testing.T) {
	h, gdb := newPostgresHandler(t)

	for i := range 25 {
		r := slog.NewRecord(time.Now(), slog.LevelInfo, "batch msg", 0)
		r.AddAttrs(slog.Int("i", i))
		require.NoError(t, h.Handle(context.Background(), r), "Handle", i)
	}

	require.Eventually(t, func() bool {
		var count int64
		gdb.Table(h.table).Count(&count)
		return count >= 25
	}, 10*time.Second, 200*time.Millisecond, "all 25 records should appear")

	var count int64
	gdb.Table(h.table).Count(&count)
	require.Equal(t, int64(25), count)
}

func TestIntegration_Postgres_AuditLevel(t *testing.T) {
	h, gdb := newPostgresHandler(t)

	r := slog.NewRecord(time.Now(), mebsuta.LevelAudit, "audit event", 0)
	r.AddAttrs(slog.String("event_type", "delete"), slog.Bool("success", true))
	require.NoError(t, h.Handle(context.Background(), r), "Handle")

	require.Eventually(t, func() bool {
		var count int64
		gdb.Table(h.table).Count(&count)
		return count >= 1
	}, 5*time.Second, 100*time.Millisecond)

	var entries []dbLogEntry
	require.NoError(t, gdb.Table(h.table).Find(&entries).Error)
	require.Len(t, entries, 1)
	require.Equal(t, (slog.LevelError + 4).String(), entries[0].Level)

	var fields map[string]any
	require.NoError(t, json.Unmarshal(entries[0].Fields, &fields))
	require.Equal(t, "delete", fields["event_type"])
}

func openGaussDSN() string {
	if dsn := os.Getenv("MEBSUTA_OPENGAUSS_DSN"); dsn != "" {
		return dsn
	}
	return "host=127.0.0.1 port=15400 user=mebsuta_test password=MebsutaTest#2026 dbname=logs sslmode=disable"
}

func newOpenGaussHandler(t *testing.T) (*Handler, *gorm.DB) {
	t.Helper()

	table := "logs_og_" + time.Now().Format("20060102150405")

	h, err := NewHandler(Config{
		Driver:        "opengauss",
		DSN:           openGaussDSN(),
		Table:         table,
		Level:         slog.LevelDebug,
		BatchSize:     10,
		BatchInterval: 200 * time.Millisecond,
		RetryDelay:    100 * time.Millisecond,
	})
	require.NoError(t, err, "NewHandler opengauss")

	gdb, err := openGormDB("opengauss", openGaussDSN())
	require.NoError(t, err, "open verification db")
	require.NoError(t, gdb.Table(table).AutoMigrate(&dbLogEntry{}), "auto migrate")
	t.Cleanup(func() {
		h.Close()
		gdb.Exec("DROP TABLE IF EXISTS " + table)
		sqlDB, _ := gdb.DB()
		if sqlDB != nil {
			sqlDB.Close()
		}
	})

	return h, gdb
}

func TestIntegration_OpenGauss_WriteAndRead(t *testing.T) {
	h, gdb := newOpenGaussHandler(t)

	r := slog.NewRecord(time.Date(2026, 1, 15, 10, 30, 0, 0, time.UTC), slog.LevelInfo, "hello opengauss", 0)
	r.AddAttrs(slog.String("key", "value"))
	require.NoError(t, h.Handle(context.Background(), r), "Handle")

	require.Eventually(t, func() bool {
		var count int64
		gdb.Table(h.table).Count(&count)
		return count >= 1
	}, 5*time.Second, 100*time.Millisecond, "record should appear in openGauss")

	var entries []dbLogEntry
	require.NoError(t, gdb.Table(h.table).Find(&entries).Error)
	require.Len(t, entries, 1)
	require.Equal(t, "hello opengauss", entries[0].Message)
	require.Equal(t, "INFO", entries[0].Level)

	var fields map[string]any
	require.NoError(t, json.Unmarshal(entries[0].Fields, &fields))
	require.Equal(t, "value", fields["key"])
}

func TestIntegration_OpenGauss_BatchWrite(t *testing.T) {
	h, gdb := newOpenGaussHandler(t)

	for i := range 25 {
		r := slog.NewRecord(time.Now(), slog.LevelInfo, "batch msg", 0)
		r.AddAttrs(slog.Int("i", i))
		require.NoError(t, h.Handle(context.Background(), r), "Handle", i)
	}

	require.Eventually(t, func() bool {
		var count int64
		gdb.Table(h.table).Count(&count)
		return count >= 25
	}, 10*time.Second, 200*time.Millisecond, "all 25 records should appear")

	var count int64
	gdb.Table(h.table).Count(&count)
	require.Equal(t, int64(25), count)
}

func TestIntegration_OpenGauss_AuditLevel(t *testing.T) {
	h, gdb := newOpenGaussHandler(t)

	r := slog.NewRecord(time.Now(), mebsuta.LevelAudit, "audit event", 0)
	r.AddAttrs(slog.String("event_type", "delete"), slog.Bool("success", true))
	require.NoError(t, h.Handle(context.Background(), r), "Handle")

	require.Eventually(t, func() bool {
		var count int64
		gdb.Table(h.table).Count(&count)
		return count >= 1
	}, 5*time.Second, 100*time.Millisecond)

	var entries []dbLogEntry
	require.NoError(t, gdb.Table(h.table).Find(&entries).Error)
	require.Len(t, entries, 1)
	require.Equal(t, (slog.LevelError + 4).String(), entries[0].Level)

	var fields map[string]any
	require.NoError(t, json.Unmarshal(entries[0].Fields, &fields))
	require.Equal(t, "delete", fields["event_type"])
}
