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
	"gorm.io/gorm"
)

func mysqlDSN() string {
	if dsn := os.Getenv("MEBSUTA_MYSQL_DSN"); dsn != "" {
		return dsn
	}
	return "root:test@tcp(127.0.0.1:3306)/logs?parseTime=true"
}

func newMySQLHandler(t *testing.T) (*Handler, *gorm.DB) {
	t.Helper()

	table := "logs_mysql_" + time.Now().Format("20060102150405")

	h, err := NewHandler(Config{
		Driver:        "mysql",
		DSN:           mysqlDSN(),
		Table:         table,
		Level:         slog.LevelDebug,
		BatchSize:     10,
		BatchInterval: 200 * time.Millisecond,
		RetryDelay:    100 * time.Millisecond,
	})
	require.NoError(t, err, "NewHandler mysql")

	gdb, err := openGormDB("mysql", mysqlDSN())
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

func TestIntegration_MySQL_WriteAndRead(t *testing.T) {
	h, gdb := newMySQLHandler(t)

	r := slog.NewRecord(time.Date(2026, 1, 15, 10, 30, 0, 0, time.UTC), slog.LevelInfo, "hello mysql", 0)
	r.AddAttrs(slog.String("key", "value"))
	require.NoError(t, h.Handle(context.Background(), r), "Handle")

	require.Eventually(t, func() bool {
		var count int64
		gdb.Table(h.table).Count(&count)
		return count >= 1
	}, 5*time.Second, 100*time.Millisecond, "record should appear in MySQL")

	var entries []dbLogEntry
	require.NoError(t, gdb.Table(h.table).Find(&entries).Error)
	require.Len(t, entries, 1)
	require.Equal(t, "hello mysql", entries[0].Message)
	require.Equal(t, "INFO", entries[0].Level)

	var fields map[string]any
	require.NoError(t, json.Unmarshal(entries[0].Fields, &fields))
	require.Equal(t, "value", fields["key"])
}

func TestIntegration_MySQL_BatchWrite(t *testing.T) {
	h, gdb := newMySQLHandler(t)

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

func TestIntegration_MySQL_AuditLevel(t *testing.T) {
	h, gdb := newMySQLHandler(t)

	r := slog.NewRecord(time.Now(), mebsuta.LevelAudit, "audit event", 0)
	r.AddAttrs(slog.String("event_type", "login"), slog.Bool("success", true))
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
	require.Equal(t, "login", fields["event_type"])
}

func TestIntegration_MySQL_Attributes(t *testing.T) {
	h, gdb := newMySQLHandler(t)

	child := h.WithAttrs([]slog.Attr{slog.String("preset", "abc")})
	r := slog.NewRecord(time.Now(), slog.LevelInfo, "with attrs", 0)
	r.AddAttrs(slog.Int("seq", 1))
	require.NoError(t, child.Handle(context.Background(), r), "Handle")

	require.Eventually(t, func() bool {
		var count int64
		gdb.Table(h.table).Count(&count)
		return count >= 1
	}, 5*time.Second, 100*time.Millisecond)

	var entries []dbLogEntry
	require.NoError(t, gdb.Table(h.table).Find(&entries).Error)
	require.Len(t, entries, 1)

	var fields map[string]any
	require.NoError(t, json.Unmarshal(entries[0].Fields, &fields))
	require.Equal(t, "abc", fields["preset"])
	require.Equal(t, float64(1), fields["seq"])
}
