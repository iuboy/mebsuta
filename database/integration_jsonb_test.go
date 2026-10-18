//go:build integration

package database

import (
	"encoding/json"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// jsonbRow mirrors the log table with a JSONB fields column — the shape a
// json → jsonb migration produces.
type jsonbRow struct {
	Time       time.Time       `gorm:"column:time"`
	Level      string          `gorm:"column:level"`
	Message    string          `gorm:"column:msg"`
	Fields     json.RawMessage `gorm:"column:fields;type:jsonb"`
	RecordHash string          `gorm:"column:record_hash"`
	Signature  []byte          `gorm:"column:signature"`
	SignAlgo   string          `gorm:"column:sign_algo"`
}

func (jsonbRow) TableName() string { return "logs_jsonb_test" }

// TestIntegrity_JsonbRoundTrip proves the canonicalization's jsonb
// transparency end to end: records signed at write time (with float values Go
// renders in exponent form, e.g. 1e+21) verify after PostgreSQL's jsonb has
// rewritten the numeric literals to plain decimal.
func TestIntegrity_JsonbRoundTrip(t *testing.T) {
	gdb, err := gorm.Open(postgres.Open(postgresDSN()), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, _ := gdb.DB()
	defer sqlDB.Close()

	require.NoError(t, gdb.Migrator().DropTable("logs_jsonb_test"))
	// Create with a json column first, then migrate in place — covering both
	// "born as jsonb" and "migrated from json" deployments.
	require.NoError(t, gdb.Exec(`CREATE TABLE logs_jsonb_test (
		time TIMESTAMPTZ NOT NULL, level TEXT NOT NULL, msg TEXT NOT NULL,
		fields JSON, record_hash TEXT NOT NULL DEFAULT '', signature BYTEA, sign_algo TEXT NOT NULL DEFAULT '')`).Error)

	h, err := NewHandler(Config{
		Driver: "postgres", DSN: postgresDSN(), Table: "logs_jsonb_test",
		Level: slog.LevelDebug, BatchSize: 10, BatchInterval: 100 * time.Millisecond,
		IntegritySigner: mockSigner{},
	})
	require.NoError(t, err)

	logger := slog.New(h)
	logger.Info("big numbers",
		"big", 1e21, // Go marshals as 1e+21 → jsonb rewrites to plain decimal
		"amount", 9007199254740993, // 2^53+1: float64-twin boundary, must stay exact
		"ratio", 12.5,
	)
	require.NoError(t, h.Close())

	// In-place migration: json → jsonb rewrites the stored numeric spelling.
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

	// And tampering is still detected post-migration: flip the amount to its
	// float64 twin (9007199254740992).
	var tamperedText string
	require.NoError(t, gdb.Raw(`SELECT replace(fields::text, '9007199254740993', '9007199254740992')::jsonb FROM logs_jsonb_test`).Scan(&tamperedText).Error)
	rec.Fields = json.RawMessage(tamperedText)
	err = VerifyRecord(rec, row.RecordHash, row.Signature, &mockVerifier{})
	require.ErrorIs(t, err, ErrHashMismatch, "float64-twin tampering must be detected after migration")

}
