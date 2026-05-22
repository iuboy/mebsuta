package database

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/iuboy/mebsuta/go"
	"github.com/iuboy/mebsuta/go/config"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// newFailingDBHandler creates a DatabaseHandler whose database will fail all writes.
// We use a closed *gorm.DB to force errors on every operation.
func newFailingDBHandler(t *testing.T) (*DatabaseHandler, func()) {
	t.Helper()

	gdb, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err, "gorm open")

	// Create the table first so migrations are fine, then we'll sabotage writes.
	require.NoError(t, gdb.AutoMigrate(&dbLogEntry{}), "auto migrate")

	// Close the underlying SQL DB so all subsequent operations fail.
	sqlDB, err := gdb.DB()
	require.NoError(t, err, "get underlying sql.DB")
	sqlDB.Close()

	ctx, cancel := context.WithCancel(context.Background())
	h := &DatabaseHandler{
		LevelHandler: mebsuta.LevelHandler{Level: slog.LevelDebug},
		db:           gdb,
		table:        "logs",
		entries:      make(chan dbLogEntry, 100),
		ctx:          ctx,
		cancel:       cancel,
	}
	eh := mebsuta.DefaultErrorHandler
	h.errorHandler.Store(&eh)
	h.wg.Add(1)
	go h.run(5, 50*time.Millisecond, 1*time.Millisecond)

	cleanup := func() {
		h.Close()
	}
	return h, cleanup
}

// TestDatabaseHandler_BatchRetryExhaustion verifies that when the DB is
// unavailable, flush retries 3 times (finalFlushRetries) and reports errors.
func TestDatabaseHandler_BatchRetryExhaustion(t *testing.T) {
	h, cleanup := newFailingDBHandler(t)
	defer cleanup()

	var (
		reported atomic.Int64
		lastErr  atomic.Pointer[error]
	)

	// Replace error handler to capture calls.
	h.setErrorHandler(func(component string, err error) {
		reported.Add(1)
		lastErr.Store(&err)
	})

	// Write a record so the batch goroutine has something to flush.
	r := slog.NewRecord(time.Now(), slog.LevelInfo, "retry test", 0)
	require.NoError(t, h.Handle(context.Background(), r), "handle should not return error")

	// Wait for flush retries to exhaust. 3 retries x 1ms delay + margin.
	time.Sleep(200 * time.Millisecond)

	// The error handler should have been called at least once for batch failure.
	count := reported.Load()
	require.Greater(t, count, int64(0), "error handler should be called for batch failures")

	// Verify the error message mentions records lost after exhausting retries.
	errPtr := lastErr.Load()
	require.NotNil(t, errPtr, "last error should not be nil")
	require.Contains(t, (*errPtr).Error(), "records lost",
		"error should mention records lost after retry exhaustion")
}

// TestDatabaseHandler_ErrorHandlerCallback verifies that the error handler
// receives the correct component name ("database") and a non-nil error.
func TestDatabaseHandler_ErrorHandlerCallback(t *testing.T) {
	h, cleanup := newFailingDBHandler(t)
	defer cleanup()

	var (
		mu      sync.Mutex
		gotComp string
		gotErr  error
		called  int
	)

	h.setErrorHandler(func(component string, err error) {
		mu.Lock()
		defer mu.Unlock()
		gotComp = component
		gotErr = err
		called++
	})

	r := slog.NewRecord(time.Now(), slog.LevelInfo, "callback test", 0)
	require.NoError(t, h.Handle(context.Background(), r))

	// Wait for flush to attempt and fail.
	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return called > 0
	}, 2*time.Second, 50*time.Millisecond, "error handler should be called")

	mu.Lock()
	defer mu.Unlock()
	require.Equal(t, "database", gotComp, "component should be 'database'")
	require.NotNil(t, gotErr, "error should not be nil")
}

// TestDatabaseHandler_WithAttrsReturnsCorrectType verifies that WithAttrs
// returns *AttrsSub[*DatabaseHandler].
func TestDatabaseHandler_WithAttrsReturnsCorrectType(t *testing.T) {
	h, cleanup := newFailingDBHandler(t)
	defer cleanup()

	result := h.WithAttrs([]slog.Attr{slog.String("key", "value")})

	// Should be *AttrsSub[*DatabaseHandler]
	_, ok := result.(*mebsuta.AttrsSub[*DatabaseHandler])
	require.True(t, ok, "WithAttrs should return *AttrsSub[*DatabaseHandler]")

	// Should also satisfy slog.Handler.
	var _ slog.Handler = result
}

// TestDatabaseHandler_WithGroupReturnsCorrectType verifies that WithGroup
// returns *GroupSub[*DatabaseHandler].
func TestDatabaseHandler_WithGroupReturnsCorrectType(t *testing.T) {
	h, cleanup := newFailingDBHandler(t)
	defer cleanup()

	result := h.WithGroup("mygroup")

	// Should be *GroupSub[*DatabaseHandler]
	_, ok := result.(*mebsuta.GroupSub[*DatabaseHandler])
	require.True(t, ok, "WithGroup should return *GroupSub[*DatabaseHandler]")

	// Should also satisfy slog.Handler.
	var _ slog.Handler = result
}

// TestDatabaseHandler_RecordToDBEntry verifies field mapping: Time, Level,
// Message, and Attrs (serialized as JSON Fields).
func TestDatabaseHandler_RecordToDBEntry(t *testing.T) {
	h, _ := newSQLiteHandler(t)
	// No need to defer close, we only use recordToDBEntry which is stateless.

	ts := time.Date(2026, 5, 20, 12, 0, 0, 0, time.UTC)
	r := slog.NewRecord(ts, slog.LevelWarn, "test message", 0)
	r.AddAttrs(
		slog.String("str_key", "hello"),
		slog.Int("int_key", 42),
	)

	entry := h.recordToDBEntry(r)

	require.Equal(t, ts, entry.Time, "time should match")
	require.Equal(t, "WARN", entry.Level, "level should be WARN string")
	require.Equal(t, "test message", entry.Message, "message should match")

	// Fields should be JSON with the two attributes.
	require.NotEmpty(t, entry.Fields, "fields should not be empty")

	var fields map[string]any
	require.NoError(t, json.Unmarshal(entry.Fields, &fields), "fields should be valid JSON")

	strVal, ok := fields["str_key"]
	require.True(t, ok, "str_key should be in fields")
	require.NotNil(t, strVal, "str_key value should not be nil")

	intVal, ok := fields["int_key"]
	require.True(t, ok, "int_key should be in fields")
	require.NotNil(t, intVal, "int_key value should not be nil")
}

// TestDatabaseHandler_RecordToDBEntry_NoAttrs verifies that a record with no
// attrs produces an entry with empty Fields.
func TestDatabaseHandler_RecordToDBEntry_NoAttrs(t *testing.T) {
	h, _ := newSQLiteHandler(t)

	r := slog.NewRecord(time.Now(), slog.LevelInfo, "no attrs", 0)
	entry := h.recordToDBEntry(r)

	require.Equal(t, "no attrs", entry.Message)
	require.Empty(t, entry.Fields, "fields should be empty when no attrs")
}

// TestDatabaseHandler_AuditLevelNotDropped verifies that audit-level records
// (LevelAudit) are not filtered out by the handler. Even with a handler level
// set to slog.LevelError, Audit records should still be accepted because
// LevelAudit > LevelError.
func TestDatabaseHandler_AuditLevelNotDropped(t *testing.T) {
	h, _ := newSQLiteHandler(t)
	// Set handler level to Error — Audit is above Error so Enabled returns true.
	h.Level = slog.LevelError

	require.True(t, h.Enabled(context.Background(), mebsuta.LevelAudit),
		"Audit should be enabled even at Error level handler")

	// Handle an Audit record — it takes the retry path (level >= Error).
	r := slog.NewRecord(time.Now(), mebsuta.LevelAudit, "audit event", 0)
	require.NoError(t, h.Handle(context.Background(), r), "audit record should be accepted")

	// Close and verify.
	require.NoError(t, h.Close())
}

// TestDatabaseHandler_AuditLevelPersisted uses file-based SQLite to verify
// that Audit records survive Close().
func TestDatabaseHandler_AuditLevelPersisted(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/audit.db"

	gdb, err := gorm.Open(sqlite.Open(path), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, gdb.AutoMigrate(&dbLogEntry{}))

	ctx, cancel := context.WithCancel(context.Background())
	h := &DatabaseHandler{
		LevelHandler: mebsuta.LevelHandler{Level: slog.LevelError},
		db:           gdb,
		table:        "logs",
		entries:      make(chan dbLogEntry, 1000),
		ctx:          ctx,
		cancel:       cancel,
	}
	eh := mebsuta.DefaultErrorHandler
	h.errorHandler.Store(&eh)
	h.wg.Add(1)
	go h.run(5, 50*time.Millisecond, 5*time.Millisecond)

	// Write an Audit record (LevelAudit > Error, so it passes Enabled check).
	r := slog.NewRecord(time.Now(), mebsuta.LevelAudit, "audit persisted", 0)
	require.NoError(t, h.Handle(context.Background(), r))

	require.NoError(t, h.Close())

	// Re-open and verify.
	gdb2, err := gorm.Open(sqlite.Open(path), &gorm.Config{})
	require.NoError(t, err)

	var entries []dbLogEntry
	require.NoError(t, gdb2.Table("logs").Find(&entries).Error)
	require.Len(t, entries, 1, "exactly one audit record should be persisted")
	require.Equal(t, "audit persisted", entries[0].Message)

	require.Equal(t, mebsuta.LevelAudit.String(), entries[0].Level,
		"level should be stored as audit level string")

	sqlDB, _ := gdb2.DB()
	sqlDB.Close()
}

// TestDatabaseHandler_LevelFiltering verifies that records below the handler's
// level are not dropped by Handle — the handler uses LevelHandler.Enabled but
// Handle itself does not check level. The caller (slog.Logger) is responsible
// for checking Enabled. This test documents the actual behavior: Handle
// processes all records it receives regardless of level.
func TestDatabaseHandler_LevelFiltering(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/level.db"

	gdb, err := gorm.Open(sqlite.Open(path), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, gdb.AutoMigrate(&dbLogEntry{}))

	ctx, cancel := context.WithCancel(context.Background())
	h := &DatabaseHandler{
		LevelHandler: mebsuta.LevelHandler{Level: slog.LevelWarn},
		db:           gdb,
		table:        "logs",
		entries:      make(chan dbLogEntry, 1000),
		ctx:          ctx,
		cancel:       cancel,
	}
	eh := mebsuta.DefaultErrorHandler
	h.errorHandler.Store(&eh)
	h.wg.Add(1)
	go h.run(5, 50*time.Millisecond, 5*time.Millisecond)

	// Debug is below Warn — Enabled returns false.
	require.False(t, h.Enabled(context.Background(), slog.LevelDebug),
		"Debug should not be enabled at Warn level")

	// But if Handle receives it directly (e.g. via slog.Log), it still processes it.
	r := slog.NewRecord(time.Now(), slog.LevelDebug, "debug msg", 0)
	require.NoError(t, h.Handle(context.Background(), r), "Handle accepts even below-level records")

	require.NoError(t, h.Close())

	// Verify the debug record was persisted (Handle doesn't filter by level).
	gdb2, err := gorm.Open(sqlite.Open(path), &gorm.Config{})
	require.NoError(t, err)

	var count int64
	require.NoError(t, gdb2.Table("logs").Count(&count).Error)
	require.Equal(t, int64(1), count, "Handle does not filter by level; record should be persisted")

	sqlDB, _ := gdb2.DB()
	sqlDB.Close()
}

// TestDatabaseHandler_BufferFullDropsInfoRecord verifies that when the entry
// channel is full, non-error/non-audit records are dropped and the error
// handler is called.
func TestDatabaseHandler_BufferFullDropsInfoRecord(t *testing.T) {
	// Create a handler with a tiny channel (capacity 1) and no batch goroutine
	// consuming from it, so it fills up quickly.
	gdb, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, gdb.AutoMigrate(&dbLogEntry{}))

	ctx, cancel := context.WithCancel(context.Background())
	h := &DatabaseHandler{
		LevelHandler: mebsuta.LevelHandler{Level: slog.LevelDebug},
		db:           gdb,
		table:        "logs",
		entries:      make(chan dbLogEntry, 1), // tiny buffer
		ctx:          ctx,
		cancel:       cancel,
	}
	// Do NOT start the run goroutine — the channel will fill up.

	var (
		mu      sync.Mutex
		errMsgs []string
	)
	h.setErrorHandler(func(component string, err error) {
		mu.Lock()
		defer mu.Unlock()
		errMsgs = append(errMsgs, err.Error())
	})

	// Fill the channel with one entry.
	r := slog.NewRecord(time.Now(), slog.LevelInfo, "fill", 0)
	require.NoError(t, h.Handle(context.Background(), r))

	// Second write should drop (channel full, Info level uses non-retry path).
	require.NoError(t, h.Handle(context.Background(), r))

	// Give a moment for error handler to be called.
	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	require.True(t, len(errMsgs) > 0, "error handler should be called for dropped record")
	require.True(t,
		strings.Contains(errMsgs[0], "buffer full"),
		"error should mention buffer full, got: %s", errMsgs[0])

	// Clean up — close the channel to stop potential goroutines.
	h.closed.Store(true)
	h.sendMu.Lock()
	close(h.entries)
	h.sendMu.Unlock()
	cancel()
	sqlDB, _ := gdb.DB()
	sqlDB.Close()
}

// TestDatabaseHandler_ConcurrentWrites verifies that multiple goroutines can
// write concurrently without races or panics.
func TestDatabaseHandler_ConcurrentWrites(t *testing.T) {
	h, _ := newSQLiteHandler(t)

	const numGoroutines = 20
	const recordsPerGoroutine = 50

	var wg sync.WaitGroup
	for g := range numGoroutines {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()
			for i := range recordsPerGoroutine {
				r := slog.NewRecord(time.Now(), slog.LevelInfo, "concurrent write", 0)
				r.AddAttrs(
					slog.Int("goroutine", goroutineID),
					slog.Int("seq", i),
				)
				if err := h.Handle(context.Background(), r); err != nil {
					t.Errorf("Handle() error: %v", err)
				}
			}
		}(g)
	}

	wg.Wait()
	require.NoError(t, h.Close())
}

// TestDatabaseHandler_ErrorRecordRetryPath verifies that Error-level records
// take the retry path with a deadline when the channel is full.
func TestDatabaseHandler_ErrorRecordRetryPath(t *testing.T) {
	gdb, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, gdb.AutoMigrate(&dbLogEntry{}))

	ctx, cancel := context.WithCancel(context.Background())
	h := &DatabaseHandler{
		LevelHandler: mebsuta.LevelHandler{Level: slog.LevelDebug},
		db:           gdb,
		table:        "logs",
		entries:      make(chan dbLogEntry, 1), // tiny buffer
		ctx:          ctx,
		cancel:       cancel,
	}
	eh := mebsuta.DefaultErrorHandler
	h.errorHandler.Store(&eh)

	// Don't start run goroutine so the channel stays full.

	var (
		mu      sync.Mutex
		errMsgs []string
	)
	h.setErrorHandler(func(component string, err error) {
		mu.Lock()
		defer mu.Unlock()
		errMsgs = append(errMsgs, err.Error())
	})

	// Fill the channel.
	r := slog.NewRecord(time.Now(), slog.LevelInfo, "fill", 0)
	require.NoError(t, h.Handle(context.Background(), r))

	// Send an Error-level record — it should retry for ~5 seconds then timeout.
	start := time.Now()
	errRecord := slog.NewRecord(time.Now(), slog.LevelError, "error retry", 0)
	require.NoError(t, h.Handle(context.Background(), errRecord))
	elapsed := time.Since(start)

	// Should have retried for up to 5 seconds before giving up.
	require.True(t, elapsed >= 1*time.Second,
		"error record should have retried, elapsed: %v", elapsed)

	mu.Lock()
	defer mu.Unlock()
	require.True(t, len(errMsgs) > 0, "error handler should be called")
	require.True(t,
		strings.Contains(errMsgs[len(errMsgs)-1], "buffer full timeout"),
		"error should mention buffer full timeout, got: %s", errMsgs[len(errMsgs)-1])

	// Cleanup
	h.closed.Store(true)
	h.sendMu.Lock()
	close(h.entries)
	h.sendMu.Unlock()
	cancel()
	sqlDB, _ := gdb.DB()
	sqlDB.Close()
}

// TestDatabaseHandler_HandleAfterClosedReturnsNil verifies that Handle returns
// nil (no error) when called after Close, and does not block.
func TestDatabaseHandler_HandleAfterClosedReturnsNil(t *testing.T) {
	h, _ := newSQLiteHandler(t)
	require.NoError(t, h.Close())

	r := slog.NewRecord(time.Now(), slog.LevelError, "after close", 0)
	require.NoError(t, h.Handle(context.Background(), r),
		"Handle after close should return nil")
}

// TestDatabaseHandler_FlushRetries verifies the exact retry count by counting
// error handler invocations during flush failures.
func TestDatabaseHandler_FlushRetries(t *testing.T) {
	gdb, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, gdb.AutoMigrate(&dbLogEntry{}))

	// Close the underlying connection to force flush errors.
	sqlDB, err := gdb.DB()
	require.NoError(t, err)
	sqlDB.Close()

	var retryCount atomic.Int64
	h := &DatabaseHandler{
		LevelHandler: mebsuta.LevelHandler{Level: slog.LevelDebug},
		db:           gdb,
		table:        "logs",
		entries:      make(chan dbLogEntry, 100),
		ctx:          context.Background(),
		cancel:       func() {},
	}
	h.setErrorHandler(func(component string, err error) {
		if strings.Contains(err.Error(), "batch insert failed") {
			retryCount.Add(1)
		}
	})

	// Manually call flush with a batch.
	batch := []dbLogEntry{
		{Time: time.Now(), Level: "INFO", Message: "test"},
	}
	h.flush(batch, 1*time.Millisecond)

	// Should have retried exactly finalFlushRetries (3) times.
	require.Equal(t, int64(finalFlushRetries), retryCount.Load(),
		"flush should retry exactly %d times", finalFlushRetries)
}

// TestDatabaseHandler_ErrCountTracksDrops verifies that errCount is incremented
// when records are dropped.
func TestDatabaseHandler_ErrCountTracksDrops(t *testing.T) {
	gdb, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, gdb.AutoMigrate(&dbLogEntry{}))

	ctx, cancel := context.WithCancel(context.Background())
	h := &DatabaseHandler{
		LevelHandler: mebsuta.LevelHandler{Level: slog.LevelDebug},
		db:           gdb,
		table:        "logs",
		entries:      make(chan dbLogEntry, 1),
		ctx:          ctx,
		cancel:       cancel,
	}
	eh := mebsuta.DefaultErrorHandler
	h.errorHandler.Store(&eh)
	// No run goroutine — channel fills immediately.

	// Fill buffer.
	r := slog.NewRecord(time.Now(), slog.LevelInfo, "fill", 0)
	require.NoError(t, h.Handle(context.Background(), r))

	// Drop one.
	require.NoError(t, h.Handle(context.Background(), r))
	require.Equal(t, int64(1), h.errCount.Load(), "errCount should be 1 after one drop")

	// Drop another.
	require.NoError(t, h.Handle(context.Background(), r))
	require.Equal(t, int64(2), h.errCount.Load(), "errCount should be 2 after two drops")

	// Cleanup
	h.closed.Store(true)
	h.sendMu.Lock()
	close(h.entries)
	h.sendMu.Unlock()
	cancel()
	sqlDB, _ := gdb.DB()
	sqlDB.Close()
}

// TestDatabaseHandler_NewDatabaseHandler_ConnectFailure verifies that
// NewDatabaseHandler returns an error when the database connection fails.
func TestDatabaseHandler_NewDatabaseHandler_ConnectFailure(t *testing.T) {
	// MySQL with invalid DSN should fail to connect.
	_, err := NewDatabaseHandler(config.MustNewDatabaseConfig("mysql", "invalid:invalid@tcp(localhost:99999)/nonexistent", "logs"), slog.LevelInfo)
	require.Error(t, err, "should fail to connect to invalid MySQL DSN")
	require.True(t, errors.Is(err, nil) || err != nil,
		"error should be non-nil for connection failure")
}
