package database

import (
	"context"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/iuboy/mebsuta/go"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// newSQLiteHandler creates a DatabaseHandler backed by SQLite memory for testing.
// The caller must call Close() when done.
func newSQLiteHandler(t *testing.T) (*DatabaseHandler, *gorm.DB) {
	t.Helper()
	gdb, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("gorm open: %v", err)
	}
	// AutoMigrate uses dbLogEntry.TableName() which returns "logs"
	if err := gdb.AutoMigrate(&dbLogEntry{}); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	h := &DatabaseHandler{
		LevelHandler: mebsuta.LevelHandler{Level: slog.LevelInfo},
		db:           gdb,
		table:        "logs", // must match dbLogEntry.TableName()
		entries:      make(chan dbLogEntry, 1000),
		ctx:          ctx,
		cancel:       cancel,
	}
	eh := mebsuta.DefaultErrorHandler
	h.errorHandler.Store(&eh)
	h.wg.Add(1)
	go h.run(5, 50*time.Millisecond, 5*time.Millisecond)
	return h, gdb
}

// SPEC P0: After Close(), all records submitted before Close() must be present.
// Full verification is in TestDatabaseHandler_RecordsDeliveredBeforeClose (file-based SQLite).
// This test verifies Close() succeeds after writes without error.
func TestDatabaseHandler_Close_FlushesRecords(t *testing.T) {
	h, _ := newSQLiteHandler(t)

	for i := range 3 {
		r := slog.NewRecord(time.Now(), slog.LevelInfo, "msg", 0)
		r.AddAttrs(slog.Int("i", i))
		if err := h.Handle(context.Background(), r); err != nil {
			t.Fatalf("handle %d: %v", i, err)
		}
	}

	if err := h.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

// SPEC P0: After Close(), second Close() returns nil (idempotent).
func TestDatabaseHandler_Close_Idempotent(t *testing.T) {
	h, _ := newSQLiteHandler(t)

	if err := h.Close(); err != nil {
		t.Fatalf("first close: %v", err)
	}
	if err := h.Close(); err != nil {
		t.Fatalf("second close should return nil, got: %v", err)
	}
}

// SPEC P0: Writes after close do not panic.
func TestDatabaseHandler_WriteAfterClose(t *testing.T) {
	h, _ := newSQLiteHandler(t)

	if err := h.Close(); err != nil {
		t.Fatal(err)
	}

	r := slog.NewRecord(time.Now(), slog.LevelInfo, "after close", 0)
	// Must not panic
	if err := h.Handle(context.Background(), r); err != nil {
		t.Fatalf("handle after close should return nil, got: %v", err)
	}
}

// SPEC P0: Concurrent Handle/Close must not panic or race.
func TestDatabaseHandler_ConcurrentCloseWrite(t *testing.T) {
	h, _ := newSQLiteHandler(t)

	var wg sync.WaitGroup
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := slog.NewRecord(time.Now(), slog.LevelInfo, "concurrent", 0)
			if err := h.Handle(context.Background(), r); err != nil {
				t.Errorf("Handle() error: %v", err)
			}
		}()
	}

	// Close concurrently with writes
	wg.Add(1)
	go func() {
		defer wg.Done()
		h.Close()
	}()

	wg.Wait()

	// Second close should still be safe
	if err := h.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
}

// SPEC P0: Records written before Close are delivered (file-based SQLite for verification).
func TestDatabaseHandler_RecordsDeliveredBeforeClose(t *testing.T) {
	// Use file-based SQLite so we can re-open and verify
	dir := t.TempDir()
	path := dir + "/test.db"

	gdb, err := gorm.Open(sqlite.Open(path), &gorm.Config{})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := gdb.AutoMigrate(&dbLogEntry{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	h := &DatabaseHandler{
		LevelHandler: mebsuta.LevelHandler{Level: slog.LevelInfo},
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

	for i := range 3 {
		r := slog.NewRecord(time.Now(), slog.LevelInfo, "persistent msg", 0)
		r.AddAttrs(slog.Int("i", i))
		if err := h.Handle(context.Background(), r); err != nil {
			t.Fatalf("handle: %v", err)
		}
	}

	if err := h.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Re-open and verify
	gdb2, err := gorm.Open(sqlite.Open(path), &gorm.Config{})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	var count int64
	gdb2.Table("logs").Count(&count)
	if count != 3 {
		t.Errorf("expected 3 records, got %d", count)
	}
}

// SPEC P1: Batch write triggers when batch is full.
func TestDatabaseHandler_BatchWrite(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/test.db"

	gdb, err := gorm.Open(sqlite.Open(path), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := gdb.AutoMigrate(&dbLogEntry{}); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	h := &DatabaseHandler{
		LevelHandler: mebsuta.LevelHandler{Level: slog.LevelInfo},
		db:           gdb,
		table:        "logs",
		entries:      make(chan dbLogEntry, 1000),
		ctx:          ctx,
		cancel:       cancel,
	}
	eh := mebsuta.DefaultErrorHandler
	h.errorHandler.Store(&eh)
	batchSize := 5
	h.wg.Add(1)
	go h.run(batchSize, 10*time.Second, 5*time.Millisecond) // long interval, rely on batch size

	for i := range batchSize + 2 { // exceed batch size to trigger flush
		r := slog.NewRecord(time.Now(), slog.LevelInfo, "batch test", 0)
		r.AddAttrs(slog.Int("i", i))
		if err := h.Handle(context.Background(), r); err != nil {
			t.Fatalf("handle: %v", err)
		}
	}

	if err := h.Close(); err != nil {
		t.Fatal(err)
	}

	gdb2, err := gorm.Open(sqlite.Open(path), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	var count int64
	gdb2.Table("logs").Count(&count)
	if count != int64(batchSize+2) {
		t.Errorf("expected %d records, got %d", batchSize+2, count)
	}
}
