package database

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/iuboy/mebsuta"
	"github.com/iuboy/mebsuta/internal/handlerkit"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// =============================================================================
// Handler 配置验证测试（不需要真实连接）
// =============================================================================

func TestNewHandler_UnsupportedDriver(t *testing.T) {
	// 使用有效的 DSN 格式，但不支持的驱动程序
	cfg := Config{Driver: "sqlite", DSN: "file:test.db", Table: "logs", Level: slog.LevelInfo}
	_, err := NewHandler(cfg)
	require.Error(t, err, "expected error for unsupported driver")
}

func TestNewHandler_EmptyDSN(t *testing.T) {
	cfg := Config{Driver: "postgres", DSN: "", Table: "logs"}
	_, err := NewHandler(cfg)
	// Validate 应该返回错误，因为 DSN 不能为空
	require.Error(t, err, "NewHandler should reject empty DSN")
}

func TestHandler_Enabled(t *testing.T) {
	h := &Handler{
		level:        handlerkit.NewLevelGate(slog.LevelError),
		errorHandler: handlerkit.NewErrorSlot(mebsuta.DefaultErrorHandler()),
	}
	require.False(t, h.Enabled(context.Background(), slog.LevelInfo), "Info should not be enabled at Error level")
	require.True(t, h.Enabled(context.Background(), slog.LevelError), "Error should be enabled at Error level")
}

func TestHandler_WithAttrs(t *testing.T) {
	var _ slog.Handler = (*Handler)(nil)
	var _ slog.Handler = (*handlerkit.AttrsSub)(nil)
	var _ slog.Handler = (*handlerkit.GroupSub)(nil)
}

// Regression: ISSUE-002 —— Handler 必须实现非导出的 setErrorHandler 方法
// Found by /qa on 2026-04-15
// propagateErrorHandler 依赖 errorHandlerSetter 接口（要求 setErrorHandler 方法）。
// 如果只实现未导出的 setErrorHandler，WithErrorHandler option 会被静默忽略。
func TestHandler_HasSetErrorHandler(t *testing.T) {
	// 验证 setErrorHandler 存在且可以调用（编译期检查）。
	// errorHandler 是 *handlerkit.ErrorSlot（构造期由 NewHandler 填充），
	// 手工构造的 Handler 需先装上槽位。
	h := &Handler{errorHandler: handlerkit.NewErrorSlot(mebsuta.DefaultErrorHandler())}
	h.SetErrorHandler(mebsuta.DefaultErrorHandler())
}

// newFailingDBHandler 创建数据库所有写入都会失败的 Handler。
// 我们用已关闭的 *gorm.DB 强制每个操作都出错。
func newFailingDBHandler(t *testing.T) (*Handler, func()) {
	t.Helper()

	gdb, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err, "gorm open")

	// 先建表让迁移无碍，随后再破坏写入。
	require.NoError(t, gdb.Table("logs").AutoMigrate(&dbLogEntry{}), "auto migrate")

	// 关闭底层 SQL DB，之后所有操作都会失败。
	sqlDB, err := gdb.DB()
	require.NoError(t, err, "get underlying sql.DB")
	_ = sqlDB.Close()

	ctx, cancel := context.WithCancel(context.Background())
	h := &Handler{
		level:        handlerkit.NewLevelGate(slog.LevelDebug),
		db:           gdb,
		table:        "logs",
		entries:      make(chan dbLogEntry, 100),
		ctx:          ctx,
		cancel:       cancel,
		errorHandler: handlerkit.NewErrorSlot(mebsuta.DefaultErrorHandler()),
	}
	h.errorHandler = handlerkit.NewErrorSlot(mebsuta.DefaultErrorHandler())
	h.wg.Add(1)
	go h.run(5, 50*time.Millisecond, 1*time.Millisecond)

	cleanup := func() {
		_ = h.Close()
	}
	return h, cleanup
}

// TestHandler_BatchRetryExhaustion 验证数据库不可用时，
// flush 重试 3 次（finalFlushRetries）并上报错误。
func TestHandler_BatchRetryExhaustion(t *testing.T) {
	h, cleanup := newFailingDBHandler(t)
	defer cleanup()

	var (
		reported atomic.Int64
		lastErr  atomic.Pointer[error]
	)

	// 换上错误处理器以捕获调用。
	h.SetErrorHandler(func(he *mebsuta.HandlerError) {
		reported.Add(1)
		{
			e := he.Err
			lastErr.Store(&e)
		}
	})

	// 写入一条记录，让批次 goroutine 有东西可 flush。
	r := slog.NewRecord(time.Now(), slog.LevelInfo, "retry test", 0)
	require.NoError(t, h.Handle(context.Background(), r), "handle should not return error")

	// 等待 flush 重试耗尽（3 次重试 × 1ms 延迟）。
	require.Eventually(t, func() bool {
		return reported.Load() >= int64(finalFlushRetries+1)
	}, 2*time.Second, 50*time.Millisecond, "error handler should receive all retry errors plus final loss report")

	// 验证错误消息提到重试耗尽后记录丢失。
	errPtr := lastErr.Load()
	require.NotNil(t, errPtr, "last error should not be nil")
	require.Contains(t, (*errPtr).Error(), "records lost",
		"error should mention records lost after retry exhaustion")
}

// TestHandler_ErrorHandlerCallback 验证错误处理器收到
// 正确的组件名（"database"）与非 nil 错误。
func TestHandler_ErrorHandlerCallback(t *testing.T) {
	h, cleanup := newFailingDBHandler(t)
	defer cleanup()

	var (
		mu      sync.Mutex
		gotComp string
		gotErr  error
		called  int
	)

	h.SetErrorHandler(func(he *mebsuta.HandlerError) {
		mu.Lock()
		defer mu.Unlock()
		gotComp = he.Component
		gotErr = he.Err
		called++
	})

	r := slog.NewRecord(time.Now(), slog.LevelInfo, "callback test", 0)
	require.NoError(t, h.Handle(context.Background(), r))

	// 等待 flush 尝试并失败。
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

// TestHandler_WithAttrsReturnsCorrectType 验证 WithAttrs
// 返回 *AttrsSub。
func TestHandler_WithAttrsReturnsCorrectType(t *testing.T) {
	h, cleanup := newFailingDBHandler(t)
	defer cleanup()

	result := h.WithAttrs([]slog.Attr{slog.String("key", "value")})

	// 应为 *AttrsSub
	_, ok := result.(*handlerkit.AttrsSub)
	require.True(t, ok, "WithAttrs should return *AttrsSub")

	// 还应满足 slog.Handler。
	var _ slog.Handler = result //nolint:staticcheck // QF1011: intentional compile-time interface assertion
}

// TestHandler_WithGroupReturnsCorrectType 验证 WithGroup
// 返回 *GroupSub。
func TestHandler_WithGroupReturnsCorrectType(t *testing.T) {
	h, cleanup := newFailingDBHandler(t)
	defer cleanup()

	result := h.WithGroup("mygroup")

	// 应为 *GroupSub
	_, ok := result.(*handlerkit.GroupSub)
	require.True(t, ok, "WithGroup should return *GroupSub")

	// 还应满足 slog.Handler。
	var _ slog.Handler = result //nolint:staticcheck // QF1011: intentional compile-time interface assertion
}

// TestHandler_RecordToDBEntry 验证字段映射：Time、Level、
// Message 与 Attrs（序列化为 JSON Fields）。
func TestHandler_RecordToDBEntry(t *testing.T) {
	h, _ := newSQLiteHandler(t)
	// 无需 defer close，我们只用无状态的 recordToDBEntry。

	ts := time.Date(2026, 5, 20, 12, 0, 0, 0, time.UTC)
	r := slog.NewRecord(ts, slog.LevelWarn, "test message", 0)
	r.AddAttrs(
		slog.String("str_key", "hello"),
		slog.Int("int_key", 42),
	)

	entry := h.recordToDBEntry(context.Background(), r)

	require.Equal(t, ts, entry.Time, "time should match")
	require.Equal(t, "WARN", entry.Level, "level should be WARN string")
	require.Equal(t, "test message", entry.Message, "message should match")

	// Fields 应是含这两个属性的 JSON。
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

// TestHandler_RecordToDBEntry_NoAttrs 验证无属性的记录
// 产出 Fields 为空的条目。
func TestHandler_RecordToDBEntry_NoAttrs(t *testing.T) {
	h, _ := newSQLiteHandler(t)

	r := slog.NewRecord(time.Now(), slog.LevelInfo, "no attrs", 0)
	entry := h.recordToDBEntry(context.Background(), r)

	require.Equal(t, "no attrs", entry.Message)
	require.Empty(t, entry.Fields, "fields should be empty when no attrs")
}

// TestHandler_AuditLevelNotDropped 验证审计级记录
// （LevelAudit）不会被 handler 过滤掉。即使 handler 级别
// 设为 slog.LevelError，Audit 记录仍应被接受，因为
// LevelAudit > LevelError。
func TestHandler_AuditLevelNotDropped(t *testing.T) {
	h, _ := newSQLiteHandler(t)
	// 把 handler 级别设为 Error——Audit 高于 Error，因此 Enabled 返回 true。
	h.level = handlerkit.NewLevelGate(slog.LevelError)

	require.True(t, h.Enabled(context.Background(), mebsuta.LevelAudit),
		"Audit should be enabled even at Error level handler")

	// 处理一条 Audit 记录——它走重试路径（level >= Error）。
	r := slog.NewRecord(time.Now(), mebsuta.LevelAudit, "audit event", 0)
	require.NoError(t, h.Handle(context.Background(), r), "audit record should be accepted")

	// 关闭并验证。
	require.NoError(t, h.Close())
}

// TestHandler_AuditLevelPersisted 用基于文件的 SQLite 验证
// Audit 记录在 Close() 后仍然存在。
func TestHandler_AuditLevelPersisted(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/audit.db"

	gdb, err := gorm.Open(sqlite.Open(path), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, gdb.Table("logs").AutoMigrate(&dbLogEntry{}))

	ctx, cancel := context.WithCancel(context.Background())
	h := &Handler{
		level:        handlerkit.NewLevelGate(slog.LevelError),
		db:           gdb,
		table:        "logs",
		entries:      make(chan dbLogEntry, 1000),
		ctx:          ctx,
		cancel:       cancel,
		errorHandler: handlerkit.NewErrorSlot(mebsuta.DefaultErrorHandler()),
	}
	h.errorHandler = handlerkit.NewErrorSlot(mebsuta.DefaultErrorHandler())
	h.wg.Add(1)
	go h.run(5, 50*time.Millisecond, 5*time.Millisecond)

	// 写入一条 Audit 记录（LevelAudit > Error，因此通过 Enabled 检查）。
	r := slog.NewRecord(time.Now(), mebsuta.LevelAudit, "audit persisted", 0)
	require.NoError(t, h.Handle(context.Background(), r))

	require.NoError(t, h.Close())

	// 重新打开并验证。
	gdb2, err := gorm.Open(sqlite.Open(path), &gorm.Config{})
	require.NoError(t, err)

	var entries []dbLogEntry
	require.NoError(t, gdb2.Table("logs").Find(&entries).Error)
	require.Len(t, entries, 1, "exactly one audit record should be persisted")
	require.Equal(t, "audit persisted", entries[0].Message)

	require.Equal(t, mebsuta.LevelAudit.String(), entries[0].Level,
		"level should be stored as audit level string")

	sqlDB, _ := gdb2.DB()
	_ = sqlDB.Close()
}

// TestHandler_LevelFiltering 验证低于 handler 级别的记录
// 不会被 Handle 丢弃——handler 经 Enabled() 检查级别，但
// Handle 本身不检查。调用方（slog.Logger）负责
// 检查 Enabled。本测试记录真实行为：Handle
// 处理收到的所有记录，不管级别。
func TestHandler_LevelFiltering(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/level.db"

	gdb, err := gorm.Open(sqlite.Open(path), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, gdb.Table("logs").AutoMigrate(&dbLogEntry{}))

	ctx, cancel := context.WithCancel(context.Background())
	h := &Handler{
		level:        handlerkit.NewLevelGate(slog.LevelWarn),
		db:           gdb,
		table:        "logs",
		entries:      make(chan dbLogEntry, 1000),
		ctx:          ctx,
		cancel:       cancel,
		errorHandler: handlerkit.NewErrorSlot(mebsuta.DefaultErrorHandler()),
	}
	h.errorHandler = handlerkit.NewErrorSlot(mebsuta.DefaultErrorHandler())
	h.wg.Add(1)
	go h.run(5, 50*time.Millisecond, 5*time.Millisecond)

	// Debug 低于 Warn——Enabled 返回 false。
	require.False(t, h.Enabled(context.Background(), slog.LevelDebug),
		"Debug should not be enabled at Warn level")

	// 但若 Handle 直接收到它（如经 slog.Log），仍会处理。
	r := slog.NewRecord(time.Now(), slog.LevelDebug, "debug msg", 0)
	require.NoError(t, h.Handle(context.Background(), r), "Handle accepts even below-level records")

	require.NoError(t, h.Close())

	// 验证 debug 记录已持久化（Handle 不按级别过滤）。
	gdb2, err := gorm.Open(sqlite.Open(path), &gorm.Config{})
	require.NoError(t, err)

	var count int64
	require.NoError(t, gdb2.Table("logs").Count(&count).Error)
	require.Equal(t, int64(1), count, "Handle does not filter by level; record should be persisted")

	sqlDB, _ := gdb2.DB()
	_ = sqlDB.Close()
}

// TestHandler_BufferFullDropsInfoRecord 验证条目 channel
// 满时，非 Error/非 Audit 记录被丢弃且错误
// 处理器被调用。
func TestHandler_BufferFullDropsInfoRecord(t *testing.T) {
	// 创建 channel 极小（容量 1）且无批次 goroutine
	// 消费的 handler，让它很快填满。
	gdb, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, gdb.Table("logs").AutoMigrate(&dbLogEntry{}))

	ctx, cancel := context.WithCancel(context.Background())
	h := &Handler{
		level:        handlerkit.NewLevelGate(slog.LevelDebug),
		db:           gdb,
		table:        "logs",
		entries:      make(chan dbLogEntry, 1), // tiny buffer
		ctx:          ctx,
		cancel:       cancel,
		errorHandler: handlerkit.NewErrorSlot(mebsuta.DefaultErrorHandler()),
	}
	// 不要启动 run goroutine——channel 会填满。

	var (
		mu      sync.Mutex
		errMsgs []string
	)
	h.SetErrorHandler(func(he *mebsuta.HandlerError) {
		mu.Lock()
		defer mu.Unlock()
		errMsgs = append(errMsgs, he.Err.Error())
	})

	// 用一条条目填满 channel。
	r := slog.NewRecord(time.Now(), slog.LevelInfo, "fill", 0)
	require.NoError(t, h.Handle(context.Background(), r))

	// 第二次写入应丢弃（channel 满，Info 级别走非重试路径）。
	require.NoError(t, h.Handle(context.Background(), r))

	// 等待错误处理器被调用。
	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(errMsgs) > 0
	}, 2*time.Second, 50*time.Millisecond, "error handler should be called for dropped record")

	mu.Lock()
	defer mu.Unlock()
	require.True(t,
		strings.Contains(errMsgs[0], "backlog full"),
		"error should mention backlog full, got: %s", errMsgs[0])

	// 清理——取 sendMu、关闭 channel、cancel（与 Close() 顺序一致）。
	h.closed.Store(true)
	h.sendMu.Lock()
	close(h.entries)
	h.sendMu.Unlock()
	cancel()
	sqlDB, _ := gdb.DB()
	_ = sqlDB.Close()
}

// TestHandler_ConcurrentWrites 验证多个 goroutine 可以
// 并发写入而无竞争或 panic。
func TestHandler_ConcurrentWrites(t *testing.T) {
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
				require.NoError(t, h.Handle(context.Background(), r), "Handle()")
			}
		}(g)
	}

	wg.Wait()
	require.NoError(t, h.Close())
}

// TestHandler_ErrorRecordRetryPath 验证 channel 满时，
// Error 级记录走带 deadline 的重试路径。
func TestHandler_ErrorRecordRetryPath(t *testing.T) {
	gdb, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, gdb.Table("logs").AutoMigrate(&dbLogEntry{}))

	ctx, cancel := context.WithCancel(context.Background())
	h := &Handler{
		level:        handlerkit.NewLevelGate(slog.LevelDebug),
		cfg:          Config{ErrorTimeout: time.Second},
		db:           gdb,
		table:        "logs",
		entries:      make(chan dbLogEntry, 1), // tiny buffer
		ctx:          ctx,
		cancel:       cancel,
		errorHandler: handlerkit.NewErrorSlot(mebsuta.DefaultErrorHandler()),
	}
	h.errorHandler = handlerkit.NewErrorSlot(mebsuta.DefaultErrorHandler())

	// 不启动 run goroutine，让 channel 保持满。

	var (
		mu      sync.Mutex
		errMsgs []string
	)
	h.SetErrorHandler(func(he *mebsuta.HandlerError) {
		mu.Lock()
		defer mu.Unlock()
		errMsgs = append(errMsgs, he.Err.Error())
	})

	// 填满 channel。
	r := slog.NewRecord(time.Now(), slog.LevelInfo, "fill", 0)
	require.NoError(t, h.Handle(context.Background(), r))

	// 发送一条 Error 级记录——它应重试约 5 秒后超时。
	start := time.Now()
	errRecord := slog.NewRecord(time.Now(), slog.LevelError, "error retry", 0)
	require.NoError(t, h.Handle(context.Background(), errRecord))
	elapsed := time.Since(start)

	// 放弃前应已重试至多 5 秒。
	require.True(t, elapsed >= 1*time.Second,
		"error record should have retried, elapsed: %v", elapsed)

	mu.Lock()
	defer mu.Unlock()
	require.True(t, len(errMsgs) > 0, "error handler should be called")
	require.True(t,
		strings.Contains(errMsgs[len(errMsgs)-1], "backlog full"),
		"error should mention backlog full, got: %s", errMsgs[len(errMsgs)-1])

	// 清理
	h.closed.Store(true)
	h.sendMu.Lock()
	close(h.entries)
	h.sendMu.Unlock()
	cancel()
	sqlDB, _ := gdb.DB()
	_ = sqlDB.Close()
}

// TestHandler_HandleAfterClosedReturnsNil 验证 Close 之后调用
// Handle 返回 nil（无错误）且不阻塞。
func TestHandler_HandleAfterClosedReturnsNil(t *testing.T) {
	h, _ := newSQLiteHandler(t)
	require.NoError(t, h.Close())

	r := slog.NewRecord(time.Now(), slog.LevelError, "after close", 0)
	require.NoError(t, h.Handle(context.Background(), r),
		"Handle after close should return nil")
}

// TestHandler_FlushRetries 通过统计 flush 失败期间错误处理器
// 的调用次数验证精确重试次数。
func TestHandler_FlushRetries(t *testing.T) {
	gdb, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, gdb.Table("logs").AutoMigrate(&dbLogEntry{}))

	// 关闭底层连接以强制 flush 出错。
	sqlDB, err := gdb.DB()
	require.NoError(t, err)
	_ = sqlDB.Close()

	var retryCount atomic.Int64
	h := &Handler{
		level:        handlerkit.NewLevelGate(slog.LevelDebug),
		db:           gdb,
		table:        "logs",
		entries:      make(chan dbLogEntry, 100),
		ctx:          context.Background(),
		cancel:       func() {},
		errorHandler: handlerkit.NewErrorSlot(mebsuta.DefaultErrorHandler()),
	}
	h.SetErrorHandler(func(he *mebsuta.HandlerError) {
		if strings.Contains(he.Err.Error(), "batch insert failed") {
			retryCount.Add(1)
		}
	})

	// 手动带批次调用 flush。
	batch := []dbLogEntry{
		{Time: time.Now(), Level: "INFO", Message: "test"},
	}
	_ = h.flush(batch, 1*time.Millisecond) // 结果经上方的重试计数器断言

	// 应恰好重试 finalFlushRetries（3）次。
	require.Equal(t, int64(finalFlushRetries), retryCount.Load(),
		"flush should retry exactly %d times", finalFlushRetries)
}

// TestHandler_ErrCountTracksDrops 验证记录被丢弃时
// errCount 递增。
func TestHandler_ErrCountTracksDrops(t *testing.T) {
	gdb, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, gdb.Table("logs").AutoMigrate(&dbLogEntry{}))

	ctx, cancel := context.WithCancel(context.Background())
	h := &Handler{
		level:        handlerkit.NewLevelGate(slog.LevelDebug),
		db:           gdb,
		table:        "logs",
		entries:      make(chan dbLogEntry, 1),
		ctx:          ctx,
		cancel:       cancel,
		errorHandler: handlerkit.NewErrorSlot(mebsuta.DefaultErrorHandler()),
	}
	h.errorHandler = handlerkit.NewErrorSlot(mebsuta.DefaultErrorHandler())
	// 无 run goroutine——channel 立即填满。

	// 填满缓冲。
	r := slog.NewRecord(time.Now(), slog.LevelInfo, "fill", 0)
	require.NoError(t, h.Handle(context.Background(), r))

	// 丢弃一条。
	require.NoError(t, h.Handle(context.Background(), r))
	require.Equal(t, int64(1), h.errCount.Load(), "errCount should be 1 after one drop")

	// 再丢弃一条。
	require.NoError(t, h.Handle(context.Background(), r))
	require.Equal(t, int64(2), h.errCount.Load(), "errCount should be 2 after two drops")

	// 清理
	h.closed.Store(true)
	h.sendMu.Lock()
	close(h.entries)
	h.sendMu.Unlock()
	cancel()
	sqlDB, _ := gdb.DB()
	_ = sqlDB.Close()
}

// TestHandler_NewHandler_ConnectFailure 验证数据库连接
// 失败时 NewHandler 返回错误。
func TestHandler_NewHandler_ConnectFailure(t *testing.T) {
	// 主机不可达的 PostgreSQL 应连接失败。
	_, err := NewHandler(Config{Driver: "postgres", DSN: "postgres://invalid:invalid@127.0.0.1:1/nonexistent?sslmode=disable", Table: "logs"})
	require.Error(t, err, "should fail to connect to unreachable PostgreSQL DSN")
	require.True(t, errors.Is(err, nil) || err != nil,
		"error should be non-nil for connection failure")
}

// TestHandler_BatchInsertError 验证批量插入失败经错误
// 处理器上报，并重试至多 finalFlushRetries 次。
func TestHandler_BatchInsertError(t *testing.T) {
	gdb, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err, "gorm open")

	// 不要建表——这会强制所有插入失败。
	sqlDB, _ := gdb.DB()

	ctx, cancel := context.WithCancel(context.Background())

	var mu sync.Mutex
	var errMsgs []string
	eh := mebsuta.ErrorHandler(func(he *mebsuta.HandlerError) {
		mu.Lock()
		errMsgs = append(errMsgs, he.Err.Error())
		mu.Unlock()
	})
	h := &Handler{
		level:        handlerkit.NewLevelGate(slog.LevelInfo),
		db:           gdb,
		table:        "nonexistent_table",
		entries:      make(chan dbLogEntry, 100),
		ctx:          ctx,
		cancel:       cancel,
		errorHandler: handlerkit.NewErrorSlot(mebsuta.DefaultErrorHandler()),
	}
	h.errorHandler = handlerkit.NewErrorSlot(eh)

	h.wg.Add(1)
	go h.run(1, 50*time.Millisecond, 10*time.Millisecond)

	r := slog.NewRecord(time.Now(), slog.LevelInfo, "will fail", 0)
	r.AddAttrs(slog.String("key", "value"))
	_ = h.Handle(context.Background(), r)

	// 等待批次（含重试）被处理。
	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(errMsgs) >= 1
	}, 5*time.Second, 50*time.Millisecond, "error handler should be called for failed batch insert")

	mu.Lock()
	defer mu.Unlock()
	require.True(t, strings.Contains(errMsgs[0], "batch"), "error should mention batch, got: %s", errMsgs[0])

	h.closed.Store(true)
	h.sendMu.Lock()
	close(h.entries)
	h.sendMu.Unlock()
	h.wg.Wait()
	cancel()
	_ = sqlDB.Close()
}

// TestConfig_BatchSizeCap 验证超大的 BatchSize 被钳制到
// maxBatchSize，内部 channel/批次才不会无界增长。
func TestConfig_BatchSizeCap(t *testing.T) {
	cfg, err := Config{Driver: "postgres", DSN: "postgres://u:p@127.0.0.1:5432/db", Table: "logs", BatchSize: 5_000_000}.Validate()
	require.NoError(t, err)
	require.Equal(t, maxBatchSize, cfg.BatchSize, "oversized BatchSize should be clamped to maxBatchSize")
}

// TestConfig_BatchSizeDefault 验证 BatchSize <= 0 时的默认值。
func TestConfig_BatchSizeDefault(t *testing.T) {
	cfg, err := Config{Driver: "postgres", DSN: "postgres://u:p@127.0.0.1:5432/db", Table: "logs"}.Validate()
	require.NoError(t, err)
	require.Equal(t, 100, cfg.BatchSize, "BatchSize should default to 100")
}

// TestSanitizeDBError_Credentials 验证 user:pass@ 与 key=value 两种
// 形式的凭据都会从传播的错误消息中脱敏。
func TestSanitizeDBError_Credentials(t *testing.T) {
	cases := []struct {
		in   string
		want string // 输出中绝不能出现的子串
	}{
		{"dial tcp: user:secret@tcp(host)/db", "secret"},
		{"connect: password=hunter2&db=x", "hunter2"},
		{"connect: sslpassword=letmein;", "letmein"},
		{"connect: passwd=foo;", "foo"},
		// Passwords containing ':' must be fully redacted. The previous
		// 正则（:[^:@/]+@）在内嵌 ':' 处停止，泄漏了 "word"。
		{"dial tcp: user:pa:ssword@tcp(host)/db", "ssword"},
	}
	for _, c := range cases {
		got := sanitizeDBError(errors.New(c.in))
		require.NotContains(t, got, c.want, "credential %q should be redacted", c.want)
	}
}

// TestSanitizeDBError_Nil 验证 nil 输入的处理。
func TestSanitizeDBError_Nil(t *testing.T) {
	require.Equal(t, "<nil>", sanitizeDBError(nil))
}

// TestBatchAttemptError_SanitizesCredentials 验证 flush/重试路径
// 在上报前脱敏 DSN 派生凭据——与连接
// 路径的 sanitizeDBError 行为一致。回归：重试路径过去
// 用 %w 原样透传驱动错误，成为唯一未脱敏的泄漏点。
func TestBatchAttemptError_SanitizesCredentials(t *testing.T) {
	got := batchAttemptError(1, errors.New(`dial tcp: user:supersecret@tcp(db.example:5432)/logs`)).Error()
	require.NotContains(t, got, "supersecret")
	require.Contains(t, got, ":***@")
	require.Contains(t, got, "attempt 1/3")

	got = batchAttemptError(2, errors.New(`connect: password=hunter2&db=logs`)).Error()
	require.NotContains(t, got, "hunter2")
	require.Contains(t, got, "password=***")
}

// TestHandler_FlushRetryCancelledCountsDrop 验证 flush 重试循环中
// 防御性的 ctx.Done 分支：被 handler 关停打断的重试
// 把批次计为丢弃、为 Close 记录 flushErr，并返回
// 显式错误而非静默报告成功（该分支过去
// `return nil`，掩盖了丢失）。
func TestHandler_FlushRetryCancelledCountsDrop(t *testing.T) {
	gdb, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, gdb.Table("logs").AutoMigrate(&dbLogEntry{}))
	sqlDB, err := gdb.DB()
	require.NoError(t, err)
	_ = sqlDB.Close() // 破坏：每次插入都失败

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h := &Handler{
		level:        handlerkit.NewLevelGate(slog.LevelDebug),
		db:           gdb,
		table:        "logs",
		entries:      make(chan dbLogEntry, 10),
		ctx:          ctx,
		cancel:       cancel,
		errorHandler: handlerkit.NewErrorSlot(mebsuta.DefaultErrorHandler()),
	}
	h.SetErrorHandler(func(*mebsuta.HandlerError) {}) // 保持测试输出干净

	batch := []dbLogEntry{
		{Time: time.Now(), Level: "INFO", Message: "one"},
		{Time: time.Now(), Level: "INFO", Message: "two"},
	}

	cancel()                        // 重试 select 必须命中 ctx.Done 而非休眠
	err = h.flush(batch, time.Hour) // 小时级延迟：只有取消能结束等待
	require.Error(t, err, "a cancelled retry must not report success")
	require.Contains(t, err.Error(), "2 records lost")
	require.Contains(t, err.Error(), "shutdown cancelled")
	require.Equal(t, int64(2), h.dropped.Load(), "cancelled retry must count the batch as dropped")

	h.flushMu.Lock()
	flushErr := h.flushErr
	h.flushMu.Unlock()
	require.Equal(t, err, flushErr, "flushErr must carry the loss error so Close can surface it")
}

// TestHandler_RecordLimitTruncatesOversizedRecord 验证超限
// 路径：fields 被替换为 mebsuta_truncated 标记、消息截断
// 到放得下，丢失被计数（dropped + errCount）。
func TestHandler_RecordLimitTruncatesOversizedRecord(t *testing.T) {
	h, _ := newSQLiteHandler(t)
	h.cfg.MaxRecordBytes = 512

	r := slog.NewRecord(time.Now(), slog.LevelInfo, "oversized", 0)
	r.AddAttrs(slog.String("body", strings.Repeat("x", 4096)))

	entry := h.recordToDBEntry(context.Background(), r)

	require.Equal(t, `{"mebsuta_truncated":true}`, string(entry.Fields), "oversized fields must be replaced by the marker")
	require.LessOrEqual(t, len(entry.Message)+len(entry.Fields), 512, "truncated record must fit the limit")
	require.Equal(t, int64(1), h.dropped.Load(), "over-limit record must count as dropped")
	require.Equal(t, int64(1), h.errCount.Load())
}

// TestHandler_RecordLimitKeepsSmallRecord 验证限内记录逐字节
// 原样通过：无标记、无截断、无计数。
func TestHandler_RecordLimitKeepsSmallRecord(t *testing.T) {
	h, _ := newSQLiteHandler(t)
	h.cfg.MaxRecordBytes = 4096

	r := slog.NewRecord(time.Now(), slog.LevelInfo, "small", 0)
	r.AddAttrs(slog.String("k", "v"))
	entry := h.recordToDBEntry(context.Background(), r)

	require.NotContains(t, string(entry.Fields), "mebsuta_truncated")
	require.Equal(t, "small", entry.Message)
	require.Contains(t, string(entry.Fields), `"k":"v"`)
	require.Equal(t, int64(0), h.dropped.Load())
	require.Equal(t, int64(0), h.errCount.Load())
}

// TestHandler_RecordLimitTruncatesMessageOnly 验证仅消息超限
// （无属性）的记录仍获得标记与截断后的消息。
func TestHandler_RecordLimitTruncatesMessageOnly(t *testing.T) {
	h, _ := newSQLiteHandler(t)
	h.cfg.MaxRecordBytes = 128

	r := slog.NewRecord(time.Now(), slog.LevelInfo, strings.Repeat("m", 500), 0)
	entry := h.recordToDBEntry(context.Background(), r)

	require.Equal(t, `{"mebsuta_truncated":true}`, string(entry.Fields))
	require.LessOrEqual(t, len(entry.Message), 128)
	require.True(t, strings.HasSuffix(entry.Message, "..."), "truncated message should carry the cut marker")
}

// TestHandler_RecordLimitTruncatesAtRuneBoundary 验证消息切口
// 绝不拆散多字节 UTF-8 rune。
func TestHandler_RecordLimitTruncatesAtRuneBoundary(t *testing.T) {
	h, _ := newSQLiteHandler(t)
	h.cfg.MaxRecordBytes = 64

	r := slog.NewRecord(time.Now(), slog.LevelInfo, strings.Repeat("é", 64), 0) // 128 字节
	entry := h.recordToDBEntry(context.Background(), r)

	require.True(t, utf8.ValidString(entry.Message), "truncated message must stay valid UTF-8")
	require.LessOrEqual(t, len(entry.Message), 64)
}

// TestHandler_RecordLimitReportsRateLimited 验证超限报告
// 与积压丢弃使用同一限频节奏：首次命中上报、
// dropReportInterval 内的后续命中静默、计数器总是
// 递增。
func TestHandler_RecordLimitReportsRateLimited(t *testing.T) {
	h, _ := newSQLiteHandler(t)
	h.cfg.MaxRecordBytes = 64

	var reported atomic.Int64
	h.SetErrorHandler(func(he *mebsuta.HandlerError) {
		if strings.Contains(he.Err.Error(), "MaxRecordBytes") {
			reported.Add(1)
		}
	})

	r := slog.NewRecord(time.Now(), slog.LevelInfo, strings.Repeat("m", 500), 0)
	_ = h.recordToDBEntry(context.Background(), r)
	require.Equal(t, int64(1), reported.Load(), "first over-limit record must be reported")

	_ = h.recordToDBEntry(context.Background(), r)
	require.Equal(t, int64(1), reported.Load(), "second report within the window must be rate-limited")
	require.Equal(t, int64(2), h.dropped.Load(), "every over-limit record must be counted")
}

// TestHandler_RecordLimitSignedAfterTruncation 验证大小上限与
// 完整性签名的顺序：签名必须覆盖实际持久化
// 的截断后内容，而非原始 fields。
func TestHandler_RecordLimitSignedAfterTruncation(t *testing.T) {
	h, _ := newSQLiteHandler(t)
	h.cfg.MaxRecordBytes = 256
	h.cfg.IntegritySigner = mockSigner{}

	r := slog.NewRecord(time.Now(), slog.LevelInfo, "sign me", 0)
	r.AddAttrs(slog.String("body", strings.Repeat("x", 2048)))

	entry := h.recordToDBEntry(context.Background(), r)

	require.Equal(t, `{"mebsuta_truncated":true}`, string(entry.Fields), "record must have been truncated")
	require.NotEmpty(t, entry.RecordHash, "truncated record must still be signed")

	canonical, err := CanonicalBytes(entry.Time, entry.Level, entry.Message, entry.Fields)
	require.NoError(t, err)
	hash, err := mockHash(canonical)
	require.NoError(t, err)
	require.Equal(t, hex.EncodeToString(hash), entry.RecordHash,
		"signature must cover the truncated content actually persisted")
}

// newSQLiteHandler 创建以 SQLite 内存库为后端的测试 Handler。
// 用完后调用方必须调用 Close()。
func newSQLiteHandler(t *testing.T) (*Handler, *gorm.DB) {
	t.Helper()
	gdb, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err, "gorm open")
	// 显式创建 "logs" 表；handler 的所有写入都使用 cfg.Table。
	require.NoError(t, gdb.Table("logs").AutoMigrate(&dbLogEntry{}), "auto migrate")

	ctx, cancel := context.WithCancel(context.Background())
	h := &Handler{
		level:        handlerkit.NewLevelGate(slog.LevelInfo),
		db:           gdb,
		table:        "logs",
		entries:      make(chan dbLogEntry, 1000),
		ctx:          ctx,
		cancel:       cancel,
		errorHandler: handlerkit.NewErrorSlot(mebsuta.DefaultErrorHandler()),
	}
	h.errorHandler = handlerkit.NewErrorSlot(mebsuta.DefaultErrorHandler())
	h.wg.Add(1)
	go h.run(5, 50*time.Millisecond, 5*time.Millisecond)
	return h, gdb
}

// SPEC P0：Close() 之后，Close() 前提交的所有记录必须存在。
// 完整验证在 TestHandler_RecordsDeliveredBeforeClose（基于文件的 SQLite）。
// 本测试验证写入后 Close() 无错误成功。
func TestHandler_Close_FlushesRecords(t *testing.T) {
	h, _ := newSQLiteHandler(t)

	for i := range 3 {
		r := slog.NewRecord(time.Now(), slog.LevelInfo, "msg", 0)
		r.AddAttrs(slog.Int("i", i))
		require.NoError(t, h.Handle(context.Background(), r), "handle %d", i)
	}

	require.NoError(t, h.Close(), "close")
}

// SPEC P0：Close() 之后再次 Close() 返回 nil（幂等）。
func TestHandler_Close_Idempotent(t *testing.T) {
	h, _ := newSQLiteHandler(t)

	require.NoError(t, h.Close(), "first close")
	require.NoError(t, h.Close(), "second close should return nil")
}

// SPEC P0：关闭后写入不 panic。
func TestHandler_WriteAfterClose(t *testing.T) {
	h, _ := newSQLiteHandler(t)

	require.NoError(t, h.Close())

	r := slog.NewRecord(time.Now(), slog.LevelInfo, "after close", 0)
	// 不得 panic
	require.NoError(t, h.Handle(context.Background(), r), "handle after close should return nil")
}

// SPEC P0：并发 Handle/Close 不得 panic 或竞争。
func TestHandler_ConcurrentCloseWrite(t *testing.T) {
	h, _ := newSQLiteHandler(t)

	var wg sync.WaitGroup
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := slog.NewRecord(time.Now(), slog.LevelInfo, "concurrent", 0)
			require.NoError(t, h.Handle(context.Background(), r), "Handle()")
		}()
	}

	// 与写入并发地 Close
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = h.Close()
	}()

	wg.Wait()

	// 第二次 close 仍应安全
	require.NoError(t, h.Close(), "second close")
}

// TestHandler_ConcurrentCloseWaitsForDrain 验证并发下的第二个
// Close 不会在第一个 Close 的排空刷盘完成之前返回：
// 每个调用方都必须得到相同的完成契约（“Close
// 返回时，缓冲记录已持久化”），而不只是赢得
// CAS 的那一个。回归：CAS 落败者过去立即返回 nil，让
// 调用方在最终 flush 落库前就读库。
func TestHandler_ConcurrentCloseWaitsForDrain(t *testing.T) {
	gdb, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, gdb.Table("logs").AutoMigrate(&dbLogEntry{}))

	// 放慢 INSERT 让排空可观测地变长；insertDone 标记
	// 持久化写入真正完成的时刻。
	var insertDone atomic.Bool
	require.NoError(t, gdb.Callback().Create().Before("gorm:create").
		Register("test:drain_delay", func(tx *gorm.DB) {
			time.Sleep(150 * time.Millisecond)
			insertDone.Store(true)
		}))

	ctx, cancel := context.WithCancel(context.Background())
	h := &Handler{
		level:        handlerkit.NewLevelGate(slog.LevelInfo),
		db:           gdb,
		table:        "logs",
		entries:      make(chan dbLogEntry, 1000),
		ctx:          ctx,
		cancel:       cancel,
		errorHandler: handlerkit.NewErrorSlot(mebsuta.DefaultErrorHandler()),
	}
	h.errorHandler = handlerkit.NewErrorSlot(mebsuta.DefaultErrorHandler())
	// 批大小与间隔都超出写入量，因此记录只会在
	// Close 的排空期间到达数据库。
	h.wg.Add(1)
	go h.run(1000, time.Hour, time.Millisecond)

	r := slog.NewRecord(time.Now(), slog.LevelInfo, "drain me", 0)
	require.NoError(t, h.Handle(context.Background(), r))

	firstDone := make(chan error, 1)
	go func() { firstDone <- h.Close() }()

	// 等到第一个 Close 拿到 CAS，第二个才必定
	// 走已关闭路径。
	require.Eventually(t, func() bool { return h.closed.Load() }, time.Second, time.Millisecond)

	secondDone := make(chan struct{})
	go func() { _ = h.Close(); close(secondDone) }()

	select {
	case <-secondDone:
	case <-time.After(5 * time.Second):
		require.FailNow(t, "second Close deadlocked waiting for the drain")
	}
	require.True(t, insertDone.Load(),
		"second Close returned before the first Close's drain flush completed")
	require.NoError(t, <-firstDone)
}

// SPEC P0：Close 前写入的记录被送达（基于文件的 SQLite，便于验证）。
func TestHandler_RecordsDeliveredBeforeClose(t *testing.T) {
	// 使用基于文件的 SQLite，便于重新打开验证
	dir := t.TempDir()
	path := dir + "/test.db"

	gdb, err := gorm.Open(sqlite.Open(path), &gorm.Config{})
	require.NoError(t, err, "open")
	require.NoError(t, gdb.Table("logs").AutoMigrate(&dbLogEntry{}), "migrate")

	ctx, cancel := context.WithCancel(context.Background())
	h := &Handler{
		level:        handlerkit.NewLevelGate(slog.LevelInfo),
		db:           gdb,
		table:        "logs",
		entries:      make(chan dbLogEntry, 1000),
		ctx:          ctx,
		cancel:       cancel,
		errorHandler: handlerkit.NewErrorSlot(mebsuta.DefaultErrorHandler()),
	}
	h.errorHandler = handlerkit.NewErrorSlot(mebsuta.DefaultErrorHandler())
	h.wg.Add(1)
	go h.run(5, 50*time.Millisecond, 5*time.Millisecond)

	for i := range 3 {
		r := slog.NewRecord(time.Now(), slog.LevelInfo, "persistent msg", 0)
		r.AddAttrs(slog.Int("i", i))
		require.NoError(t, h.Handle(context.Background(), r), "handle")
	}

	require.NoError(t, h.Close(), "close")

	// 重新打开并验证
	gdb2, err := gorm.Open(sqlite.Open(path), &gorm.Config{})
	require.NoError(t, err, "reopen")
	var count int64
	gdb2.Table("logs").Count(&count)
	require.Equal(t, int64(3), count, "expected 3 records")
}

// SPEC P1：批次写满即触发批量写入。
func TestHandler_BatchWrite(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/test.db"

	gdb, err := gorm.Open(sqlite.Open(path), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, gdb.Table("logs").AutoMigrate(&dbLogEntry{}))

	ctx, cancel := context.WithCancel(context.Background())
	h := &Handler{
		level:        handlerkit.NewLevelGate(slog.LevelInfo),
		db:           gdb,
		table:        "logs",
		entries:      make(chan dbLogEntry, 1000),
		ctx:          ctx,
		cancel:       cancel,
		errorHandler: handlerkit.NewErrorSlot(mebsuta.DefaultErrorHandler()),
	}
	h.errorHandler = handlerkit.NewErrorSlot(mebsuta.DefaultErrorHandler())
	batchSize := 5
	h.wg.Add(1)
	go h.run(batchSize, 10*time.Second, 5*time.Millisecond) // 长间隔，依赖批大小

	for i := range batchSize + 2 { // 超过批大小以触发 flush
		r := slog.NewRecord(time.Now(), slog.LevelInfo, "batch test", 0)
		r.AddAttrs(slog.Int("i", i))
		require.NoError(t, h.Handle(context.Background(), r), "handle")
	}

	require.NoError(t, h.Close())

	gdb2, err := gorm.Open(sqlite.Open(path), &gorm.Config{})
	require.NoError(t, err)
	var count int64
	gdb2.Table("logs").Count(&count)
	require.Equal(t, int64(batchSize+2), count, "expected records")
}

// captureFD1 在 fn 执行期间把文件描述符 1 重定向到管道，
// 并返回写入其中的全部内容。
func captureFD1(t *testing.T, fn func()) string {
	t.Helper()

	pipeR, pipeW, err := os.Pipe()
	require.NoError(t, err)

	saved, err := syscall.Dup(1)
	require.NoError(t, err)

	// 让 fd 1 指向管道写端，再丢弃原始句柄，
	// fd 1 就是写端的唯一引用。
	require.NoError(t, syscall.Close(1))
	if _, err := syscall.Dup(int(pipeW.Fd())); err != nil {
		// 测试失败前尽力恢复。
		_, _ = syscall.Dup(saved)
		_ = syscall.Close(saved)
		_ = pipeR.Close()
		_ = pipeW.Close()
		require.FailNow(t, "dup pipe onto stdout: %v", err)
	}
	_ = pipeW.Close()

	fn()

	// 排空管道前先恢复真正的 stdout：关闭 fd 1 并把
	// saved 复制回去会释放最后一个写端引用，
	// 下方的读取因此遇到 EOF 而不是永久阻塞。
	require.NoError(t, syscall.Close(1))
	_, err = syscall.Dup(saved)
	require.NoError(t, err)
	require.NoError(t, syscall.Close(saved))

	var out bytes.Buffer
	_, err = io.Copy(&out, pipeR)
	require.NoError(t, err)
	require.NoError(t, pipeR.Close())
	return out.String()
}

// TestNewHandler_GormConfigDiscardsLogger 钉住静默决策：handler
// 打开的每个 gorm 会话都必须使用 logger.Discard。
func TestNewHandler_GormConfigDiscardsLogger(t *testing.T) {
	require.True(t, newGORMConfig().Logger == logger.Discard,
		"newGORMConfig must install gorm's Discard logger: the default logger renders slow/failed statements with all bound values interpolated onto stdout (memory x2 at peak, unredacted sensitive content)")
}

// TestGormConfig_FailedStatementWritesNothingToStdout 端到端证明
// 静默生效。对照组：gorm 默认配置下，失败的 INSERT 会把
// 语句与绑定值渲染到 fd 1——这同时验证捕获
// 机制本身。实验组：使用 newGORMConfig 时什么都不写。
//
// 失败是执行期错误（表不存在）。事务开始时的错误
// （如 "sql: database is closed"）会在任何 SQL 构建之前在
// gorm 的 create 回调内短路，永远不会到达 logger，
// 因此不能作为这里的触发器。
func TestGormConfig_FailedStatementWritesNothingToStdout(t *testing.T) {
	run := func(cfg *gorm.Config) string {
		gdb, err := gorm.Open(sqlite.Open(":memory:"), cfg)
		require.NoError(t, err)
		require.NoError(t, gdb.Table("logs").AutoMigrate(&dbLogEntry{}))
		require.NoError(t, gdb.Exec("DROP TABLE logs").Error)

		batch := []dbLogEntry{{
			Time: time.Now(), Level: "INFO", Message: "secret-message",
			Fields: []byte(`{"token":"hunter2"}`),
		}}
		return captureFD1(t, func() {
			_ = gdb.Table("logs").CreateInBatches(batch, 10).Error //nolint:errcheck // 被测的不是错误本身，只是它对 stdout 的副作用
		})
	}

	control := run(&gorm.Config{})
	require.NotEmpty(t, control,
		"expected gorm's default logger to render the failed statement — the capture mechanism itself is broken otherwise")
	require.Contains(t, control, "hunter2",
		"the default logger interpolates bound values — exactly what the handler must not leak")

	silent := run(newGORMConfig())
	require.Empty(t, silent,
		"newGORMConfig must silence gorm completely: no SQL, no bound values on stdout")
}

// TestFlush_RetriesExhaustedCountsDropped:重试耗尽的整批丢失必须计入
// dropped(B3)——这是 database handler 最大的丢失路径,此前只上报
// 不计数,丢弃观测面看不到。
func TestFlush_RetriesExhaustedCountsDropped(t *testing.T) {
	h, cleanup := newFailingDBHandler(t)
	r := slog.NewRecord(time.Now(), slog.LevelInfo, "lost", 0)
	require.NoError(t, h.Handle(context.Background(), r))
	cleanup()
	require.NotZero(t, h.dropped.Load(), "retry-exhausted batch must count as dropped")
}
