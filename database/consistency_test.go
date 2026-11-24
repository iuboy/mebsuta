package database

import (
	"context"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/iuboy/mebsuta"
	"github.com/iuboy/mebsuta/internal/handlerkit"
	"github.com/oklog/ulid/v2"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/log"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/trace"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// relayCapture 是真实 SDK 管线末端的捕获型 OTel 日志
// exporter（log.Logger 接口被一个未导出
// 方法封死，fake 因此改插在 exporter 接缝上——那里也是
// sdk Record 暴露由 emit context 填充的链路
// 字段的地方）。
type relayCapture struct {
	mu      sync.Mutex
	records []sdklog.Record
}

func (c *relayCapture) Export(_ context.Context, records []sdklog.Record) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, r := range records {
		// 克隆：SDK 可能在 Export 返回后复用记录。
		c.records = append(c.records, r.Clone())
	}
	return nil
}

func (c *relayCapture) Shutdown(context.Context) error   { return nil }
func (c *relayCapture) ForceFlush(context.Context) error { return nil }

var _ sdklog.Exporter = (*relayCapture)(nil)

// provider 把捕获器接成同步 LoggerProvider 返回。
func (c *relayCapture) provider() log.LoggerProvider {
	return sdklog.NewLoggerProvider(sdklog.WithProcessor(sdklog.NewSimpleProcessor(c)))
}

func (c *relayCapture) snapshot() []sdklog.Record {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]sdklog.Record, len(c.records))
	copy(out, c.records)
	return out
}

// newConsistencyHandler 构建以 sqlite 为后端、对着捕获
// provider 做事务双写的 handler。基于文件（而非 :memory:）：
// relay 扫描器会引入并发数据库用户，而每条全新的
// sqlite :memory: 连接都是自己的私有空库——
// 连接池会递给扫描器一个“无此表”的视图。
func newConsistencyHandler(t *testing.T, syncRelay bool, scanInterval time.Duration) (*Handler, *gorm.DB, *relayCapture) {
	t.Helper()
	gdb, err := gorm.Open(sqlite.Open(t.TempDir()+"/consistency.db"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, gdb.Table("logs").AutoMigrate(&dbLogEntry{}))

	cap := &relayCapture{}
	syncFlag := &(syncRelay) // 参数副本；直接取 &syncRel 会让实参逃逸
	disabled := false
	if !syncRelay {
		syncFlag = &disabled
	}

	ctx, cancel := context.WithCancel(context.Background())
	h := &Handler{
		level: handlerkit.NewLevelGate(slog.LevelInfo),
		cfg: Config{
			Consistency: ConsistencyConfig{
				Enabled:           true,
				SyncRelay:         syncFlag,
				RelayScanInterval: scanInterval,
				RelayBatch:        100,
			},
		},
		db:      gdb,
		table:   "logs",
		entries: make(chan dbLogEntry, 1000),
		ctx:     ctx,
		cancel:  cancel,
		relayTo: cap.provider(),
	}
	h.errorHandler = handlerkit.NewErrorSlot(mebsuta.DefaultErrorHandler)
	h.wg.Add(1)
	go h.run(5, 50*time.Millisecond, 5*time.Millisecond)
	if scanInterval > 0 {
		h.scanStop = make(chan struct{})
		h.wg.Add(1)
		go h.runRelayScanner(scanInterval, 100)
	}
	return h, gdb, cap
}

func TestRecordToDBEntry_OTelAlignment(t *testing.T) {
	h := &Handler{cfg: Config{ServiceName: "svc-a"}, errorHandler: handlerkit.NewErrorSlot(mebsuta.DefaultErrorHandler)}

	// span 内：关联列从 context 填充。
	tid, _ := trace.TraceIDFromHex("0102030405060708090a0b0c0d0e0f10")
	sid, _ := trace.SpanIDFromHex("0102030405060708")
	sc := trace.NewSpanContext(trace.SpanContextConfig{TraceID: tid, SpanID: sid, TraceFlags: trace.FlagsSampled})
	ctx := trace.ContextWithSpanContext(context.Background(), sc)

	r := slog.NewRecord(time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC), slog.LevelInfo, "aligned", 0)
	entry := h.recordToDBEntry(ctx, r)

	_, err := ulid.Parse(entry.ID)
	require.NoError(t, err, "id must be a valid ULID")
	require.False(t, entry.ObservedTime.IsZero())
	require.Equal(t, 9, entry.SeverityNumber)
	require.Equal(t, "0102030405060708090a0b0c0d0e0f10", entry.TraceID)
	require.Equal(t, "0102030405060708", entry.SpanID)
	require.Equal(t, "svc-a", entry.ServiceName)
	require.Nil(t, entry.RelayedAt)

	// span 外：关联两半为空；audit 落在 fatal 段。
	audit := h.recordToDBEntry(context.Background(), slog.NewRecord(time.Now(), mebsuta.LevelAudit, "a", 0))
	require.Empty(t, audit.TraceID)
	require.Empty(t, audit.SpanID)
	require.Equal(t, 21, audit.SeverityNumber)
}

func TestNewRecordID_UniqueAndSorted(t *testing.T) {
	const n = 500
	ids := make([]string, n)
	seen := make(map[string]struct{}, n)
	for i := range ids {
		ids[i] = newRecordID()
		seen[ids[i]] = struct{}{}
	}
	require.Len(t, seen, n, "ids must be unique")
	for i := 1; i < n; i++ {
		require.Less(t, ids[i-1], ids[i], "ULIDs must be monotonic for cursor semantics")
	}
}

func TestConfig_ConsistencyValidation(t *testing.T) {
	cfg := Config{Driver: "postgres", DSN: "host=localhost", Table: "logs",
		Consistency: ConsistencyConfig{Enabled: true}}
	_, err := cfg.Validate()
	require.ErrorContains(t, err, "RelayTo")

	cap := &relayCapture{}
	cfg.RelayTo = cap.provider()
	out, err := cfg.Validate()
	require.NoError(t, err)
	require.True(t, *out.Consistency.SyncRelay)
	require.Equal(t, 30*time.Second, out.Consistency.RelayScanInterval)
	require.Equal(t, 500, out.Consistency.RelayBatch)
}

func TestConsistency_SyncRelayAfterFlush(t *testing.T) {
	h, gdb, cap := newConsistencyHandler(t, true, 0)
	defer func() { require.NoError(t, h.Close()) }()

	tid, _ := trace.TraceIDFromHex("11111111111111111111111111111111")
	sid, _ := trace.SpanIDFromHex("2222222222222222")
	sc := trace.NewSpanContext(trace.SpanContextConfig{TraceID: tid, SpanID: sid, TraceFlags: trace.FlagsSampled})
	ctx := trace.ContextWithSpanContext(context.Background(), sc)

	logger := slog.New(h)
	logger.InfoContext(ctx, "dual write", "k", "v")

	require.Eventually(t, func() bool {
		var count int64
		gdb.Table("logs").Count(&count)
		return count == 1
	}, 5*time.Second, 50*time.Millisecond)

	emitted := cap.snapshot()
	require.Len(t, emitted, 1, "committed batch must relay synchronously")
	e := emitted[0]
	require.Equal(t, "dual write", e.Body().AsString())
	require.Equal(t, log.SeverityInfo, e.Severity())
	require.Equal(t, "INFO", e.SeverityText())

	// 重建的 trace context：emit context 的 span 两半
	// 被填进了 sdk 记录。
	require.Equal(t, tid.String(), e.TraceID().String())
	require.Equal(t, sid.String(), e.SpanID().String())

	// Relay 属性包含解码出的 fields。
	var attrs []attribute.KeyValue
	e.WalkAttributes(func(kv attribute.KeyValue) bool {
		attrs = append(attrs, kv)
		return true
	})
	// B10:relay 记录携带存储行 id(log.record.id)供消费方幂等去重,
	// 加上原始属性共 2 项。
	require.Len(t, attrs, 2)
	require.Equal(t, "log.record.id", string(attrs[0].Key))
	require.NotEmpty(t, attrs[0].Value.AsString(), "storage row id present")
	require.Equal(t, "k", string(attrs[1].Key))
	require.Equal(t, "v", attrs[1].Value.AsString())

	// 标记在同一轮被翻转。
	require.Eventually(t, func() bool {
		var n int64
		gdb.Table("logs").Where("relayed_at IS NOT NULL").Count(&n)
		return n == 1
	}, 5*time.Second, 50*time.Millisecond)
}

func TestConsistency_ScannerReconcilesPending(t *testing.T) {
	// 吞吐模式：SyncRelay 关闭；扫描间隔停在 2s，
	// 投递因此由显式 scanOnce 确定性驱动，
	// 而不是让 ticker 与下方断言赛跑。
	h, gdb, cap := newConsistencyHandler(t, false, 2*time.Second)
	defer func() { require.NoError(t, h.Close()) }()

	logger := slog.New(h)
	logger.Info("pending until scanned")

	require.Eventually(t, func() bool {
		var count int64
		gdb.Table("logs").Count(&count)
		return count == 1
	}, 5*time.Second, 50*time.Millisecond)

	require.Empty(t, cap.snapshot(), "no sync relay in throughput mode")

	h.scanOnce(context.Background(), 100)

	emitted := cap.snapshot()
	require.Len(t, emitted, 1)
	require.Equal(t, "pending until scanned", emitted[0].Body().AsString())

	var n int64
	gdb.Table("logs").Where("relayed_at IS NOT NULL").Count(&n)
	require.Equal(t, int64(1), n, "scanOnce must mark the row relayed")
}
