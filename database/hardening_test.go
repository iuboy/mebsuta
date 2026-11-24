package database

// 第五轮安全审计修复批的回归测试：
//   P2-1  扫描器字节预算 + ULID 续传
//   P3-2  AutoMigrateTables 表名校验对齐
//   P4-1  直方图 Count int64 钳制

import (
	"context"
	"log/slog"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/iuboy/mebsuta"
	"github.com/iuboy/mebsuta/internal/handlerkit"
	"github.com/stretchr/testify/require"
	sdkmetricdata "go.opentelemetry.io/otel/sdk/metric/metricdata"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// TestScanOnce_ByteBudget_Resumable 缩小预算并证明
// 扫描只投递放得下的部分、其余保持待处理，下一轮
// 扫描恰好从上一轮停止处继续（不丢、不跳）。
func TestScanOnce_ByteBudget_Resumable(t *testing.T) {
	gdb, err := gorm.Open(sqlite.Open(t.TempDir()+"/budget.db"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, gdb.Table("logs").AutoMigrate(&dbLogEntry{}))

	cap := &relayCapture{}
	h := &Handler{
		cfg:          Config{Consistency: ConsistencyConfig{Enabled: true}},
		db:           gdb,
		table:        "logs",
		relayTo:      cap.provider(),
		errorHandler: handlerkit.NewErrorSlot(mebsuta.DefaultErrorHandler()),
	}
	eh := mebsuta.DefaultErrorHandler()
	h.errorHandler = handlerkit.NewErrorSlot(eh)

	// 三行约 100 字节的 fields；预算 250 字节 → 第一轮
	// 扫描至多携带两行（第三行会越线）。
	big := strings.Repeat("x", 100)
	for range 3 {
		e := h.recordToDBEntry(context.Background(),
			slog.NewRecord(time.Now(), slog.LevelInfo, "big", 0))
		e.Fields = []byte(`{"pad":"` + big + `"}`)
		require.NoError(t, gdb.Table("logs").Create(&e).Error)
	}

	prev := scanByteBudget
	scanByteBudget = 250
	defer func() { scanByteBudget = prev }()

	h.scanOnce(context.Background(), 100)

	var relayed int64
	gdb.Table("logs").Where("relayed_at IS NOT NULL").Count(&relayed)
	require.Equal(t, int64(2), relayed, "budget must stop the page at two rows")

	h.scanOnce(context.Background(), 100)
	gdb.Table("logs").Where("relayed_at IS NOT NULL").Count(&relayed)
	require.Equal(t, int64(3), relayed, "second scan must resume and finish")
	require.Len(t, cap.snapshot(), 3)
}

// TestAutoMigrateTables_RejectsBadNames 钉住与 EnsureTables 的
// 纵深防御一致性（P3-2）。
func TestAutoMigrateTables_RejectsBadNames(t *testing.T) {
	gdb, err := gorm.Open(sqlite.Open(t.TempDir()+"/names.db"), &gorm.Config{})
	require.NoError(t, err)

	err = AutoMigrateTables(gdb, "bad name; DROP TABLE x", "ok_metrics")
	require.ErrorContains(t, err, "table name must match")

	err = AutoMigrateTables(gdb, "ok_spans", "also bad")
	require.ErrorContains(t, err, "table name must match")
}

// TestHistogramRows_CountClamp 钉住 G115 钳制（P4-1）：超过
// MaxInt64 的 uint64 计数必须饱和，绝不回绕为负。
func TestHistogramRows_CountClamp(t *testing.T) {
	dp := sdkmetricdata.HistogramDataPoint[float64]{
		Count: uint64(math.MaxInt64) + 1,
		Sum:   1,
		Time:  time.Now(),
	}
	rows := histogramRows("h", sdkmetricdata.Histogram[float64]{
		Temporality: sdkmetricdata.CumulativeTemporality,
		DataPoints:  []sdkmetricdata.HistogramDataPoint[float64]{dp},
	}, "svc")
	require.Len(t, rows, 1)
	require.NotNil(t, rows[0].Count)
	require.Equal(t, int64(math.MaxInt64), *rows[0].Count)
}
