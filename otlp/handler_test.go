package otlp

import (
	"context"
	"encoding/hex"
	"log/slog"
	"testing"
	"time"

	"github.com/iuboy/mebsuta"
	"github.com/iuboy/mebsuta/mebsutatest"
	"github.com/iuboy/mebsuta/telemetry"
	"github.com/stretchr/testify/require"
	commonpb "go.opentelemetry.io/proto/slim/otlp/common/v1"
	logsv1 "go.opentelemetry.io/proto/slim/otlp/logs/v1"
)

// startPipeline 面向捕获接收端启动一个带日志（可选带 trace）的 telemetry
// 引导，并返回测试所需的部件。
func startPipeline(t *testing.T, signals telemetry.Signals) (*telemetry.Telemetry, *mebsutatest.OTLPReceiver) {
	t.Helper()
	r := mebsutatest.NewOTLPReceiver()
	no := false // 测试直接驱动 provider；全局保持原样
	tel, err := telemetry.Start(context.Background(), telemetry.Config{
		ServiceName: "otlp-handler-test",
		Endpoint:    r.URL(),
		Signals:     signals,
		SetGlobal:   &no,
	})
	require.NoError(t, err)
	return tel, r
}

func TestHandler_EndToEnd(t *testing.T) {
	tel, r := startPipeline(t, telemetry.Traces|telemetry.Logs)
	defer r.Close()

	logger := slog.New(NewHandler(tel.LoggerProvider(), Config{}))

	ctx, span := tel.TracerProvider().Tracer("test").Start(context.Background(), "correlated-op")
	logger.InfoContext(ctx, "hello from slog",
		"str", "v",
		"n", int64(42),
		"f", 1.5,
		"b", true,
		"d", 150*time.Millisecond,
		slog.Group("g", "inner", "iv"),
	)
	span.End()

	require.NoError(t, tel.Shutdown(context.Background()))

	records := r.LogRecords()
	require.Len(t, records, 1)
	rec := records[0]

	require.Equal(t, "hello from slog", rec.Body.GetStringValue())
	require.Equal(t, logsv1.SeverityNumber(9), rec.SeverityNumber) // INFO 频段基数
	require.Equal(t, "INFO", rec.SeverityText)

	// logs SDK 原生地从发出时的 context 填充 TraceID/SpanID。
	sc := span.SpanContext()
	require.Equal(t, sc.TraceID().String(), hex.EncodeToString(rec.TraceId))
	require.Equal(t, sc.SpanID().String(), hex.EncodeToString(rec.SpanId))

	for key, want := range map[string]string{
		"str":     "v",
		"g.inner": "iv",
	} {
		v, ok := mebsutatest.AttrValue(rec.Attributes, key)
		require.True(t, ok, "属性 %s 必须存在", key)
		require.Equal(t, want, v, "属性 %s", key)
	}
	nums := map[string]int64{"n": 42, "d": 150 * int64(time.Millisecond)}
	for key, want := range nums {
		kv := findAttr(rec.Attributes, key)
		require.NotNil(t, kv, "整型属性 %s 必须存在", key)
		require.Equal(t, want, kv.Value.GetIntValue(), "整型属性 %s", key)
	}
	kv := findAttr(rec.Attributes, "f")
	require.NotNil(t, kv, "浮点属性 f 必须存在")
	require.Equal(t, 1.5, kv.Value.GetDoubleValue())
	kv = findAttr(rec.Attributes, "b")
	require.NotNil(t, kv, "布尔属性 b 必须存在")
	require.True(t, kv.Value.GetBoolValue())
}

func TestHandler_LevelMapping(t *testing.T) {
	tel, r := startPipeline(t, telemetry.Logs)
	defer r.Close()

	logger := slog.New(NewHandler(tel.LoggerProvider(), Config{}))
	logger.Warn("w")
	logger.Error("e")
	logger.Log(context.Background(), mebsuta.LevelAudit, "audit")
	require.NoError(t, tel.Shutdown(context.Background()))

	records := r.LogRecords()
	require.Len(t, records, 3)
	for i, want := range []logsv1.SeverityNumber{13, 17, 21} {
		require.Equal(t, want, records[i].SeverityNumber, "记录 %d 的 SeverityNumber", i)
	}
}

func TestHandler_PresetAndGroups(t *testing.T) {
	tel, r := startPipeline(t, telemetry.Logs)
	defer r.Close()

	base := slog.New(NewHandler(tel.LoggerProvider(), Config{}))
	// group 之前预置的属性不得带上 group 前缀。
	preset := base.With("service", "billing")
	grouped := preset.WithGroup("req").With(slog.String("id", "7"))
	grouped.Info("through groups")
	require.NoError(t, tel.Shutdown(context.Background()))

	records := r.LogRecords()
	require.Len(t, records, 1)
	for key, want := range map[string]string{
		"service": "billing",
		"req.id":  "7",
	} {
		v, ok := mebsutatest.AttrValue(records[0].Attributes, key)
		require.True(t, ok, "属性 %s 必须存在", key)
		require.Equal(t, want, v, "属性 %s", key)
	}
}

func TestHandler_MinLevel(t *testing.T) {
	tel, r := startPipeline(t, telemetry.Logs)
	defer r.Close()

	logger := slog.New(NewHandler(tel.LoggerProvider(), Config{MinLevel: slog.LevelWarn}))
	logger.Info("dropped")
	logger.Warn("kept")
	require.NoError(t, tel.Shutdown(context.Background()))

	records := r.LogRecords()
	require.Len(t, records, 1)
	require.Equal(t, "kept", records[0].Body.GetStringValue())
}

func TestHandler_NilProvider(t *testing.T) {
	// nil provider 退化为静默而不是 panic，因此选项接线可以无条件进行。
	h := NewHandler(nil, Config{})
	// 零值 MinLevel 默认为 Info（项目约定）。
	require.True(t, h.Enabled(context.Background(), slog.LevelInfo),
		"nil-provider handler 在 Info 级别仍必须报告 Enabled")
	require.False(t, h.Enabled(context.Background(), slog.LevelDebug),
		"Debug 必须被 Info 默认值过滤")
	require.NoError(t, h.Handle(context.Background(), slog.NewRecord(time.Now(), slog.LevelInfo, "m", 0)))
}

func findAttr(attrs []*commonpb.KeyValue, key string) *commonpb.KeyValue {
	for _, kv := range attrs {
		if kv.GetKey() == key {
			return kv
		}
	}
	return nil
}

// TestHandler_SeverityTextAudit:OTLP severity text 对 AUDIT 记录渲染
// 规范文本 "AUDIT"(B7)而非 slog 数值形式 "ERROR+4";severity number
// 走共享映射(21)。
func TestHandler_SeverityTextAudit(t *testing.T) {
	tel, r := startPipeline(t, telemetry.Logs)
	defer r.Close()

	logger := slog.New(NewHandler(tel.LoggerProvider(), Config{}))
	logger.Log(context.Background(), mebsuta.LevelAudit, "audit via otlp")
	require.NoError(t, tel.Shutdown(context.Background()))

	records := r.LogRecords()
	require.Len(t, records, 1)
	require.Equal(t, "AUDIT", records[0].SeverityText, "severity text renders the named level")
	require.Equal(t, logsv1.SeverityNumber(21), records[0].SeverityNumber, "audit maps to the fatal band")
}

// TestHandler_SetLevel:MinLevel 传入 *slog.LevelVar 后支持运行时热调
// (B20)——此前固定 slog.Level 使 mebsuta.SetLevel 对本 handler 静默
// 无效(applied=0 且 skipped 为空)。
func TestHandler_SetLevel(t *testing.T) {
	tel, r := startPipeline(t, telemetry.Logs)
	defer r.Close()

	lv := mebsuta.NewLevelVar(slog.LevelInfo)
	logger := slog.New(NewHandler(tel.LoggerProvider(), Config{MinLevel: lv}))
	logger.Debug("dropped at info")

	h := logger.Handler().(*Handler)
	require.True(t, h.SetLevel(slog.LevelWarn), "LevelVar-backed MinLevel is hot-adjustable")
	logger.Info("dropped at warn")
	logger.Warn("kept")
	require.NoError(t, tel.Shutdown(context.Background()))

	records := r.LogRecords()
	require.Len(t, records, 1)
	require.Equal(t, "kept", records[0].Body.GetStringValue())
}
