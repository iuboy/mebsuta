package mebsuta_test

import (
	"context"
	"log/slog"
	"testing"

	"github.com/iuboy/mebsuta"
	"github.com/iuboy/mebsuta/mebsutatest"
	"github.com/iuboy/mebsuta/telemetry"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// bootTelemetry starts a real bootstrap against a capture receiver with
// globals enabled — the facades delegate to the otel globals, which is
// what telemetry.Start wires by default.
func bootTelemetry(t *testing.T, signals telemetry.Signals) (*telemetry.Telemetry, *mebsutatest.OTLPReceiver) {
	t.Helper()
	r := mebsutatest.NewOTLPReceiver()
	tel, err := telemetry.Start(context.Background(), telemetry.Config{
		ServiceName: "facade-test",
		Endpoint:    r.URL(),
		Signals:     signals,
	})
	require.NoError(t, err)
	return tel, r
}

// resetGlobals 复位 otel 全局与 telemetry 安装跟踪（公共测试工具）。
func resetGlobals() {
	mebsutatest.ResetOTelGlobals()
	telemetry.ResetGlobalTracking()
}

func TestStartSpan_Facade(t *testing.T) {
	tel, r := bootTelemetry(t, telemetry.Traces)
	defer r.Close()
	defer resetGlobals()

	_, span := mebsuta.StartSpan(context.Background(), "facade-op", attribute.String("k", "v"))
	span.End()

	require.NoError(t, tel.Shutdown(context.Background()))
	spans := r.Spans()
	require.Len(t, spans, 1)
	require.Equal(t, "facade-op", spans[0].Name)
}

func TestTraceContextExtractor(t *testing.T) {
	tel, r := bootTelemetry(t, telemetry.Traces)
	defer r.Close()
	defer resetGlobals()
	defer func() { _ = tel.Shutdown(context.Background()) }()

	extract := mebsuta.TraceContextExtractor()

	require.Nil(t, extract(context.Background()), "no-span context must yield no attrs")

	ctx, span := mebsuta.StartSpan(context.Background(), "with-log")
	defer span.End()
	attrs := extract(ctx)
	require.Len(t, attrs, 2, "want trace_id + span_id")
	sc := trace.SpanContextFromContext(ctx)
	want := map[string]string{
		"trace_id": sc.TraceID().String(),
		"span_id":  sc.SpanID().String(),
	}
	for _, a := range attrs {
		require.Equal(t, want[a.Key], a.Value.String(), "attr %s", a.Key)
	}
}

func TestMetricFacades(t *testing.T) {
	tel, r := bootTelemetry(t, telemetry.Metrics)
	defer r.Close()
	defer resetGlobals()

	ctx := context.Background()
	mebsuta.Counter(ctx, "facade.requests", 2, attribute.String("route", "/api"))
	mebsuta.Counter(ctx, "facade.requests", 3, attribute.String("route", "/api"))
	mebsuta.Histogram(ctx, "facade.latency_ms", 12.5)
	mebsuta.Gauge(ctx, "facade.queue_depth", 7)

	require.NoError(t, tel.Shutdown(context.Background()))

	byName := map[string]int{}
	for _, m := range r.MetricFamilies() {
		byName[m.Name]++
	}
	for _, name := range []string{"facade.requests", "facade.latency_ms", "facade.queue_depth"} {
		require.Equal(t, 1, byName[name], "metric %s (instrument caching)", name)
	}

	for _, m := range r.MetricFamilies() {
		switch m.Name {
		case "facade.requests":
			dp := m.GetSum().GetDataPoints()
			require.Len(t, dp, 1)
			require.Equal(t, int64(5), dp[0].GetAsInt(), "counter datapoints, want single sum 5")
			v, ok := mebsutatest.AttrValue(dp[0].Attributes, "route")
			require.True(t, ok, "counter attr route present")
			require.Equal(t, "/api", v, "counter attr route")
		case "facade.latency_ms":
			dp := m.GetHistogram().GetDataPoints()
			require.Len(t, dp, 1)
			require.Equal(t, uint64(1), dp[0].GetCount(), "histogram count")
			require.Equal(t, 12.5, dp[0].GetSum(), "histogram sum")
		case "facade.queue_depth":
			dp := m.GetGauge().GetDataPoints()
			require.Len(t, dp, 1)
			require.Equal(t, int64(7), dp[0].GetAsInt(), "gauge datapoints, want single value 7")
		}
	}
}

func TestFacadesWithoutGlobals(t *testing.T) {
	// With no provider registered the otel globals are no-ops: every
	// facade call must be safe and silent.
	resetGlobals()
	defer resetGlobals()
	ctx := context.Background()
	_, span := mebsuta.StartSpan(ctx, "noop")
	span.End()
	mebsuta.Counter(ctx, "noop.requests", 1)
	mebsuta.Histogram(ctx, "noop.latency", 1)
	mebsuta.Gauge(ctx, "noop.depth", 1)
}

func TestSetLevel_WalkAppliesAndSkips(t *testing.T) {
	lv := mebsuta.NewLevelVar(slog.LevelWarn)
	logger, err := mebsuta.New(
		mebsuta.UseStdout(mebsuta.StdoutConfig{Level: lv}),             // 热调面
		mebsuta.UseStdout(mebsuta.StdoutConfig{Level: slog.LevelInfo}), // 固定值 → skipped
	)
	require.NoError(t, err)

	ctx := context.Background()
	require.False(t, logger.Enabled(ctx, slog.LevelDebug), "Warn 起步：Debug 不启用")

	applied, skipped, err := mebsuta.SetLevel(logger.Handler(), slog.LevelDebug)
	require.NoError(t, err)
	require.Equal(t, 1, applied, "仅 LevelVar 构造的 stdout 生效")
	require.Len(t, skipped, 1)
	require.Contains(t, skipped[0], "StdoutHandler", "固定值 handler 进入诚实面")

	require.True(t, logger.Enabled(ctx, slog.LevelDebug), "热调后 Debug 经 multi 扇出启用")

	// nil logger 无害。
	applied, skipped, err = mebsuta.SetLevel(nil, slog.LevelInfo)
	require.NoError(t, err)
	require.Zero(t, applied)
	require.Empty(t, skipped)
}

func TestSetLevel_DecoratorsTraverse(t *testing.T) {
	// 装饰器（async）包装下的内层 stdout 也要被遍历到。
	lv := mebsuta.NewLevelVar(slog.LevelError)
	logger, err := mebsuta.New(
		mebsuta.UseAsync(mebsuta.AsyncConfig{}),
		mebsuta.UseStdout(mebsuta.StdoutConfig{Level: lv}),
	)
	require.NoError(t, err)

	applied, skipped, err := mebsuta.SetLevel(logger.Handler(), slog.LevelInfo)
	require.NoError(t, err)
	require.Equal(t, 1, applied)
	require.Empty(t, skipped)
	require.Equal(t, slog.LevelInfo, lv.Level())
}

// TestMetricFacades_FollowProviderSwap:instrument 不得缓存在门面——
// 代次轮换(新 Start 覆盖全局)后,旧名字必须写进新 provider(0.1.0-22
// 修复:此前缓存的 instrument 绑死创建时的 provider,旧名字永远写进
// 已 Shutdown 的旧 provider)。
func TestMetricFacades_FollowProviderSwap(t *testing.T) {
	resetGlobals()
	tel1, _ := bootTelemetry(t, telemetry.Metrics)
	mebsuta.Counter(context.Background(), "swap.probe", 1)
	require.NoError(t, tel1.Shutdown(context.Background()))

	tel2, r2 := bootTelemetry(t, telemetry.Metrics)
	mebsuta.Counter(context.Background(), "swap.probe", 1)
	// Shutdown 触发最终 flush,批处理导出的数据此后才确定可见。
	require.NoError(t, tel2.Shutdown(context.Background()))
	defer resetGlobals()

	var found bool
	for _, m := range r2.MetricFamilies() {
		if m.Name == "swap.probe" {
			found = true
			dp := m.GetSum().GetDataPoints()
			require.Len(t, dp, 1)
			require.Equal(t, int64(1), dp[0].GetAsInt(),
				"new provider must receive the counter for a name first used under the previous provider")
		}
	}
	require.True(t, found, "swapped-in provider must see the instrument (facade must not cache instruments)")
}
