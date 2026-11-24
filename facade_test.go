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

// bootTelemetry starts a real bootstrap against a capture receiver.
// 0.1.0-29 起 span/metric 门面是 Telemetry 的实例方法,直接绑定实例
// (不再经 otel 全局转发)。
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

func TestStartSpan_Instance(t *testing.T) {
	tel, r := bootTelemetry(t, telemetry.Traces)
	defer r.Close()
	defer resetGlobals()

	_, span := tel.StartSpan(context.Background(), "facade-op", attribute.String("k", "v"))
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

	ctx, span := tel.StartSpan(context.Background(), "with-log")
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
	tel.Counter(ctx, "facade.requests", 2, attribute.String("route", "/api"))
	tel.Counter(ctx, "facade.requests", 3, attribute.String("route", "/api"))
	tel.Histogram(ctx, "facade.latency_ms", 12.5)
	tel.Gauge(ctx, "facade.queue_depth", 7)

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

func TestTelemetryFacade_NoOp(t *testing.T) {
	// 未启动(零值/nil 实例)的门面必须安全静默:无 panic、无输出。
	ctx := context.Background()
	var unstarted *telemetry.Telemetry
	_, span := unstarted.StartSpan(ctx, "noop")
	span.End()
	unstarted.Counter(ctx, "noop.requests", 1)
	unstarted.Histogram(ctx, "noop.latency", 1)
	unstarted.Gauge(ctx, "noop.depth", 1)
	zero := &telemetry.Telemetry{}
	_, span = zero.StartSpan(ctx, "noop")
	span.End()
	zero.Counter(ctx, "noop.requests", 1)
	zero.Histogram(ctx, "noop.latency", 1)
	zero.Gauge(ctx, "noop.depth", 1)
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

// TestMetricFacade_InstanceIsolation:instrument 缓存归实例所有——
// 两个实例对同一名字各自计数、互不串扰;实例 Shutdown 后其缓存随之
// 作废,新实例从零开始(0.1.0-29 起,取代"provider 代次轮换"语义——
// 门面已不再经全局转发)。
func TestMetricFacade_InstanceIsolation(t *testing.T) {
	tel1, r1 := bootTelemetry(t, telemetry.Metrics)
	tel1.Counter(context.Background(), "iso.probe", 1)

	tel2, r2 := bootTelemetry(t, telemetry.Metrics)
	tel2.Counter(context.Background(), "iso.probe", 41)

	require.NoError(t, tel1.Shutdown(context.Background()))
	require.NoError(t, tel2.Shutdown(context.Background()))
	defer resetGlobals()

	count := func(r *mebsutatest.OTLPReceiver) int64 {
		for _, m := range r.MetricFamilies() {
			if m.Name == "iso.probe" {
				return m.GetSum().GetDataPoints()[0].GetAsInt()
			}
		}
		return -1
	}
	require.Equal(t, int64(1), count(r1), "instance 1 keeps its own counter")
	require.Equal(t, int64(41), count(r2), "instance 2 is independent (no shared instrument cache)")
}
