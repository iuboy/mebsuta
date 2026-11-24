package prombridge

import (
	"context"
	"testing"
	"time"

	"github.com/iuboy/mebsuta/mebsutatest"
	"github.com/iuboy/mebsuta/telemetry"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
)

// TestBridge_CountersAndGauges 面向捕获接收端驱动两轮轮询：counter 必须
// 桥接为单调累计值的每次轮询增量（而非再次输出原始累计值），gauge 按
// 最后写入胜出，histogram 必须被跳过并计入诚实健康计数。
func TestBridge_CountersAndGauges(t *testing.T) {
	r := mebsutatest.NewOTLPReceiver()
	defer r.Close()
	no := false
	tel, err := telemetry.Start(context.Background(), telemetry.Config{
		ServiceName: "prombridge-test",
		Endpoint:    r.URL(),
		Signals:     telemetry.Metrics,
		SetGlobal:   &no,
	})
	require.NoError(t, err)
	defer tel.Shutdown(context.Background())

	reg := prometheus.NewRegistry()
	reqs := prometheus.NewCounterVec(prometheus.CounterOpts{Name: "svc_requests_total"}, []string{"route"})
	depth := prometheus.NewGauge(prometheus.GaugeOpts{Name: "svc_queue_depth"})
	lat := prometheus.NewHistogram(prometheus.HistogramOpts{Name: "svc_latency"})
	reg.MustRegister(reqs, depth, lat)

	b, err := Start(context.Background(), tel.MeterProvider(), reg, WithInterval(time.Hour))
	require.NoError(t, err)
	defer b.Close()

	// 第一个窗口：/api 加 2，gauge 置 7。
	reqs.WithLabelValues("/api").Add(2)
	depth.Set(7)
	lat.Observe(0.5)
	b.pollOnce(context.Background())

	// 第二个窗口：再加 3（累计 5），gauge 改写为 9。
	reqs.WithLabelValues("/api").Add(3)
	depth.Set(9)
	b.pollOnce(context.Background())

	require.NoError(t, tel.Shutdown(context.Background()))

	var counterDP, gaugeDP float64
	for _, m := range r.MetricFamilies() {
		switch m.Name {
		case "svc_requests_total":
			require.NotNil(t, m.GetSum(), "counter must bridge as a sum")
			dp := m.GetSum().GetDataPoints()
			require.Len(t, dp, 1)
			counterDP = dp[0].GetAsDouble()
			v, ok := mebsutatest.AttrValue(dp[0].Attributes, "route")
			require.True(t, ok, "route 属性必须存在")
			require.Equal(t, "/api", v, "route 属性")
		case "svc_queue_depth":
			require.NotNil(t, m.GetGauge(), "gauge must bridge as a gauge")
			dp := m.GetGauge().GetDataPoints()
			require.Len(t, dp, 1)
			gaugeDP = dp[0].GetAsDouble()
		case "svc_latency":
			require.FailNow(t, "histogram 必须被跳过，却得到 family %s", m.Name)
		}
	}
	require.Equal(t, 5.0, counterDP, "counter must bridge deltas to the full total")
	require.Equal(t, 9.0, gaugeDP, "gauge must be last-write-wins")
	require.Equal(t, map[string]int{"svc_latency": 2}, b.Skipped(), "skipped-health must count histogram observations")
}

// TestBridge_UntypedAndCounterReset:UNTYPED 指标必须经 GetUntyped 读取
// (GetGauge 对 untyped 恒读 0,B16);counter 重置(值变小)必须从头累计
// 而非导出负增量。
func TestBridge_UntypedAndCounterReset(t *testing.T) {
	r := mebsutatest.NewOTLPReceiver()
	defer r.Close()
	no := false
	tel, err := telemetry.Start(context.Background(), telemetry.Config{
		ServiceName: "prombridge-untyped", Endpoint: r.URL(),
		Signals: telemetry.Metrics, SetGlobal: &no,
	})
	require.NoError(t, err)
	defer tel.Shutdown(context.Background())

	reg := prometheus.NewRegistry()
	unt := prometheus.NewUntypedFunc(prometheus.UntypedOpts{Name: "svc_untyped"}, func() float64 { return 42 })
	reqs := prometheus.NewCounterVec(prometheus.CounterOpts{Name: "svc_reset_total"}, nil)
	reg.MustRegister(unt, reqs)

	b, err := Start(context.Background(), tel.MeterProvider(), reg, WithInterval(time.Hour))
	require.NoError(t, err)
	defer b.Close()

	reqs.WithLabelValues().Add(5)
	b.pollOnce(context.Background())

	// counter 重置(CounterVec.Reset 模拟进程重启):从 1 重新累计。
	reqs.Reset()
	reqs.WithLabelValues().Add(1)
	b.pollOnce(context.Background())
	require.NoError(t, tel.Shutdown(context.Background()))

	var untypedVal, counterVal float64
	for _, m := range r.MetricFamilies() {
		switch m.Name {
		case "svc_untyped":
			require.NotNil(t, m.GetGauge(), "untyped must bridge as gauge (last-write)")
			untypedVal = m.GetGauge().GetDataPoints()[0].GetAsDouble()
		case "svc_reset_total":
			counterVal = m.GetSum().GetDataPoints()[0].GetAsDouble()
		}
	}
	require.Equal(t, 42.0, untypedVal, "untyped value read via GetUntyped, not 0")
	// OTel counter 累计两轮增量(5 + 1);若重置误算为负增量,
	// 第二轮会报 -4,总和为 1——6 证明重置后从头累计。
	require.Equal(t, 6.0, counterVal, "counter reset restarts from the new value, not negative delta")
}
