package metrics_test

// 0.1.0-27 起 Metrics 收敛为 mebsuta.HandlerMetrics 的唯一实现
// (ObserveHandle/IncError/IncDroppedN);包内其余 13 个 mutator 是
// 从未接线的死指标面,已删除。

import (
	"sync"
	"testing"
	"time"

	mebmetrics "github.com/iuboy/mebsuta/metrics"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
)

// newTestMetrics 创建一个注册到独立 registry 的全新 Metrics 实例。
func newTestMetrics(t *testing.T) (*mebmetrics.Metrics, *prometheus.Registry) {
	t.Helper()
	m := mebmetrics.NewMetrics()
	reg := prometheus.NewPedanticRegistry()
	require.NoError(t, reg.Register(m))
	return m, reg
}

// counterValue 读指定名字的 counter 当前值。
func counterValue(t *testing.T, reg *prometheus.Registry, name string) float64 {
	t.Helper()
	mfs, err := reg.Gather()
	require.NoError(t, err)
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
		total := 0.0
		for _, m := range mf.GetMetric() {
			total += m.GetCounter().GetValue()
		}
		return total
	}
	t.Fatalf("metric %q not gathered", name)
	return 0
}

// TestRegister 注册冒烟:三个指标(写延迟/错误/丢弃)均可采集。
func TestRegister(t *testing.T) {
	m, reg := newTestMetrics(t)
	require.NotNil(t, m)

	mfs, err := reg.Gather()
	require.NoError(t, err)
	// CounterVec 无样本时不产出 family;直方图恒在。逐名确认注册面。
	names := map[string]bool{}
	for _, mf := range mfs {
		names[mf.GetName()] = true
	}
	require.True(t, names["mebsuta_write_latency_seconds"], "latency histogram registered")
}

// TestIncError 覆盖 handler 名称标签维度。
func TestIncError(t *testing.T) {
	m, reg := newTestMetrics(t)
	m.IncError("stdout")
	m.IncError("stdout")
	m.IncError("database")
	require.Equal(t, 3.0, counterValue(t, reg, "mebsuta_log_errors_total"))
}

// TestIncDroppedN 幅值语义:一次上报携带批量丢弃数 n,而非逐条 +1。
func TestIncDroppedN(t *testing.T) {
	m, reg := newTestMetrics(t)
	m.IncDroppedN("async", 25)
	m.IncDroppedN("async", 1)
	require.Equal(t, 26.0, counterValue(t, reg, "mebsuta_log_dropped_total"))
}

// TestObserveHandle 延迟直方图采集。
func TestObserveHandle(t *testing.T) {
	m, reg := newTestMetrics(t)
	m.ObserveHandle(5 * time.Millisecond)
	m.ObserveHandle(10 * time.Millisecond)

	mfs, err := reg.Gather()
	require.NoError(t, err)
	var count uint64
	for _, mf := range mfs {
		if mf.GetName() == "mebsuta_write_latency_seconds" {
			for _, hm := range mf.GetMetric() {
				count += hm.GetHistogram().GetSampleCount()
			}
		}
	}
	require.Equal(t, uint64(2), count, "two observations recorded")
}

// TestMetrics_ImplementsHandlerMetrics 编译期契约:三个方法构成
// mebsuta.HandlerMetrics 的完整实现。
func TestMetrics_ImplementsHandlerMetrics(t *testing.T) {
	m, _ := newTestMetrics(t)
	var iface interface {
		ObserveHandle(duration time.Duration)
		IncError(output string)
		IncDroppedN(output string, n int64)
	} = m
	require.NotNil(t, iface)
}

// TestConcurrentMetrics 并发调用三方法无竞争(-race 下验证)。
func TestConcurrentMetrics(t *testing.T) {
	m, reg := newTestMetrics(t)
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 50 {
				m.ObserveHandle(time.Millisecond)
				m.IncError("concurrent")
				m.IncDroppedN("concurrent", 1)
			}
		}()
		_ = i
	}
	wg.Wait()
	require.Equal(t, 400.0, counterValue(t, reg, "mebsuta_log_errors_total"))
}
