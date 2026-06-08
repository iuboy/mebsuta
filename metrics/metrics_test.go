package metrics_test

import (
	"sync"
	"testing"

	mebmetrics "github.com/iuboy/mebsuta/metrics"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestMetrics creates a fresh Metrics instance registered in an isolated registry.
func newTestMetrics(t *testing.T) (*mebmetrics.Metrics, *prometheus.Registry) {
	t.Helper()
	m := mebmetrics.NewMetrics()
	reg := prometheus.NewPedanticRegistry()
	require.NoError(t, reg.Register(m))
	return m, reg
}

// TestRegister 测试注册metrics
func TestRegister(t *testing.T) {
	m, reg := newTestMetrics(t)
	require.NotNil(t, m)

	// Verify the collector is registered by gathering.
	mfs, err := reg.Gather()
	require.NoError(t, err)
	assert.NotEmpty(t, mfs)
}

// TestIncLogWrite 测试记录日志写入
func TestIncLogWrite(t *testing.T) {
	m, reg := newTestMetrics(t)

	m.IncLogWrite("info", "stdout")
	m.IncLogWrite("error", "db")
	m.IncLogWrite("debug", "file")

	mfs, err := reg.Gather()
	require.NoError(t, err)

	found := false
	for _, mf := range mfs {
		if mf.GetName() == "mebsuta_log_writes_total" {
			found = true
			metricCount := 0
			for _, m := range mf.GetMetric() {
				metricCount++
				labels := prometheus.Labels{}
				for _, label := range m.GetLabel() {
					labels[label.GetName()] = label.GetValue()
				}
				assert.Contains(t, []string{"info", "error", "debug"}, labels["level"])
			}
			assert.GreaterOrEqual(t, metricCount, 3)
		}
	}
	assert.True(t, found, "未找到mebsuta_log_writes_total指标")
}

// TestIncLogDropped 测试记录日志丢弃
func TestIncLogDropped(t *testing.T) {
	m, reg := newTestMetrics(t)

	m.IncLogDropped("buffer_full", "stdout")
	m.IncLogDropped("sampling", "file")

	mfs, err := reg.Gather()
	require.NoError(t, err)

	found := false
	for _, mf := range mfs {
		if mf.GetName() == "mebsuta_log_dropped_total" {
			found = true
			assert.GreaterOrEqual(t, len(mf.GetMetric()), 2)
		}
	}
	assert.True(t, found, "未找到mebsuta_log_dropped_total指标")
}

// TestIncLogError 测试记录日志错误
func TestIncLogError(t *testing.T) {
	m, reg := newTestMetrics(t)

	m.IncLogError("write_failed", "db")
	m.IncLogError("parse_failed", "influxdb")

	mfs, err := reg.Gather()
	require.NoError(t, err)

	found := false
	for _, mf := range mfs {
		if mf.GetName() == "mebsuta_log_errors_total" {
			found = true
			assert.GreaterOrEqual(t, len(mf.GetMetric()), 2)
		}
	}
	assert.True(t, found, "未找到mebsuta_log_errors_total指标")
}

// TestIncBatchWrite 测试批量写入指标
func TestIncBatchWrite(t *testing.T) {
	m, reg := newTestMetrics(t)

	m.IncBatchWrite()
	m.IncBatchWrite()
	m.IncBatchWrite()

	mfs, err := reg.Gather()
	require.NoError(t, err)

	found := false
	for _, mf := range mfs {
		if mf.GetName() == "mebsuta_batch_writes_total" {
			found = true
			count := mf.GetMetric()[0].GetCounter().GetValue()
			assert.Equal(t, 3.0, count)
		}
	}
	assert.True(t, found, "未找到mebsuta_batch_writes_total指标")
}

// TestObserveBatchSize 测试记录批量大小
func TestObserveBatchSize(t *testing.T) {
	m, reg := newTestMetrics(t)

	sizes := []float64{10, 50, 100, 200}
	for _, size := range sizes {
		m.ObserveBatchSize(size)
	}

	mfs, err := reg.Gather()
	require.NoError(t, err)

	found := false
	for _, mf := range mfs {
		if mf.GetName() == "mebsuta_batch_size" {
			found = true
			assert.GreaterOrEqual(t, len(mf.GetMetric()), 1)
			h := mf.GetMetric()[0].GetHistogram()
			assert.Equal(t, uint64(4), h.GetSampleCount())
		}
	}
	assert.True(t, found, "未找到mebsuta_batch_size指标")
}

// TestObserveBatchLatency 测试记录批量延迟
func TestObserveBatchLatency(t *testing.T) {
	m, reg := newTestMetrics(t)

	latencies := []float64{0.001, 0.005, 0.01, 0.05}
	for _, latency := range latencies {
		m.ObserveBatchLatency(latency)
	}

	mfs, err := reg.Gather()
	require.NoError(t, err)

	found := false
	for _, mf := range mfs {
		if mf.GetName() == "mebsuta_batch_latency_seconds" {
			found = true
			assert.GreaterOrEqual(t, len(mf.GetMetric()), 1)
			h := mf.GetMetric()[0].GetHistogram()
			assert.Equal(t, uint64(4), h.GetSampleCount())
		}
	}
	assert.True(t, found, "未找到mebsuta_batch_latency_seconds指标")
}

// TestIncBatchFailure 测试批量写入失败
func TestIncBatchFailure(t *testing.T) {
	m, reg := newTestMetrics(t)

	m.IncBatchFailure()
	m.IncBatchFailure()

	mfs, err := reg.Gather()
	require.NoError(t, err)

	found := false
	for _, mf := range mfs {
		if mf.GetName() == "mebsuta_batch_failures_total" {
			found = true
			count := mf.GetMetric()[0].GetCounter().GetValue()
			assert.Equal(t, 2.0, count)
		}
	}
	assert.True(t, found, "未找到mebsuta_batch_failures_total指标")
}

// TestSetBufferUsage 测试缓冲区使用率
func TestSetBufferUsage(t *testing.T) {
	m, reg := newTestMetrics(t)

	usages := []float64{0.1, 0.5, 0.8, 1.0}
	for _, usage := range usages {
		m.SetBufferUsage(usage)
	}

	mfs, err := reg.Gather()
	require.NoError(t, err)

	found := false
	for _, mf := range mfs {
		if mf.GetName() == "mebsuta_buffer_usage" {
			found = true
			value := mf.GetMetric()[0].GetGauge().GetValue()
			assert.Equal(t, 1.0, value)
		}
	}
	assert.True(t, found, "未找到mebsuta_buffer_usage指标")
}

// TestIncBufferFull 测试缓冲区满事件
func TestIncBufferFull(t *testing.T) {
	m, reg := newTestMetrics(t)

	m.IncBufferFull()
	m.IncBufferFull()

	mfs, err := reg.Gather()
	require.NoError(t, err)

	found := false
	for _, mf := range mfs {
		if mf.GetName() == "mebsuta_buffer_full_total" {
			found = true
			count := mf.GetMetric()[0].GetCounter().GetValue()
			assert.Equal(t, 2.0, count)
		}
	}
	assert.True(t, found, "未找到mebsuta_buffer_full_total指标")
}

// TestSetActiveConns 测试设置活跃连接数
func TestSetActiveConns(t *testing.T) {
	m, reg := newTestMetrics(t)

	conns := []float64{5, 10, 20}
	for _, conn := range conns {
		m.SetActiveConns(conn)
	}

	mfs, err := reg.Gather()
	require.NoError(t, err)

	found := false
	for _, mf := range mfs {
		if mf.GetName() == "mebsuta_active_connections" {
			found = true
			value := mf.GetMetric()[0].GetGauge().GetValue()
			assert.Equal(t, 20.0, value)
		}
	}
	assert.True(t, found, "未找到mebsuta_active_connections指标")
}

// TestSetIdleConns 测试设置空闲连接数
func TestSetIdleConns(t *testing.T) {
	m, reg := newTestMetrics(t)

	conns := []float64{2, 5, 10}
	for _, conn := range conns {
		m.SetIdleConns(conn)
	}

	mfs, err := reg.Gather()
	require.NoError(t, err)

	found := false
	for _, mf := range mfs {
		if mf.GetName() == "mebsuta_idle_connections" {
			found = true
			value := mf.GetMetric()[0].GetGauge().GetValue()
			assert.Equal(t, 10.0, value)
		}
	}
	assert.True(t, found, "未找到mebsuta_idle_connections指标")
}

// TestIncGoroutine 测试goroutine计数
func TestIncGoroutine(t *testing.T) {
	m, reg := newTestMetrics(t)

	m.IncGoroutine()
	m.IncGoroutine()
	m.IncGoroutine()

	m.DecGoroutine()
	m.DecGoroutine()

	mfs, err := reg.Gather()
	require.NoError(t, err)

	for _, mf := range mfs {
		if mf.GetName() == "mebsuta_active_goroutines" {
			value := mf.GetMetric()[0].GetGauge().GetValue()
			assert.Equal(t, 1.0, value)
			return
		}
	}
	t.Fatal("未找到mebsuta_active_goroutines指标")
}

// TestMetricsWithEncoderCache 测试编码器缓存metrics
func TestMetricsWithEncoderCache(t *testing.T) {
	m, reg := newTestMetrics(t)

	m.IncLogWrite("encoder_cache_evict", "cache")
	m.IncLogWrite("encoder_cache_evict", "cache")

	mfs, err := reg.Gather()
	require.NoError(t, err)

	found := false
	for _, mf := range mfs {
		if mf.GetName() == "mebsuta_log_writes_total" {
			for _, metric := range mf.GetMetric() {
				for _, label := range metric.GetLabel() {
					if label.GetName() == "level" && label.GetValue() == "encoder_cache_evict" {
						found = true
					}
				}
			}
		}
	}
	assert.True(t, found, "未找到编码器缓存淘汰指标")
}

// TestMetricsWithStructuredCore 测试与StructuredCore集成
func TestMetricsWithStructuredCore(t *testing.T) {
	m, reg := newTestMetrics(t)

	for range 10 {
		m.IncLogWrite("info", "structured_core")
	}

	mfs, err := reg.Gather()
	require.NoError(t, err)

	logWriteFound := false
	for _, mf := range mfs {
		if mf.GetName() == "mebsuta_log_writes_total" {
			logWriteFound = true
		}
	}
	assert.True(t, logWriteFound, "应记录日志写入指标")
}

// TestGoroutineCount 测试goroutine计数
func TestGoroutineCount(t *testing.T) {
	m, reg := newTestMetrics(t)

	// 全新实例，计数器从0开始
	mfs, err := reg.Gather()
	require.NoError(t, err)
	for _, mf := range mfs {
		if mf.GetName() == "mebsuta_active_goroutines" {
			assert.Equal(t, 0.0, mf.GetMetric()[0].GetGauge().GetValue())
		}
	}

	m.IncGoroutine()
	m.IncGoroutine()
	m.IncGoroutine()

	m.DecGoroutine()

	// Verify via Prometheus gauge
	mfs, err = reg.Gather()
	require.NoError(t, err)
	for _, mf := range mfs {
		if mf.GetName() == "mebsuta_active_goroutines" {
			assert.Equal(t, 2.0, mf.GetMetric()[0].GetGauge().GetValue())
		}
	}
}

// TestEventWriteSyncerMetrics 测试事件写入同步器metrics
func TestEventWriteSyncerMetrics(t *testing.T) {
	m, reg := newTestMetrics(t)

	for range 5 {
		m.IncLogWrite("info", "event_writer")
	}

	mfs, err := reg.Gather()
	require.NoError(t, err)

	found := false
	for _, mf := range mfs {
		if mf.GetName() == "mebsuta_log_writes_total" {
			for _, metric := range mf.GetMetric() {
				for _, label := range metric.GetLabel() {
					if label.GetName() == "output" && label.GetValue() == "event_writer" {
						found = true
					}
				}
			}
		}
	}
	assert.True(t, found, "未找到事件写入器指标")
}

// TestConcurrentMetrics 测试并发metrics
func TestConcurrentMetrics(t *testing.T) {
	m, reg := newTestMetrics(t)

	var wg sync.WaitGroup

	for i := range 10 {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := range 100 {
				m.IncLogWrite("info", "stdout")
				m.IncBatchWrite()
				m.ObserveBatchSize(float64(j))
			}
		}(i)
	}

	wg.Wait()

	mfs, err := reg.Gather()
	require.NoError(t, err)

	for _, mf := range mfs {
		if mf.GetName() == "mebsuta_log_writes_total" {
			for _, metric := range mf.GetMetric() {
				labels := make(map[string]string)
				for _, label := range metric.GetLabel() {
					labels[label.GetName()] = label.GetValue()
				}
				if labels["level"] == "info" && labels["output"] == "stdout" {
					count := metric.GetCounter().GetValue()
					assert.Equal(t, 1000.0, count)
				}
			}
		}
		if mf.GetName() == "mebsuta_batch_writes_total" {
			for _, metric := range mf.GetMetric() {
				count := metric.GetCounter().GetValue()
				assert.Equal(t, 1000.0, count)
			}
		}
		if mf.GetName() == "mebsuta_batch_size" {
			h := mf.GetMetric()[0].GetHistogram()
			assert.Equal(t, uint64(1000), h.GetSampleCount())
		}
	}
}

// TestMetricLabelCombinations 测试不同的标签组合
func TestMetricLabelCombinations(t *testing.T) {
	m, reg := newTestMetrics(t)

	levels := []string{"debug", "info", "warn", "error", "fatal"}
	outputs := []string{"stdout", "file", "db", "syslog", "influxdb"}

	for _, level := range levels {
		for _, output := range outputs {
			m.IncLogWrite(level, output)
		}
	}

	mfs, err := reg.Gather()
	require.NoError(t, err)

	found := false
	for _, mf := range mfs {
		if mf.GetName() == "mebsuta_log_writes_total" {
			found = true
			assert.Equal(t, 25, len(mf.GetMetric()), "should have exactly 5*5=25 label combinations")
		}
	}
	assert.True(t, found)
}

// TestNewMethods 测试Metrics所有方法
func TestNewMethods(t *testing.T) {
	m, _ := newTestMetrics(t)

	// 测试所有方法不 panic
	m.IncLogWrite("info", "stdout")
	m.IncBatchWrite()
	m.ObserveBatchSize(50)
	m.SetBufferUsage(0.5)
	m.SetActiveConns(10)
	m.SetIdleConns(5)
	m.IncGoroutine()
	m.DecGoroutine()
}
