package metrics_test

import (
	"sync"
	"testing"

	mebmetrics "github.com/iuboy/mebsuta/metrics"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRegister 测试注册metrics
func TestRegister(t *testing.T) {
	// 注册metrics
	err := mebmetrics.Register()
	require.NoError(t, err)
}

// TestIncLogWrite 测试记录日志写入
func TestIncLogWrite(t *testing.T) {
	_ = mebmetrics.Register()

	// 记录日志
	mebmetrics.GetMetrics().IncLogWrite("info", "stdout")
	mebmetrics.GetMetrics().IncLogWrite("error", "db")
	mebmetrics.GetMetrics().IncLogWrite("debug", "file")

	// 验证指标
	mfs, err := prometheus.DefaultGatherer.Gather()
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
				// 验证标签
				assert.Contains(t, []string{"info", "error", "debug"}, labels["level"])
			}
			assert.GreaterOrEqual(t, metricCount, 3)
		}
	}
	assert.True(t, found, "未找到mebsuta_log_writes_total指标")
}

// TestIncLogDropped 测试记录日志丢弃
func TestIncLogDropped(t *testing.T) {
	_ = mebmetrics.Register()

	// 记录丢弃的日志
	mebmetrics.GetMetrics().IncLogDropped("buffer_full", "stdout")
	mebmetrics.GetMetrics().IncLogDropped("sampling", "file")

	// 验证指标
	mfs, err := prometheus.DefaultGatherer.Gather()
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
	_ = mebmetrics.Register()

	// 记录错误
	mebmetrics.GetMetrics().IncLogError("write_failed", "db")
	mebmetrics.GetMetrics().IncLogError("parse_failed", "influxdb")

	// 验证指标
	mfs, err := prometheus.DefaultGatherer.Gather()
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
	_ = mebmetrics.Register()

	// 记录批量写入
	mebmetrics.GetMetrics().IncBatchWrite()
	mebmetrics.GetMetrics().IncBatchWrite()
	mebmetrics.GetMetrics().IncBatchWrite()

	// 验证指标
	mfs, err := prometheus.DefaultGatherer.Gather()
	require.NoError(t, err)

	found := false
	for _, mf := range mfs {
		if mf.GetName() == "mebsuta_batch_writes_total" {
			found = true
			// 检查计数
			count := mf.GetMetric()[0].GetCounter().GetValue()
			assert.Equal(t, 3.0, count)
		}
	}
	assert.True(t, found, "未找到mebsuta_batch_writes_total指标")
}

// TestObserveBatchSize 测试记录批量大小
func TestObserveBatchSize(t *testing.T) {
	_ = mebmetrics.Register()

	// 记录不同大小的批量
	sizes := []float64{10, 50, 100, 200}
	for _, size := range sizes {
		mebmetrics.GetMetrics().ObserveBatchSize(size)
	}

	// 验证指标
	mfs, err := prometheus.DefaultGatherer.Gather()
	require.NoError(t, err)

	found := false
	for _, mf := range mfs {
		if mf.GetName() == "mebsuta_batch_size" {
			found = true
			// Histogram有固定的buckets数量（10个），每次观察会增加sample count
			// 检查是否有指标存在即可
			assert.GreaterOrEqual(t, len(mf.GetMetric()), 1)
			// 验证观察次数（通过sum或count）
			h := mf.GetMetric()[0].GetHistogram()
			assert.GreaterOrEqual(t, h.GetSampleCount(), uint64(4))
		}
	}
	assert.True(t, found, "未找到mebsuta_batch_size指标")
}

// TestObserveBatchLatency 测试记录批量延迟
func TestObserveBatchLatency(t *testing.T) {
	_ = mebmetrics.Register()

	// 记录不同延迟
	latencies := []float64{0.001, 0.005, 0.01, 0.05}
	for _, latency := range latencies {
		mebmetrics.GetMetrics().ObserveBatchLatency(latency)
	}

	// 验证指标
	mfs, err := prometheus.DefaultGatherer.Gather()
	require.NoError(t, err)

	found := false
	for _, mf := range mfs {
		if mf.GetName() == "mebsuta_batch_latency_seconds" {
			found = true
			// Histogram有固定的buckets数量
			// 检查是否有指标存在即可
			assert.GreaterOrEqual(t, len(mf.GetMetric()), 1)
			// 验证观察次数
			h := mf.GetMetric()[0].GetHistogram()
			assert.GreaterOrEqual(t, h.GetSampleCount(), uint64(4))
		}
	}
	assert.True(t, found, "未找到mebsuta_batch_latency_seconds指标")
}

// TestIncBatchFailure 测试批量写入失败
func TestIncBatchFailure(t *testing.T) {
	_ = mebmetrics.Register()

	// 记录失败
	mebmetrics.GetMetrics().IncBatchFailure()
	mebmetrics.GetMetrics().IncBatchFailure()

	// 验证指标
	mfs, err := prometheus.DefaultGatherer.Gather()
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
	_ = mebmetrics.Register()

	// 设置不同使用率
	usages := []float64{0.1, 0.5, 0.8, 1.0}
	for _, usage := range usages {
		mebmetrics.GetMetrics().SetBufferUsage(usage)
	}

	// 验证指标
	mfs, err := prometheus.DefaultGatherer.Gather()
	require.NoError(t, err)

	found := false
	for _, mf := range mfs {
		if mf.GetName() == "mebsuta_buffer_usage" {
			found = true
			// 最后一个值应该是1.0
			value := mf.GetMetric()[0].GetGauge().GetValue()
			assert.Equal(t, 1.0, value)
		}
	}
	assert.True(t, found, "未找到mebsuta_buffer_usage指标")
}

// TestIncBufferFull 测试缓冲区满事件
func TestIncBufferFull(t *testing.T) {
	_ = mebmetrics.Register()

	// 记录缓冲区满事件
	mebmetrics.GetMetrics().IncBufferFull()
	mebmetrics.GetMetrics().IncBufferFull()

	// 验证指标
	mfs, err := prometheus.DefaultGatherer.Gather()
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
	_ = mebmetrics.Register()

	// 设置不同连接数
	conns := []float64{5, 10, 20}
	for _, conn := range conns {
		mebmetrics.GetMetrics().SetActiveConns(conn)
	}

	// 验证指标
	mfs, err := prometheus.DefaultGatherer.Gather()
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
	_ = mebmetrics.Register()

	// 设置不同连接数
	conns := []float64{2, 5, 10}
	for _, conn := range conns {
		mebmetrics.GetMetrics().SetIdleConns(conn)
	}

	// 验证指标
	mfs, err := prometheus.DefaultGatherer.Gather()
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
	_ = mebmetrics.Register()

	// 增加goroutine
	mebmetrics.GetMetrics().IncGoroutine()
	mebmetrics.GetMetrics().IncGoroutine()
	mebmetrics.GetMetrics().IncGoroutine()

	// 减少goroutine
	mebmetrics.GetMetrics().DecGoroutine()
	mebmetrics.GetMetrics().DecGoroutine()

	// Goroutine计数器使用atomic.Int64，不是Prometheus指标
	// 直接使用GetGoroutineCount()验证
	count := mebmetrics.GetMetrics().GetGoroutineCount()
	assert.Equal(t, int64(1), count)
}

// TestMetricsWithEncoderCache 测试编码器缓存metrics
func TestMetricsWithEncoderCache(t *testing.T) {
	_ = mebmetrics.Register()

	// 模拟编码器缓存淘汰事件
	mebmetrics.GetMetrics().IncLogWrite("encoder_cache_evict", "cache")
	mebmetrics.GetMetrics().IncLogWrite("encoder_cache_evict", "cache")

	// 验证指标
	mfs, err := prometheus.DefaultGatherer.Gather()
	require.NoError(t, err)

	found := false
	for _, mf := range mfs {
		if mf.GetName() == "mebsuta_log_writes_total" {
			for _, m := range mf.GetMetric() {
				for _, label := range m.GetLabel() {
					if label.GetName() == "level" && label.GetValue() == "encoder_cache_evict" {
						found = true
					}
				}
			}
		}
	}
	assert.True(t, found, "未找到encoder器缓存淘汰指标")
}

// TestMetricsWithStructuredCore 测试与StructuredCore集成
func TestMetricsWithStructuredCore(t *testing.T) {
	_ = mebmetrics.Register()

	// 记录日志
	for range 10 {
		mebmetrics.GetMetrics().IncLogWrite("info", "structured_core")
	}

	// 验证指标
	mfs, err := prometheus.DefaultGatherer.Gather()
	require.NoError(t, err)

	// 检查日志写入指标
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
	_ = mebmetrics.Register()

	// 重置计数器（通过操作到0开始）
	for mebmetrics.GetMetrics().GetGoroutineCount() > 0 {
		mebmetrics.GetMetrics().DecGoroutine()
	}

	// 增加goroutine
	mebmetrics.GetMetrics().IncGoroutine()
	mebmetrics.GetMetrics().IncGoroutine()
	mebmetrics.GetMetrics().IncGoroutine()

	// 减少goroutine
	mebmetrics.GetMetrics().DecGoroutine()

	// 获取goroutine计数
	count := mebmetrics.GetMetrics().GetGoroutineCount()
	assert.Equal(t, int64(2), count)
}

// TestEventWriteSyncerMetrics 测试事件写入同步器metrics
func TestEventWriteSyncerMetrics(t *testing.T) {
	_ = mebmetrics.Register()

	// 模拟事件写入
	for range 5 {
		mebmetrics.GetMetrics().IncLogWrite("info", "event_writer")
	}

	// 验证指标
	mfs, err := prometheus.DefaultGatherer.Gather()
	require.NoError(t, err)

	found := false
	for _, mf := range mfs {
		if mf.GetName() == "mebsuta_log_writes_total" {
			for _, m := range mf.GetMetric() {
				for _, label := range m.GetLabel() {
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
	_ = mebmetrics.Register()

	var wg sync.WaitGroup

	// 并发记录metrics
	for i := range 10 {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := range 100 {
				mebmetrics.GetMetrics().IncLogWrite("info", "stdout")
				mebmetrics.GetMetrics().IncBatchWrite()
				mebmetrics.GetMetrics().ObserveBatchSize(float64(j))
			}
		}(i)
	}

	// 等待所有goroutine完成
	wg.Wait()

	// 验证指标
	mfs, err := prometheus.DefaultGatherer.Gather()
	require.NoError(t, err)

	// 验证计数
	for _, mf := range mfs {
		if mf.GetName() == "mebsuta_log_writes_total" {
			for _, m := range mf.GetMetric() {
				labels := make(map[string]string)
				for _, label := range m.GetLabel() {
					labels[label.GetName()] = label.GetValue()
				}
				// 只检查"info"级别和"stdout"输出的计数
				if labels["level"] == "info" && labels["output"] == "stdout" {
					count := m.GetCounter().GetValue()
					assert.GreaterOrEqual(t, count, 1000.0) // 可能包含之前测试的值
				}
			}
		}
		if mf.GetName() == "mebsuta_batch_writes_total" {
			for _, m := range mf.GetMetric() {
				count := m.GetCounter().GetValue()
				assert.GreaterOrEqual(t, count, 1000.0) // 可能包含之前测试的值
			}
		}
		if mf.GetName() == "mebsuta_batch_size" {
			// Histogram有固定数量的buckets，检查sample count
			h := mf.GetMetric()[0].GetHistogram()
			assert.GreaterOrEqual(t, h.GetSampleCount(), uint64(1000))
		}
	}
}

// TestGetMetrics 测试获取Metrics实例
func TestGetMetrics(t *testing.T) {
	_ = mebmetrics.Register()

	// 获取metrics实例
	m := mebmetrics.GetMetrics()
	require.NotNil(t, m)

	// 测试所有方法
	m.IncLogWrite("info", "stdout")
	m.IncBatchWrite()
	m.ObserveBatchSize(50)
	m.SetBufferUsage(0.5)
	m.SetActiveConns(10)
	m.SetIdleConns(5)
	m.IncGoroutine()
	m.DecGoroutine()

	// 测试goroutine计数 - 由于是全局的，可能不为0
	// 只验证方法调用不会panic
	count := m.GetGoroutineCount()
	assert.GreaterOrEqual(t, count, int64(0))
}

// TestMetricLabelCombinations 测试不同的标签组合
func TestMetricLabelCombinations(t *testing.T) {
	_ = mebmetrics.Register()

	levels := []string{"debug", "info", "warn", "error", "fatal"}
	outputs := []string{"stdout", "file", "db", "syslog", "influxdb"}

	// 测试所有组合
	for _, level := range levels {
		for _, output := range outputs {
			mebmetrics.GetMetrics().IncLogWrite(level, output)
		}
	}

	// 验证指标
	mfs, err := prometheus.DefaultGatherer.Gather()
	require.NoError(t, err)

	found := false
	for _, mf := range mfs {
		if mf.GetName() == "mebsuta_log_writes_total" {
			found = true
			// 应该有5*5=25个不同的指标（每种组合一个）
			// 但可能包含之前测试的数据，所以用>=
			assert.GreaterOrEqual(t, len(mf.GetMetric()), 25)
		}
	}
	assert.True(t, found)
}
