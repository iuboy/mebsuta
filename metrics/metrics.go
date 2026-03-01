// Package metrics 提供日志系统的指标监控功能
package metrics

import (
	"sync"
	"sync/atomic"

	"github.com/prometheus/client_golang/prometheus"
)

// Metrics 收集日志系统的所有指标
type Metrics struct {
	// 日志写入计数器（按级别）
	logWrites  *prometheus.CounterVec
	logDropped *prometheus.CounterVec
	logErrors  *prometheus.CounterVec

	// 批量写入指标
	batchWrites   prometheus.Counter
	batchSize     prometheus.Histogram
	batchLatency  prometheus.Histogram
	batchFailures prometheus.Counter

	// 缓冲区指标
	bufferUsage prometheus.Gauge
	bufferFull  prometheus.Counter

	// 连接池指标
	activeConns prometheus.Gauge
	idleConns   prometheus.Gauge

	// 写入延迟指标
	writeLatency prometheus.Histogram

	// Goroutine状态
	activeGoroutines atomic.Int64
}

var (
	// 全局metrics实例
	globalMetrics *Metrics
	once          sync.Once
	registryOnce  sync.Once // 防止重复注册
)

// NewMetrics 创建新的metrics收集器（不自动注册）
func NewMetrics() *Metrics {
	return &Metrics{
		logWrites: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "mebsuta_log_writes_total",
				Help: "日志写入总数",
			},
			[]string{"level", "output"},
		),

		logDropped: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "mebsuta_log_dropped_total",
				Help: "日志丢弃总数",
			},
			[]string{"reason", "output"},
		),

		logErrors: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "mebsuta_log_errors_total",
				Help: "日志错误总数",
			},
			[]string{"error_type", "output"},
		),

		batchWrites: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "mebsuta_batch_writes_total",
				Help: "批量写入总数",
			},
		),

		batchSize: prometheus.NewHistogram(
			prometheus.HistogramOpts{
				Name:    "mebsuta_batch_size",
				Help:    "批量写入大小分布",
				Buckets: prometheus.ExponentialBuckets(1, 2, 10), // 1, 2, 4, 8, 16, 32, 64, 128, 256, 512
			},
		),

		batchLatency: prometheus.NewHistogram(
			prometheus.HistogramOpts{
				Name:    "mebsuta_batch_latency_seconds",
				Help:    "批量写入延迟分布",
				Buckets: prometheus.ExponentialBuckets(0.001, 2, 10), // 1ms, 2ms, 4ms, ... 512ms
			},
		),

		batchFailures: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "mebsuta_batch_failures_total",
				Help: "批量写入失败总数",
			},
		),

		bufferUsage: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "mebsuta_buffer_usage",
				Help: "缓冲区使用情况（已用/总容量）",
			},
		),

		bufferFull: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "mebsuta_buffer_full_total",
				Help: "缓冲区满事件总数",
			},
		),

		activeConns: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "mebsuta_active_connections",
				Help: "活跃连接数",
			},
		),

		idleConns: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "mebsuta_idle_connections",
				Help: "空闲连接数",
			},
		),

		writeLatency: prometheus.NewHistogram(
			prometheus.HistogramOpts{
				Name:    "mebsuta_write_latency_seconds",
				Help:    "写入延迟分布",
				Buckets: prometheus.ExponentialBuckets(0.0001, 2, 10), // 0.1ms, 0.2ms, ... 51.2ms
			},
		),
	}
}

// GetMetrics 获取全局metrics实例
func GetMetrics() *Metrics {
	once.Do(func() {
		globalMetrics = NewMetrics()
	})
	return globalMetrics
}

// IncLogWrite 增加日志写入计数
func (m *Metrics) IncLogWrite(level, output string) {
	m.logWrites.WithLabelValues(level, output).Inc()
}

// IncLogDropped 增加日志丢弃计数
func (m *Metrics) IncLogDropped(reason, output string) {
	m.logDropped.WithLabelValues(reason, output).Inc()
}

// IncLogError 增加日志错误计数
func (m *Metrics) IncLogError(errorType, output string) {
	m.logErrors.WithLabelValues(errorType, output).Inc()
}

// IncBatchWrite 增加批量写入计数
func (m *Metrics) IncBatchWrite() {
	m.batchWrites.Inc()
}

// ObserveBatchSize 观察批量写入大小
func (m *Metrics) ObserveBatchSize(size float64) {
	m.batchSize.Observe(size)
}

// ObserveBatchLatency 观察批量写入延迟（秒）
func (m *Metrics) ObserveBatchLatency(seconds float64) {
	m.batchLatency.Observe(seconds)
}

// IncBatchFailure 增加批量写入失败计数
func (m *Metrics) IncBatchFailure() {
	m.batchFailures.Inc()
}

// SetBufferUsage 设置缓冲区使用率（0-1）
func (m *Metrics) SetBufferUsage(ratio float64) {
	m.bufferUsage.Set(ratio)
}

// IncBufferFull 增加缓冲区满事件计数
func (m *Metrics) IncBufferFull() {
	m.bufferFull.Inc()
}

// SetActiveConns 设置活跃连接数
func (m *Metrics) SetActiveConns(count float64) {
	m.activeConns.Set(count)
}

// SetIdleConns 设置空闲连接数
func (m *Metrics) SetIdleConns(count float64) {
	m.idleConns.Set(count)
}

// ObserveWriteLatency 观察写入延迟（秒）
func (m *Metrics) ObserveWriteLatency(seconds float64) {
	m.writeLatency.Observe(seconds)
}

// IncGoroutine 增加活跃goroutine计数
func (m *Metrics) IncGoroutine() {
	m.activeGoroutines.Add(1)
}

// DecGoroutine 减少活跃goroutine计数
func (m *Metrics) DecGoroutine() {
	m.activeGoroutines.Add(-1)
}

// GetGoroutineCount 获取活跃goroutine计数
func (m *Metrics) GetGoroutineCount() int64 {
	return m.activeGoroutines.Load()
}

// Describe 实现 prometheus.Collector 接口
func (m *Metrics) Describe(ch chan<- *prometheus.Desc) {
	m.logWrites.Describe(ch)
	m.logDropped.Describe(ch)
	m.logErrors.Describe(ch)
	m.batchWrites.Describe(ch)
	m.batchSize.Describe(ch)
	m.batchLatency.Describe(ch)
	m.batchFailures.Describe(ch)
	m.bufferUsage.Describe(ch)
	m.bufferFull.Describe(ch)
	m.activeConns.Describe(ch)
	m.idleConns.Describe(ch)
	m.writeLatency.Describe(ch)
}

// Collect 实现 prometheus.Collector 接口
func (m *Metrics) Collect(ch chan<- prometheus.Metric) {
	m.logWrites.Collect(ch)
	m.logDropped.Collect(ch)
	m.logErrors.Collect(ch)
	m.batchWrites.Collect(ch)
	m.batchSize.Collect(ch)
	m.batchLatency.Collect(ch)
	m.batchFailures.Collect(ch)
	m.bufferUsage.Collect(ch)
	m.bufferFull.Collect(ch)
	m.activeConns.Collect(ch)
	m.idleConns.Collect(ch)
	m.writeLatency.Collect(ch)
}

// Register 注册所有指标到自定义的 Prometheus 注册表
// 用法示例：
//
//	registry := prometheus.NewRegistry()
//	registry.MustRegister(mebsuta.GetMetricsAsCollector())
//	http.Handle("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))
func RegisterToRegistry(registry prometheus.Registerer) error {
	registry.MustRegister(GetMetrics())
	return nil
}

// GetMetricsAsCollector 获取指标作为 prometheus.Collector
// 用于注册到自定义的 Prometheus 注册表
//
// 用法示例：
//
//	import (
//	    "github.com/prometheus/client_golang/prometheus"
//	    "github.com/prometheus/client_golang/prometheus/promhttp"
//	    "github.com/iuboy/mebsuta"
//	)
//
//	func main() {
//	    // 初始化日志
//	    mebsuta.Init(cfg)
//
//	    // 创建自定义注册表
//	    registry := prometheus.NewRegistry()
//	    registry.MustRegister(mebsuta.GetMetricsAsCollector())
//
//	    // 暴露指标端点
//	    http.Handle("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))
//	    http.ListenAndServe(":2112", nil)
//	}
func GetMetricsAsCollector() prometheus.Collector {
	return GetMetrics()
}

// Register 注册到默认的 Prometheus 注册表（幂等，可安全多次调用）
func Register() error {
	var err error
	registryOnce.Do(func() {
		err = RegisterToRegistry(prometheus.DefaultRegisterer)
	})
	return err
}
