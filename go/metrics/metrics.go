// Package metrics provides Prometheus-based metrics collection for the mebsuta logging system.
package metrics

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Metrics collects all observability metrics for the mebsuta logging system.
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
	activeGoroutines prometheus.Gauge
	goroutineCount   atomic.Int64
}

var (
	// 全局metrics实例
	globalMetrics *Metrics
	once          sync.Once
	registryOnce  sync.Once // 防止重复注册
	registerErr   error     // 保存首次注册错误
)

// NewMetrics creates a new Metrics collector without registering it with Prometheus.
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

		activeGoroutines: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "mebsuta_active_goroutines",
				Help: "活跃 goroutine 数量",
			},
		),
	}
}

// GetMetrics returns the singleton Metrics instance, creating it on first call.
func GetMetrics() *Metrics {
	once.Do(func() {
		globalMetrics = NewMetrics()
	})
	return globalMetrics
}

// IncLogWrite increments the log write counter for the given level and output.
func (m *Metrics) IncLogWrite(level, output string) {
	m.logWrites.WithLabelValues(level, output).Inc()
}

// IncLogDropped increments the log dropped counter for the given reason and output.
func (m *Metrics) IncLogDropped(reason, output string) {
	m.logDropped.WithLabelValues(reason, output).Inc()
}

// IncLogError increments the log error counter for the given error type and output.
func (m *Metrics) IncLogError(errorType, output string) {
	m.logErrors.WithLabelValues(errorType, output).Inc()
}

// IncBatchWrite increments the batch write counter.
func (m *Metrics) IncBatchWrite() {
	m.batchWrites.Inc()
}

// ObserveBatchSize observes the batch write size distribution.
func (m *Metrics) ObserveBatchSize(size float64) {
	m.batchSize.Observe(size)
}

// ObserveBatchLatency observes the batch write latency in seconds.
func (m *Metrics) ObserveBatchLatency(seconds float64) {
	m.batchLatency.Observe(seconds)
}

// IncBatchFailure increments the batch write failure counter.
func (m *Metrics) IncBatchFailure() {
	m.batchFailures.Inc()
}

// SetBufferUsage sets the buffer usage gauge (0 to 1).
func (m *Metrics) SetBufferUsage(ratio float64) {
	m.bufferUsage.Set(ratio)
}

// IncBufferFull increments the buffer-full event counter.
func (m *Metrics) IncBufferFull() {
	m.bufferFull.Inc()
}

// SetActiveConns sets the active connection count gauge.
func (m *Metrics) SetActiveConns(count float64) {
	m.activeConns.Set(count)
}

// SetIdleConns sets the idle connection count gauge.
func (m *Metrics) SetIdleConns(count float64) {
	m.idleConns.Set(count)
}

// ObserveWriteLatency observes a write latency in seconds.
func (m *Metrics) ObserveWriteLatency(seconds float64) {
	m.writeLatency.Observe(seconds)
}

// IncGoroutine increments the active goroutine counter.
func (m *Metrics) IncGoroutine() {
	m.goroutineCount.Add(1)
	m.activeGoroutines.Inc()
}

// DecGoroutine decrements the active goroutine counter.
func (m *Metrics) DecGoroutine() {
	m.goroutineCount.Add(-1)
	m.activeGoroutines.Dec()
}

// GetGoroutineCount returns the current active goroutine count.
func (m *Metrics) GetGoroutineCount() int64 {
	return m.goroutineCount.Load()
}

// ObserveHandle records handle call latency, implementing the mebsuta.HandlerMetrics interface.
func (m *Metrics) ObserveHandle(duration time.Duration) {
	m.writeLatency.Observe(duration.Seconds())
}

// IncError increments the error counter for the named handler, implementing the mebsuta.HandlerMetrics interface.
func (m *Metrics) IncError(handlerName string) {
	m.logErrors.WithLabelValues("handle", handlerName).Inc()
}

// IncDropped increments the dropped counter for the named handler, implementing the mebsuta.HandlerMetrics interface.
func (m *Metrics) IncDropped(handlerName string) {
	m.logDropped.WithLabelValues("overflow", handlerName).Inc()
}

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

// RegisterToRegistry registers all metrics with a custom Prometheus registerer.
func RegisterToRegistry(registry prometheus.Registerer) error {
	return registry.Register(GetMetrics())
}

// GetMetricsAsCollector returns the global Metrics as a prometheus.Collector for custom registration.
func GetMetricsAsCollector() prometheus.Collector {
	return GetMetrics()
}

// Register registers all metrics with the default Prometheus registry. It is idempotent; repeated calls return the first error.
func Register() error {
	registryOnce.Do(func() {
		registerErr = RegisterToRegistry(prometheus.DefaultRegisterer)
	})
	return registerErr
}
