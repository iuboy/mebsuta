// Package metrics 为 mebsuta 日志系统提供基于 Prometheus 的指标采集。
package metrics

import (
	"math"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Metrics 汇集 mebsuta 日志系统的全部可观测性指标。
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

	// 写延迟指标
	writeLatency prometheus.Histogram

	// goroutine 状态
	activeGoroutines prometheus.Gauge
}

var _ prometheus.Collector = (*Metrics)(nil)

// NewMetrics 创建新的 Metrics 采集器。需显式注册到 Prometheus：
//
//	m := metrics.NewMetrics()
//	prometheus.MustRegister(m)
func NewMetrics() *Metrics {
	return &Metrics{
		logWrites: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "mebsuta_log_writes_total",
				Help: "Total number of log writes",
			},
			[]string{"level", "output"},
		),

		logDropped: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "mebsuta_log_dropped_total",
				Help: "Total number of dropped log records",
			},
			[]string{"reason", "output"},
		),

		logErrors: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "mebsuta_log_errors_total",
				Help: "Total number of log errors",
			},
			[]string{"error_type", "output"},
		),

		batchWrites: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "mebsuta_batch_writes_total",
				Help: "Total number of batch writes",
			},
		),

		batchSize: prometheus.NewHistogram(
			prometheus.HistogramOpts{
				Name:    "mebsuta_batch_size",
				Help:    "Batch write size distribution",
				Buckets: prometheus.ExponentialBuckets(1, 2, 10), // 1, 2, 4, 8, 16, 32, 64, 128, 256, 512
			},
		),

		batchLatency: prometheus.NewHistogram(
			prometheus.HistogramOpts{
				Name:    "mebsuta_batch_latency_seconds",
				Help:    "Batch write latency distribution",
				Buckets: prometheus.ExponentialBuckets(0.001, 2, 10), // 1ms, 2ms, 4ms, ... 512ms
			},
		),

		batchFailures: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "mebsuta_batch_failures_total",
				Help: "Total number of batch write failures",
			},
		),

		bufferUsage: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "mebsuta_buffer_usage",
				Help: "Buffer usage ratio (used/total capacity)",
			},
		),

		bufferFull: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "mebsuta_buffer_full_total",
				Help: "Total number of buffer-full events",
			},
		),

		activeConns: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "mebsuta_active_connections",
				Help: "Number of active connections",
			},
		),

		idleConns: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "mebsuta_idle_connections",
				Help: "Number of idle connections",
			},
		),

		writeLatency: prometheus.NewHistogram(
			prometheus.HistogramOpts{
				Name:    "mebsuta_write_latency_seconds",
				Help:    "Write latency distribution",
				Buckets: prometheus.ExponentialBuckets(0.0001, 2, 10), // 0.1ms, 0.2ms, ... 51.2ms
			},
		),

		activeGoroutines: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "mebsuta_active_goroutines",
				Help: "Number of active goroutines",
			},
		),
	}
}

// IncLogWrite 递增指定级别与输出目标的日志写入计数器。
func (m *Metrics) IncLogWrite(level, output string) {
	m.logWrites.WithLabelValues(level, output).Inc()
}

// IncLogDropped 递增指定原因与输出目标的日志丢弃计数器。
func (m *Metrics) IncLogDropped(reason, output string) {
	m.logDropped.WithLabelValues(reason, output).Inc()
}

// IncLogError 递增指定错误类型与输出目标的日志错误计数器。
func (m *Metrics) IncLogError(errorType, output string) {
	m.logErrors.WithLabelValues(errorType, output).Inc()
}

// IncBatchWrite 递增批量写入计数器。
func (m *Metrics) IncBatchWrite() {
	m.batchWrites.Inc()
}

// ObserveBatchSize 记录批量写入大小的分布样本。
func (m *Metrics) ObserveBatchSize(size float64) {
	m.batchSize.Observe(size)
}

// ObserveBatchLatency 记录批量写入延迟（单位：秒）样本。
func (m *Metrics) ObserveBatchLatency(seconds float64) {
	m.batchLatency.Observe(seconds)
}

// IncBatchFailure 递增批量写入失败计数器。
func (m *Metrics) IncBatchFailure() {
	m.batchFailures.Inc()
}

// SetBufferUsage 设置缓冲区使用率 gauge。比率会被钳制到 [0, 1]。
// NaN 与 Inf 值按 0 处理，以免污染指标。
func (m *Metrics) SetBufferUsage(ratio float64) {
	if math.IsNaN(ratio) || math.IsInf(ratio, 0) {
		ratio = 0
	}
	m.bufferUsage.Set(math.Max(0, math.Min(1, ratio)))
}

// IncBufferFull 递增缓冲区打满事件计数器。
func (m *Metrics) IncBufferFull() {
	m.bufferFull.Inc()
}

// SetActiveConns 设置活跃连接数 gauge。
func (m *Metrics) SetActiveConns(count float64) {
	m.activeConns.Set(count)
}

// SetIdleConns 设置空闲连接数 gauge。
func (m *Metrics) SetIdleConns(count float64) {
	m.idleConns.Set(count)
}

// IncGoroutine 递增活跃 goroutine 计数器。
func (m *Metrics) IncGoroutine() {
	m.activeGoroutines.Inc()
}

// DecGoroutine 递减活跃 goroutine 计数器。
func (m *Metrics) DecGoroutine() {
	m.activeGoroutines.Dec()
}

// ObserveHandle 记录 handle 调用延迟，实现 mebsuta.HandlerMetrics 接口。
func (m *Metrics) ObserveHandle(duration time.Duration) {
	m.writeLatency.Observe(duration.Seconds())
}

// IncError 递增指定输出目标（handler 名称）的错误计数器，
// 实现 mebsuta.HandlerMetrics 接口。
func (m *Metrics) IncError(output string) {
	m.logErrors.WithLabelValues("handle", output).Inc()
}

// IncDroppedN 将 n 条被丢弃的记录累加到指定输出目标（handler 名称）的
// 丢弃计数器，实现 mebsuta.HandlerMetrics 接口。
func (m *Metrics) IncDroppedN(output string, n int64) {
	m.logDropped.WithLabelValues("overflow", output).Add(float64(n))
}

// collectors 以单一切片返回全部已注册的指标采集器，
// 保证新增指标时 Describe 与 Collect 保持同步。
func (m *Metrics) collectors() []prometheus.Collector {
	return []prometheus.Collector{
		m.logWrites,
		m.logDropped,
		m.logErrors,
		m.batchWrites,
		m.batchSize,
		m.batchLatency,
		m.batchFailures,
		m.bufferUsage,
		m.bufferFull,
		m.activeConns,
		m.idleConns,
		m.writeLatency,
		m.activeGoroutines,
	}
}

// Describe 实现 prometheus.Collector。
func (m *Metrics) Describe(ch chan<- *prometheus.Desc) {
	for _, c := range m.collectors() {
		c.Describe(ch)
	}
}

// Collect 实现 prometheus.Collector。
func (m *Metrics) Collect(ch chan<- prometheus.Metric) {
	for _, c := range m.collectors() {
		c.Collect(ch)
	}
}
