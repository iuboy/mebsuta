// Package metrics provides Prometheus-based metrics collection for the mebsuta logging system.
package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Metrics collects all observability metrics for the mebsuta logging system.
type Metrics struct {
	// Log write counters (by level)
	logWrites  *prometheus.CounterVec
	logDropped *prometheus.CounterVec
	logErrors  *prometheus.CounterVec

	// Batch write metrics
	batchWrites   prometheus.Counter
	batchSize     prometheus.Histogram
	batchLatency  prometheus.Histogram
	batchFailures prometheus.Counter

	// Buffer metrics
	bufferUsage prometheus.Gauge
	bufferFull  prometheus.Counter

	// Connection pool metrics
	activeConns prometheus.Gauge
	idleConns   prometheus.Gauge

	// Write latency metrics
	writeLatency prometheus.Histogram

	// Goroutine status
	activeGoroutines prometheus.Gauge
}

var _ prometheus.Collector = (*Metrics)(nil)

// NewMetrics creates a new Metrics collector. Register with Prometheus explicitly:
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
	m.activeGoroutines.Inc()
}

// DecGoroutine decrements the active goroutine counter.
func (m *Metrics) DecGoroutine() {
	m.activeGoroutines.Dec()
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

// Describe implements prometheus.Collector.
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
	m.activeGoroutines.Describe(ch)
}

// Collect implements prometheus.Collector.
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
	m.activeGoroutines.Collect(ch)
}
