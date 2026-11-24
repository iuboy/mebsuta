// Package metrics 为 mebsuta 提供 Prometheus 形态的 HandlerMetrics 实现。
//
// 0.1.0-27 起收敛为 mebsuta.HandlerMetrics 接口的唯一实现：包内其余
// 13 个 mutator（批量写入、缓冲区、连接池、goroutine 等）在仓库与
// 示例中零调用，属于从未接线的死指标面——导出无人调用的计数器只会
// 让 Prometheus 里常年是一排 0。需要更宽观测面的项目用 client_golang
// 自建 collector。
package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Metrics 实现 mebsuta.HandlerMetrics：写延迟、错误与丢弃三个指标，
// 交由 MetricsHandler 观测。
type Metrics struct {
	writeLatency prometheus.Histogram
	logErrors    *prometheus.CounterVec
	logDropped   *prometheus.CounterVec
}

var (
	_ prometheus.Collector  = (*Metrics)(nil)
	_ mebsutaHandlerMetrics = (*Metrics)(nil)
)

// mebsutaHandlerMetrics 编译期锚定 HandlerMetrics 接口（避免对根包的
// 接口断言漂移——根包接口的三方法与本结构一一对应）。
type mebsutaHandlerMetrics interface {
	ObserveHandle(duration time.Duration)
	IncError(output string)
	IncDroppedN(output string, n int64)
}

// NewMetrics 创建新的 Metrics 采集器。需显式注册到 Prometheus：
//
//	m := metrics.NewMetrics()
//	prometheus.MustRegister(m)
//	h, _ := mebsuta.New(mebsuta.UseMetrics(m, "stdout"), ...)
func NewMetrics() *Metrics {
	return &Metrics{
		writeLatency: prometheus.NewHistogram(
			prometheus.HistogramOpts{
				Name:    "mebsuta_write_latency_seconds",
				Help:    "Write latency distribution",
				Buckets: prometheus.ExponentialBuckets(0.0001, 2, 10), // 0.1ms, 0.2ms, ... 51.2ms
			},
		),
		logErrors: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "mebsuta_log_errors_total",
				Help: "Total number of log errors",
			},
			[]string{"error_type", "output"},
		),
		logDropped: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "mebsuta_log_dropped_total",
				Help: "Total number of dropped log records",
			},
			[]string{"reason", "output"},
		),
	}
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
		m.writeLatency,
		m.logErrors,
		m.logDropped,
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
