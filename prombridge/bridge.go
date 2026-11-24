// Package prombridge 把 prometheus client_golang 指标导出到 OTel metric
// 管线（通常是对接 OTLP 端点的 mebsuta/telemetry 引导）。它存在的意义是
// 让组织内仅用 prometheus 的服务（mbta-go、wasat-dns、……）零改动插桩
// 即可接上 OTLP 通路。
//
// 保真度限制（有意为之）：counter 与 gauge 精确映射——counter 按
// 单调累计值的每次轮询增量（delta），gauge 按最后写入胜出记录。
// histogram 与 summary 被跳过：OTel metric API 无法通过 Add/Record
// 忠实表达预聚合的桶计数，而合成回放的近似会破坏分布。histogram/
// summary 需要原生 OTel 插桩；本桥是 counter/gauge 存量资产的迁移路径。
//
// 用法：
//
//	tel, _ := telemetry.Start(ctx, telemetry.Config{...})
//	bridge, err := prombridge.Start(ctx, tel.MeterProvider(), promReg)
//	if err != nil { ... }
//	defer bridge.Close()
package prombridge

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/iuboy/mebsuta"
	dto "github.com/prometheus/client_model/go"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/iuboy/mebsuta/internal/handlerkit"
)

// DefaultPollInterval 是未设置 WithInterval 时的采集节奏。
const DefaultPollInterval = 30 * time.Second

// Bridge 轮询 prometheus Gatherer，并通过 OTel meter 重新发出其 counter/
// gauge。并发安全：Close 与 pollOnce 可并发调用；Close 停止轮询。
type Bridge struct {
	mp        metric.MeterProvider
	gatherer  promGatherer
	interval  time.Duration
	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	closed    atomic.Bool
	errorHPtr atomic.Pointer[mebsuta.ErrorHandler]
	// reportGate 限频错误上报:每秒至多一次(F6)。
	reportGate handlerkit.RateGate

	mu       sync.Mutex
	last     map[string]float64 // counter 指纹 → 上次累计值
	counters map[string]metric.Float64Counter
	gauges   map[string]metric.Float64Gauge
	skipped  map[string]int // family 名 → 被跳过的数据点数（histogram/summary）
}

// promGatherer 是 bridge 所需的 prometheus.Registry 的窄接口
// （Registry 实现了它；任何 Gatherer 也实现）。
type promGatherer interface {
	Gather() ([]*dto.MetricFamily, error)
}

// Option 配置一个 Bridge。
type Option func(*Bridge)

// WithInterval 设置采集节奏（默认 DefaultPollInterval）。
func WithInterval(d time.Duration) Option {
	return func(b *Bridge) {
		if d > 0 {
			b.interval = d
		}
	}
}

// WithErrorHandler 路由 bridge 内部失败（Gather 错误、仪器创建错误）。
// nil → mebsuta.DefaultErrorHandler()。
func WithErrorHandler(fn mebsuta.ErrorHandler) Option {
	return func(b *Bridge) {
		if fn != nil {
			b.errorHPtr.Store(&fn)
		}
	}
}

// Start 开始通过 mp 的 meter 轮询 g。返回的 Bridge 在 Close 之前持有一个
// goroutine。
func Start(ctx context.Context, mp metric.MeterProvider, g promGatherer, opts ...Option) (*Bridge, error) {
	if mp == nil {
		return nil, fmt.Errorf("prombridge: nil MeterProvider")
	}
	if g == nil {
		return nil, fmt.Errorf("prombridge: nil Gatherer")
	}
	b := &Bridge{
		mp:       mp,
		gatherer: g,
		interval: DefaultPollInterval,
		counters: make(map[string]metric.Float64Counter),
		gauges:   make(map[string]metric.Float64Gauge),
		last:     make(map[string]float64),
		skipped:  make(map[string]int),
	}
	eh := mebsuta.DefaultErrorHandler()
	b.errorHPtr.Store(&eh)
	for _, opt := range opts {
		opt(b)
	}
	b.ctx, b.cancel = context.WithCancel(ctx)

	b.wg.Add(1)
	go b.run()
	return b, nil
}

// Close 停止轮询并释放 goroutine。幂等。
func (b *Bridge) Close() {
	if b == nil || !b.closed.CompareAndSwap(false, true) {
		return
	}
	b.cancel()
	b.wg.Wait()
}

func (b *Bridge) run() {
	defer b.wg.Done()
	ticker := time.NewTicker(b.interval)
	defer ticker.Stop()
	for {
		select {
		case <-b.ctx.Done():
			return
		case <-ticker.C:
			b.pollOnce(b.ctx)
		}
	}
}

// pollOnce 采集一次快照并重新发出。暴露给包内测试以做确定性验证。
func (b *Bridge) pollOnce(ctx context.Context) {
	families, err := b.gatherer.Gather()
	if err != nil {
		b.report(fmt.Errorf("prombridge: gather: %w", err))
		return
	}
	for _, mf := range families {
		switch mf.GetType() {
		case dto.MetricType_COUNTER:
			for _, m := range mf.GetMetric() {
				v := m.GetCounter().GetValue()
				fp := fingerprint(mf.GetName(), m)
				b.mu.Lock()
				delta := v - b.last[fp]
				if v < b.last[fp] {
					// counter 重置（进程重启、重注册）：从头累计而非
					// 导出负增量。
					delta = v
				}
				b.last[fp] = v
				ctr, ok := b.counters[mf.GetName()]
				b.mu.Unlock()
				if !ok {
					var err error
					ctr, err = b.meter().Float64Counter(mf.GetName())
					if err != nil {
						b.report(fmt.Errorf("prombridge: counter %s: %w", mf.GetName(), err))
						continue
					}
					b.mu.Lock()
					b.counters[mf.GetName()] = ctr
					b.mu.Unlock()
				}
				ctr.Add(ctx, delta, metric.WithAttributes(labelAttrs(m.GetLabel())...))
			}
		case dto.MetricType_GAUGE, dto.MetricType_UNTYPED:
			for _, m := range mf.GetMetric() {
				// UNTYPED 走 GetUntyped：GetGauge 对 untyped 恒读 0。
				v := m.GetGauge().GetValue()
				if mf.GetType() == dto.MetricType_UNTYPED {
					v = m.GetUntyped().GetValue()
				}
				b.mu.Lock()
				g, ok := b.gauges[mf.GetName()]
				b.mu.Unlock()
				if !ok {
					var err error
					g, err = b.meter().Float64Gauge(mf.GetName())
					if err != nil {
						b.report(fmt.Errorf("prombridge: gauge %s: %w", mf.GetName(), err))
						continue
					}
					b.mu.Lock()
					b.gauges[mf.GetName()] = g
					b.mu.Unlock()
				}
				g.Record(ctx, v, metric.WithAttributes(labelAttrs(m.GetLabel())...))
			}
		case dto.MetricType_HISTOGRAM, dto.MetricType_GAUGE_HISTOGRAM, dto.MetricType_SUMMARY:
			// 有意跳过——见包文档。
			b.mu.Lock()
			b.skipped[mf.GetName()] += len(mf.GetMetric())
			b.mu.Unlock()
		}
	}
}

// meter 把 bridge 的仪器归入同一个 instrumentation 名称之下。
func (b *Bridge) meter() metric.Meter {
	return b.mp.Meter("github.com/iuboy/mebsuta/prombridge")
}

// labelAttrs 把 prometheus 标签对转换为 OTel 属性。
func labelAttrs(labels []*dto.LabelPair) []attribute.KeyValue {
	if len(labels) == 0 {
		return nil
	}
	attrs := make([]attribute.KeyValue, 0, len(labels))
	for _, lp := range labels {
		attrs = append(attrs, attribute.String(lp.GetName(), lp.GetValue()))
	}
	return attrs
}

// fingerprint 标识一个 family 中带标签的单条序列。
func fingerprint(name string, m *dto.Metric) string {
	if len(m.GetLabel()) == 0 {
		return name
	}
	parts := make([]string, 0, len(m.GetLabel()))
	for _, lp := range m.GetLabel() {
		parts = append(parts, lp.GetName()+"="+lp.GetValue())
	}
	sort.Strings(parts)
	return name + "{" + strings.Join(parts, ",") + "}"
}

// Skipped 按 family 名报告有多少 histogram/summary 数据点未被桥接——
// 这是面向接入方的诚实健康面。
func (b *Bridge) Skipped() map[string]int {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make(map[string]int, len(b.skipped))
	for k, v := range b.skipped {
		out[k] = v
	}
	return out
}

func (b *Bridge) report(err error) {
	fn := b.errorHPtr.Load()
	if fn == nil {
		return
	}
	// 限频 + panic 恢复(F6):轮询 goroutine 里的用户回调若 panic 会
	// 杀死进程(MetricsHandler.metricsSafe 同款遏制);失败风暴不得
	// 1:1 放大为回调调用。
	if !b.reportGate.Allow() {
		return
	}
	func() {
		defer func() {
			if p := recover(); p != nil {
				fmt.Fprintf(os.Stderr, "prombridge: error handler panic recovered: %v\n", p)
			}
		}()
		(*fn)(&mebsuta.HandlerError{Component: "prombridge", Operation: "poll", Err: err})
	}()
}
