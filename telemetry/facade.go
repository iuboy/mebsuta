package telemetry

// 遥测门面的实例方法形态（0.1.0-29，C1）：span 与 metric 的创建绑定
// 本 Telemetry 实例，取代根包经 otel 全局转发的 StartSpan/Counter/
// Histogram/Gauge。instrument 缓存归实例所有——instrument 与实例的
// provider 同生命周期（Shutdown 后实例作废，新 Start 是新实例、新
// 缓存），根包全局缓存的教训（0.1.0-22：instrument 绑死创建时的
// provider，代次轮换后旧名字写进已关停的旧 provider）在实例形态下
// 结构性消失。

import (
	"context"
	"sync"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
	nooptrace "go.opentelemetry.io/otel/trace/noop"
)

// facadeScope 是门面创建的 span 与 metric 的 instrumentation scope
// 名称。保持单一 scope 可让下游把框架插桩信号与应用自身的信号区分开。
const facadeScope = "github.com/iuboy/mebsuta"

// noopTracer 是未启动（no-op 模式）实例的门面回退——安全且零开销。
var noopTracer = nooptrace.NewTracerProvider().Tracer(facadeScope)

// StartSpan 经本实例的 TracerProvider 启动一个 span。未启动（no-op
// 模式）或 nil receiver 时返回 no-op span——调用方无需判空。
//
//	ctx, span := tel.StartSpan(ctx, "handle_request")
//	defer span.End()
func (t *Telemetry) StartSpan(ctx context.Context, name string, attrs ...attribute.KeyValue) (context.Context, trace.Span) {
	if t == nil || t.tp == nil {
		return noopTracer.Start(ctx, name)
	}
	return t.tp.Tracer(facadeScope).Start(ctx, name, trace.WithAttributes(attrs...))
}

// Counter 经本实例的 MeterProvider 向一个 int64 计数器累加 delta。
// instrument 按名字在实例内缓存（实例 Shutdown 后随实例作废）。错误
// 被有意吞掉：遥测绝不能破坏请求路径；名字必须是静态常量，绝不能
// 来自请求数据，否则缓存会成为攻击者可控的基数面。
func (t *Telemetry) Counter(ctx context.Context, name string, delta int64, attrs ...attribute.KeyValue) {
	if t == nil || t.mp == nil {
		return
	}
	if c, ok := t.instrument(&t.counterCache, name, func(m metric.Meter) (any, error) {
		return m.Int64Counter(name)
	}).(metric.Int64Counter); ok {
		c.Add(ctx, delta, metric.WithAttributes(attrs...))
	}
}

// Histogram 经本实例的 MeterProvider 把 value 记入一个 float64 直方图。
// 缓存与错误语义见 Counter。
func (t *Telemetry) Histogram(ctx context.Context, name string, value float64, attrs ...attribute.KeyValue) {
	if t == nil || t.mp == nil {
		return
	}
	if h, ok := t.instrument(&t.histogramCache, name, func(m metric.Meter) (any, error) {
		return m.Float64Histogram(name)
	}).(metric.Float64Histogram); ok {
		h.Record(ctx, value, metric.WithAttributes(attrs...))
	}
}

// Gauge 经本实例的 MeterProvider 把 value 记入一个 int64 量规（每个
// 属性集后写胜出）。缓存与错误语义见 Counter。
func (t *Telemetry) Gauge(ctx context.Context, name string, value int64, attrs ...attribute.KeyValue) {
	if t == nil || t.mp == nil {
		return
	}
	if g, ok := t.instrument(&t.gaugeCache, name, func(m metric.Meter) (any, error) {
		return m.Int64Gauge(name)
	}).(metric.Int64Gauge); ok {
		g.Record(ctx, value, metric.WithAttributes(attrs...))
	}
}

// instrument 返回 name 对应的实例内缓存 instrument，首次使用时经
// 本实例的 meter 创建。并发创建者的竞争是良性的——两个 instrument
// 都有效，CompareAndSwap 只保留一个。
func (t *Telemetry) instrument(cache *sync.Map, name string, create func(metric.Meter) (any, error)) any {
	if t == nil || t.mp == nil {
		return nil
	}
	if v, ok := cache.Load(name); ok {
		return v
	}
	created, err := create(t.mp.Meter(facadeScope))
	if err != nil {
		return nil
	}
	// 良性竞争:两个 instrument 都有效,LoadOrStore 只保留一个。
	v, _ := cache.LoadOrStore(name, created)
	return v
}
