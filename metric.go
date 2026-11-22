package mebsuta

import (
	"context"
	"sync"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// metric 门面的 instrument 缓存。OTel instrument 本应创建一次并复用；
// 门面把它隐藏在一次调用助手后面，代价是每次调用一次 map 查找——
// 想要零查找开销的热路径应通过 otel.Meter(facadeScope) 显式创建
// instrument。
var (
	counters   sync.Map // name → metric.Int64Counter
	histograms sync.Map // name → metric.Float64Histogram
	gauges     sync.Map // name → metric.Int64Gauge
)

// Counter 经全局注册的 meter（telemetry.Start 默认装配）向一个 int64
// 计数器累加 delta。instrument 按名字在首次使用时创建并缓存。
//
// 门面错误被有意吞掉：遥测绝不能破坏请求路径，配置错误的管道表现为
// 指标缺失，而非 panic 或每次调用产生日志噪声。
//
// 安全纪律（第五次审计建议）：instrument 按名字缓存且无淘汰——名字
// 必须是静态常量，绝不能来自请求数据（路由的 fmt.Sprintf、用户 id 等），
// 否则缓存会随攻击者控制的基数增长。
func Counter(ctx context.Context, name string, delta int64, attrs ...attribute.KeyValue) {
	if c, ok := instrument(&counters, name, func(m metric.Meter) (any, error) {
		return m.Int64Counter(name)
	}).(metric.Int64Counter); ok {
		c.Add(ctx, delta, metric.WithAttributes(attrs...))
	}
}

// Histogram 经全局注册的 meter 把 value 记入一个 float64 直方图。
// 缓存与错误语义见 Counter。
func Histogram(ctx context.Context, name string, value float64, attrs ...attribute.KeyValue) {
	if h, ok := instrument(&histograms, name, func(m metric.Meter) (any, error) {
		return m.Float64Histogram(name)
	}).(metric.Float64Histogram); ok {
		h.Record(ctx, value, metric.WithAttributes(attrs...))
	}
}

// Gauge 经全局注册的 meter 把 value 记入一个 int64 量规（每个属性集
// 后写胜出）。缓存与错误语义见 Counter。
func Gauge(ctx context.Context, name string, value int64, attrs ...attribute.KeyValue) {
	if g, ok := instrument(&gauges, name, func(m metric.Meter) (any, error) {
		return m.Int64Gauge(name)
	}).(metric.Int64Gauge); ok {
		g.Record(ctx, value, metric.WithAttributes(attrs...))
	}
}

// instrument 返回 name 对应的缓存 instrument，首次使用时经全局 meter
// 创建。创建失败返回 nil（吞掉，见 Counter）；并发创建者的竞争是良性
// 的——两个 instrument 都有效，LoadOrStore 只保留一个、丢弃另一个。
func instrument(cache *sync.Map, name string, create func(metric.Meter) (any, error)) any {
	if v, ok := cache.Load(name); ok {
		return v
	}
	created, err := create(otel.Meter(facadeScope))
	if err != nil {
		return nil
	}
	v, _ := cache.LoadOrStore(name, created)
	return v
}
