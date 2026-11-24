package mebsuta

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// Counter 经全局注册的 meter（telemetry.Start 默认装配）向一个 int64
// 计数器累加 delta。
//
// instrument 不在门面缓存：otel 全局 provider 是唯一事实源，SDK 的
// meter 自身按名字缓存 instrument。门面再缓存一层会让 instrument
// 绑死在创建时的 provider 上——代次轮换（新 Start 覆盖全局，见
// README「热重载」）后旧名字会继续写进已 Shutdown 的旧 provider，
// 新 provider 收不到任何数据。
//
// 门面错误被有意吞掉：遥测绝不能破坏请求路径，配置错误的管道表现
// 为指标缺失，而非 panic 或每次调用产生日志噪声。
//
// 安全纪律：instrument 按名字解析，名字必须是静态常量，绝不能来自
// 请求数据（路由的 fmt.Sprintf、用户 id 等），否则会成为攻击者可控
// 的基数面。
func Counter(ctx context.Context, name string, delta int64, attrs ...attribute.KeyValue) {
	if c, err := otel.Meter(facadeScope).Int64Counter(name); err == nil {
		c.Add(ctx, delta, metric.WithAttributes(attrs...))
	}
}

// Histogram 经全局注册的 meter 把 value 记入一个 float64 直方图。
// instrument 生命周期与错误语义见 Counter。
func Histogram(ctx context.Context, name string, value float64, attrs ...attribute.KeyValue) {
	if h, err := otel.Meter(facadeScope).Float64Histogram(name); err == nil {
		h.Record(ctx, value, metric.WithAttributes(attrs...))
	}
}

// Gauge 经全局注册的 meter 把 value 记入一个 int64 量规（每个属性集
// 后写胜出）。instrument 生命周期与错误语义见 Counter。
func Gauge(ctx context.Context, name string, value int64, attrs ...attribute.KeyValue) {
	if g, err := otel.Meter(facadeScope).Int64Gauge(name); err == nil {
		g.Record(ctx, value, metric.WithAttributes(attrs...))
	}
}
