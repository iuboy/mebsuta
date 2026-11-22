package mebsutatest

import (
	"go.opentelemetry.io/otel"
	lognoop "go.opentelemetry.io/otel/log/noop"
	metricnoop "go.opentelemetry.io/otel/metric/noop"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

// ResetOTelGlobals 把 otel 全局复位为 no-op 默认（tracer/meter/logger
// provider 与 propagator）——消费方测试的隔离舞步至此收编为一次调用。
//
// # TEST-ONLY
//
// 仅供测试收尾调用；生产代码触碰 otel 全局属于安装方的职责。使用
// telemetry 覆盖告警的测试请配对调用 telemetry.ResetGlobalTracking()
// （本包不依赖 telemetry，避免与 telemetry 的内部测试成环）。
// 注意：otel 的全局 ErrorHandler 不在此复位——telemetry 的错误桥转发
// 到 mebsuta.DefaultErrorHandler（stderr），与 otel 缺省行为等价，复位
// 无观测收益。
func ResetOTelGlobals() {
	otel.SetTracerProvider(trace.NewNoopTracerProvider())
	otel.SetMeterProvider(metricnoop.NewMeterProvider())
	otel.SetLoggerProvider(lognoop.NewLoggerProvider())
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator())
}
