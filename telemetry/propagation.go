package telemetry

import "go.opentelemetry.io/otel/propagation"

// propagator 返回启用 SetGlobal 时注册到全局的复合 W3C propagator：
// trace context 负责 span 关联，baggage 负责带外键值传播。这与组织内
// 各 internal/telemetry 实现原本的用法一致，因此切换到本包不会改变
// 跨服务传播行为。
func propagator() propagation.TextMapPropagator {
	return propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	)
}
