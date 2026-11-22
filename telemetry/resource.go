package telemetry

import (
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.43.0"
)

// buildResource 组装所有已启动信号共享的 OTel resource：SDK/telemetry
// 默认值，加上服务标识与 Config 中的额外属性。
//
// 自定义属性有意不带 schema。当两侧声明的 schema URL 不同时
// resource.Merge 会失败，而 resource.Default() 钉住的 semconv 版本随 SDK
// 演进——无 schema 的合并使升级 SDK 不会破坏启动，同时我们输出的属性键
// （service.*、deployment.environment）在各 semconv 版本间保持稳定。
func buildResource(cfg Config) *resource.Resource {
	attrs := []attribute.KeyValue{
		semconv.ServiceName(cfg.ServiceName),
	}
	if v := cfg.ServiceVersion; v != "" {
		attrs = append(attrs, semconv.ServiceVersion(v))
	}
	if e := cfg.Environment; e != "" {
		attrs = append(attrs, semconv.DeploymentEnvironmentNameKey.String(e))
	}
	for k, v := range cfg.Attributes {
		attrs = append(attrs, attribute.String(k, v))
	}
	res, err := resource.Merge(resource.Default(), resource.NewSchemaless(attrs...))
	if err != nil {
		// 无 schema 合并（无冲突的 schema URL）时不可达，但 resource
		// 绝不能为 nil：回退到仅默认值，而不是在插桩内部 panic。
		return resource.Default()
	}
	return res
}
