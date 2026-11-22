package mebsuta

import (
	"context"
	"log/slog"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// facadeScope 是经由包门面创建的 span 与 metric 的 instrumentation scope
// 名称。保持单一 scope 可让下游消费方把框架插桩信号与应用自身的信号
// 区分开。
const facadeScope = "github.com/iuboy/mebsuta"

// StartSpan 通过全局注册的 tracer provider 启动一个 span
// （telemetry.Start 默认经 SetGlobal 装配）。未注册 provider 时，otel
// 全局回退到 no-op tracer——在测试与本地开发中该调用安全且廉价。
//
//	ctx, span := mebsuta.StartSpan(ctx, "handle_request")
//	defer span.End()
//
// 返回的 span 是完整的 otel trace.Span 接口；高级用法
// （SetStatus、RecordError、AddEvent）无需 mebsuta 专属包装。
func StartSpan(ctx context.Context, name string, attrs ...attribute.KeyValue) (context.Context, trace.Span) {
	return otel.Tracer(facadeScope).Start(ctx, name, trace.WithAttributes(attrs...))
}

// TraceContextExtractor 返回一个 ContextExtractor，把活动 span 的
// trace_id/span_id 作为属性注入每条日志记录。它让本地输出
// （stdout、file、database、syslog）获得与 OTel 日志管道原生能力相同的
// 日志-trace 关联——otlp handler 自行从发出记录的 context 读取 trace
// 上下文，不需要该提取器。
//
//	logger, _ := mebsuta.New(
//		mebsuta.UseFile(...),
//		mebsuta.UseContextExtractor(mebsuta.TraceContextExtractor()),
//	)
//
// 在任何 span 之外记录的日志不携带额外属性。
func TraceContextExtractor() ContextExtractor {
	return func(ctx context.Context) []slog.Attr {
		sc := trace.SpanContextFromContext(ctx)
		if !sc.IsValid() {
			return nil
		}
		return []slog.Attr{
			slog.String("trace_id", sc.TraceID().String()),
			slog.String("span_id", sc.SpanID().String()),
		}
	}
}
