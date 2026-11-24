// trace 关联助手：日志-追踪关联所需的 context 提取器。span 与 metric
// 的门面（StartSpan/Counter 等）在 0.1.0-29 起随 telemetry 实例
// （telemetry.Telemetry 的同名方法）——根包不再经 otel 全局转发。
package mebsuta

import (
	"context"
	"log/slog"

	"go.opentelemetry.io/otel/trace"
)

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
