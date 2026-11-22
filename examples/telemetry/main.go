// telemetry: 经 mebsuta/telemetry 完成 OTel 三信号引导（traces/metrics/logs）。
//
// 面向本地 mebsuta-forwarder 的 OTLP source 运行（或 :4318 上的任意
// OTLP/HTTP 端点）：
//
//	go run ./examples/telemetry
//
// 用 OTLP_ENDPOINT 指向别处（如测试里的 mebsutatest 接收端）；
// 设为 "off" 可观察 no-op 模式。
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/log"

	"github.com/iuboy/mebsuta/telemetry"
)

func main() {
	endpoint := os.Getenv("OTLP_ENDPOINT")
	if endpoint == "" {
		endpoint = "http://127.0.0.1:4318"
	}

	cfg := telemetry.Config{
		ServiceName:    "telemetry-example",
		ServiceVersion: "0.0.1",
		Environment:    "development",
		Endpoint:       endpoint,
	}
	if endpoint == "off" {
		// 空端点 → no-op 模式：Start 永不报错、Shutdown 亦为 no-op，
		// 同一调用形态在无接收端时照常工作。
		cfg.Endpoint = ""
	}

	tel, err := telemetry.Start(context.Background(), cfg)
	if err != nil {
		panic(err)
	}
	// Shutdown 会在超时内 flush 所有已启动的管道；这是唯一需要的
	// 清理调用。
	defer func() { _ = tel.Shutdown(context.Background()) }()

	ctx := context.Background()

	// Traces：SetGlobal 默认为 true，otel.Tracer 因此拿到已启动的
	// provider——即 otelgin/otelhttp 读取的同一句柄。
	ctx, span := otel.Tracer("example").Start(ctx, "example.run")
	span.SetAttributes(attribute.String("example.attr", "demo"))
	work(ctx)
	span.End()

	// Metrics：经全局 meter 上报一个 counter。
	ctr, err := otel.Meter("example").Int64Counter("example.operations")
	if err != nil {
		panic(err)
	}
	ctr.Add(ctx, 1)

	// Logs：日志信号的 provider。本示例直接经 OTel log API 发射；
	// mebsuta 根包的门面（slog bridge）把 slog 日志接入同一条管道。
	var rec log.Record
	rec.SetSeverity(log.SeverityInfo)
	rec.SetSeverityText("INFO")
	rec.SetBody(attribute.StringValue("telemetry example finished"))
	rec.SetObservedTimestamp(time.Now())
	tel.LoggerProvider().Logger("example").Emit(ctx, rec)

	fmt.Printf("sent 1 span, 1 metric and 1 log record to %s (no-op: %v)\n", endpoint, !tel.Enabled())
}

// work 嵌套一个子 span，演示 context 传播。
func work(ctx context.Context) {
	_, span := otel.Tracer("example").Start(ctx, "example.work")
	defer span.End()
	time.Sleep(10 * time.Millisecond)
}
