// otlp-logs: 经 OTel 日志管道导出 slog 记录，
// 并附带日志与链路的原生关联。
//
//	go run ./examples/otlp-logs
//
// 需要 127.0.0.1:4318 上有一个 OTLP/HTTP 接收端（mebsuta-forwarder 的
// otlp source 或任意 collector）。设 OTLP_ENDPOINT 指向别处，或设为
// "off" 以无接收端运行（telemetry 与 handler 退化为 no-op；
// slog 调用仍然有效）。
package main

import (
	"context"
	"os"

	"log/slog"

	"github.com/iuboy/mebsuta"
	"github.com/iuboy/mebsuta/otlp"
	"github.com/iuboy/mebsuta/telemetry"
)

func main() {
	endpoint := os.Getenv("OTLP_ENDPOINT")
	if endpoint == "" {
		endpoint = "http://127.0.0.1:4318"
	}
	if endpoint == "off" {
		endpoint = ""
	}

	ctx := context.Background()

	// 一次 bootstrap 即持有 exporters 与关闭路径。
	tel, err := telemetry.Start(ctx, telemetry.Config{
		ServiceName: "otlp-logs-example",
		Endpoint:    endpoint,
	})
	if err != nil {
		panic(err)
	}
	defer func() { _ = tel.Shutdown(ctx) }()

	// otlp handler 把 slog 桥接进该管道；WithHandler 像对待其他
	// mebsuta handler 一样将它与本地输出组合。
	logger, err := mebsuta.New(
		mebsuta.WithHandler(otlp.NewHandler(tel.LoggerProvider(), otlp.Config{})),
		mebsuta.UseStdout(mebsuta.StdoutConfig{}),
	)
	if err != nil {
		panic(err)
	}
	slog.SetDefault(logger)

	// 在 span 内记录日志即可关联该记录：logs SDK 会自动从 context
	// 填充 TraceID/SpanID——OTLP 路径无需 extractor
	// （TraceContextExtractor 服务于本地输出）。
	_, span := tel.StartSpan(ctx, "example.run")
	slog.InfoContext(ctx, "hello over OTLP", "service", "otlp-logs-example")
	tel.Counter(ctx, "example.logs_emitted", 1)
	span.End()
}
