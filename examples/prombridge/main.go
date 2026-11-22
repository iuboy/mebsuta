// prombridge: 存量 prometheus 指标零改造接入 OTLP 路径。
//
// 起一个 OTLP/HTTP 接收端（mebsuta-forwarder 的 otlp source，或任意
// collector），然后：
//
//	OTLP_ENDPOINT=http://127.0.0.1:4318 go run ./examples/prombridge
//
// OTLP_ENDPOINT=off 可无接收端空跑（telemetry no-op，桥照常轮询）。
package main

import (
	"context"
	"os"
	"time"

	"github.com/iuboy/mebsuta/prombridge"
	"github.com/iuboy/mebsuta/telemetry"
	"github.com/prometheus/client_golang/prometheus"
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
	tel, err := telemetry.Start(ctx, telemetry.Config{
		ServiceName: "prombridge-example",
		Endpoint:    endpoint,
		Signals:     telemetry.Metrics,
	})
	if err != nil {
		panic(err)
	}
	defer func() { _ = tel.Shutdown(ctx) }()

	// 既有服务的 prometheus Registry 原样挂上桥——instrumentation 零改动。
	reg := prometheus.NewRegistry()
	requests := prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "example_requests_total"},
		[]string{"route"},
	)
	depth := prometheus.NewGauge(prometheus.GaugeOpts{Name: "example_queue_depth"})
	reg.MustRegister(requests, depth)

	bridge, err := prombridge.Start(ctx, tel.MeterProvider(), reg,
		prombridge.WithInterval(2*time.Second))
	if err != nil {
		panic(err)
	}
	defer bridge.Close()

	// 业务侧照常只操作 prometheus 指标；桥在后台差分转发。
	for i := range 5 {
		requests.WithLabelValues("/api").Inc()
		depth.Set(float64(i))
		time.Sleep(500 * time.Millisecond)
	}
	// histogram/summary 会被跳过（API 无法忠实表达预聚合 bucket），
	// Bridge.Skipped() 提供诚实健康面。
}
