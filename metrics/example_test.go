package metrics_test

import (
	"fmt"
	"net/http"

	"github.com/iuboy/mebsuta"
	"github.com/iuboy/mebsuta/config"
	mebmetrics "github.com/iuboy/mebsuta/metrics"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Example_withCategraf 展示如何与 Categraf 集成
//
// Categraf 配置示例 (conf/input.prometheus/prometheus.toml):
//
//	[[instances]]
//	  urls = ["http://localhost:2112/metrics"]
//	  name_prefix = "mebsuta_"
//	  labels = { service = "my-service" }
func Example_withCategraf() {
	// 1. 初始化日志库
	cfg := config.LoggerConfig{
		ServiceName: "my-service",
		Outputs: []config.OutputConfig{
			{
				Type:     config.Stdout,
				Level:    config.InfoLevel,
				Encoding: config.JSON,
				Enabled:  true,
			},
		},
	}
	if err := mebsuta.Init(cfg); err != nil {
		panic(err)
	}

	// 2. 创建自定义 Prometheus 注册表
	registry := prometheus.NewRegistry()

	// 3. 注册 Mebsuta 指标
	registry.MustRegister(mebmetrics.GetMetricsAsCollector())

	// 4. 启动 HTTP 服务器（供 Categraf 抓取）
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{
		EnableOpenMetrics: true, // Categraf 支持 OpenMetrics 格式
	}))

	go func() {
		if err := http.ListenAndServe(":2112", mux); err != nil {
			panic(err)
		}
	}()

	fmt.Println("Metrics server started on :2112")
	fmt.Println("Categraf can scrape http://localhost:2112/metrics")
}

// Example_withStandardPrometheus 展示与标准 Prometheus 集成
func Example_withStandardPrometheus() {
	// 初始化日志
	cfg := config.LoggerConfig{
		ServiceName: "my-service",
		Outputs: []config.OutputConfig{
			{
				Type:     config.Stdout,
				Level:    config.InfoLevel,
				Encoding: config.JSON,
				Enabled:  true,
			},
		},
	}
	mebsuta.Init(cfg)

	// 注册到默认注册表
	mebmetrics.Register()

	// 使用默认的 HTTP handler
	http.Handle("/metrics", promhttp.Handler())
	http.ListenAndServe(":2112", nil)
}

// Example_customRegistry 展示使用自定义注册表
func Example_customRegistry() {
	cfg := config.LoggerConfig{
		ServiceName: "my-service",
		Outputs: []config.OutputConfig{
			{
				Type:    config.Stdout,
				Level:   config.InfoLevel,
				Enabled: true,
			},
		},
	}
	mebsuta.Init(cfg)

	// 创建自定义注册表
	registry := prometheus.NewRegistry()

	// 注册 Mebsuta 指标
	if err := mebmetrics.RegisterToRegistry(registry); err != nil {
		panic(err)
	}

	// 可以同时注册其他指标
	// registry.MustRegister(otherCollectors...)

	// 暴露指标
	http.Handle("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))
	http.ListenAndServe(":2112", nil)
}
