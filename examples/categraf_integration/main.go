// Categraf 集成示例
// 演示如何在应用程序中暴露 Mebsuta 指标供 Categraf 采集
package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/iuboy/mebsuta"
	"github.com/iuboy/mebsuta/config"
	mebmetrics "github.com/iuboy/mebsuta/metrics"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func main() {
	// 1. 初始化 Mebsuta 日志库
	cfg := config.LoggerConfig{
		ServiceName: "my-app",
		DebugMode:   false,
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
		fmt.Fprintf(os.Stderr, "初始化日志库失败: %v\n", err)
		os.Exit(1)
	}

	// 2. 创建自定义 Prometheus 注册表
	registry := prometheus.NewRegistry()

	// 3. 注册 Mebsuta 指标
	registry.MustRegister(mebmetrics.GetMetricsAsCollector())

	// 4. 启动指标 HTTP 服务器（供 Categraf 抓取）
	metricsMux := http.NewServeMux()
	metricsMux.Handle("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{
		EnableOpenMetrics: true, // 支持 OpenMetrics 格式
	}))

	metricsServer := &http.Server{
		Addr:         ":2112",
		Handler:      metricsMux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	go func() {
		fmt.Println("✓ 指标服务器启动在 http://localhost:2112/metrics")
		fmt.Println("✓ Categraf 配置:")
		fmt.Println("  [[instances]]")
		fmt.Println("    urls = [\"http://localhost:2112/metrics\"]")
		if err := metricsServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Fprintf(os.Stderr, "指标服务器错误: %v\n", err)
		}
	}()

	// 5. 模拟应用程序运行
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	// 记录一些日志以生成指标
	for i := 0; ; i++ {
		select {
		case <-ticker.C:
			mebsuta.Info("应用程序运行中",
				mebsuta.Int("iteration", i),
				mebsuta.String("status", "healthy"))

			mebsuta.Debug("调试信息",
				mebsuta.Int("counter", i*10))

		case sig := <-waitForShutdown():
			fmt.Printf("\n收到信号 %v，正在关闭...\n", sig)

			// 优雅关闭
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			if err := metricsServer.Shutdown(ctx); err != nil {
				fmt.Fprintf(os.Stderr, "关闭指标服务器失败: %v\n", err)
			}

			if err := mebsuta.Sync(); err != nil {
				fmt.Fprintf(os.Stderr, "同步日志失败: %v\n", err)
			}

			fmt.Println("已安全关闭")
			return
		}
	}
}

func waitForShutdown() <-chan os.Signal {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	return sigCh
}
