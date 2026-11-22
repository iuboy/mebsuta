// telemetry-database: 方式 B——traces/metrics 经 mebsuta 直写数据库，
// 不经 OTLP 网络路径；SQL 游标消费者（mebsuta-forwarder 的 database
// source 等）按 ULID id 增量拉取。
//
// 需要一个 PostgreSQL（表由 EnsureSchema 默认幂等创建）：
//
//	docker run --rm -p 5432:5432 -e POSTGRES_PASSWORD=dev postgres:17
//	MEBSUTA_DATABASE_DSN='postgres://postgres:dev@localhost:5432/postgres?sslmode=disable' \
//	go run ./examples/telemetry-database
package main

import (
	"context"
	"os"
	"time"

	"github.com/iuboy/mebsuta/telemetry"
)

func main() {
	dsn := os.Getenv("MEBSUTA_DATABASE_DSN")
	if dsn == "" {
		panic("MEBSUTA_DATABASE_DSN is required（参见文件头注释的 docker 启动方式）")
	}

	ctx := context.Background()

	// 仅 Database 后端（Endpoint 留空）：traces/metrics 落 mebsuta_traces /
	// mebsuta_metrics 两表；与 Endpoint 并存即双写（fanout）。
	tel, err := telemetry.Start(ctx, telemetry.Config{
		ServiceName: "db-mode-example",
		Database: &telemetry.DatabaseConfig{
			Driver: "postgres",
			DSN:    dsn,
		},
		MetricExportInterval: 2 * time.Second,
	})
	if err != nil {
		panic(err)
	}
	defer func() { _ = tel.Shutdown(ctx) }()

	// span + 指标各一条，Shutdown 刷入表。
	_, span := tel.TracerProvider().Tracer("example").Start(ctx, "db-mode-op")
	span.End()
	ctr, err := tel.MeterProvider().Meter("example").Int64Counter("db_mode_total")
	if err != nil {
		panic(err)
	}
	ctr.Add(ctx, 1)
	time.Sleep(3 * time.Second) // 等一轮周期导出再 Shutdown 亦可
}
