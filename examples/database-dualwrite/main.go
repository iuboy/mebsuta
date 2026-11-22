// database-dualwrite: 事务一致双写——DB 为事实源，OTLP 经 outbox 中继。
//
// 需要一个 PostgreSQL（表由 LogsTableDDL 参考 DDL 自建或手工执行）与一个
// OTLP/HTTP 接收端：
//
//	docker run --rm -p 5432:5432 -e POSTGRES_PASSWORD=dev postgres:17
//	MEBSUTA_DATABASE_DSN='postgres://postgres:dev@localhost:5432/postgres?sslmode=disable' \
//	OTLP_ENDPOINT=http://127.0.0.1:4318 go run ./examples/database-dualwrite
//
// 行为：日志批量落库（事务原子 + 防篡改签名可选），flush 提交后同步中继
// 到 OTLP；中继失败行保持 relayed_at IS NULL，由后台扫描器（30s）对账补投。
package main

import (
	"context"
	"log/slog"
	"os"
	"time"

	"github.com/iuboy/mebsuta/database"
	"github.com/iuboy/mebsuta/telemetry"
)

func main() {
	dsn := os.Getenv("MEBSUTA_DATABASE_DSN")
	if dsn == "" {
		panic("MEBSUTA_DATABASE_DSN is required（参见文件头注释的 docker 启动方式）")
	}
	endpoint := os.Getenv("OTLP_ENDPOINT")
	if endpoint == "" {
		endpoint = "http://127.0.0.1:4318"
	}

	ctx := context.Background()

	// OTLP 管线（方式 A）——同时是事务双写的 RelayTo 目标。
	tel, err := telemetry.Start(ctx, telemetry.Config{
		ServiceName: "dualwrite-example",
		Endpoint:    endpoint,
		Signals:     telemetry.Logs,
	})
	if err != nil {
		panic(err)
	}
	defer func() { _ = tel.Shutdown(ctx) }()

	// 数据库 handler（方式 B）+ Consistency 开启事务一致双写：
	// DB 事务提交后才中继；at-least-once，消费方按 ULID id 幂等去重。
	dbH, err := database.NewHandler(database.Config{
		Driver:        "postgres",
		DSN:           dsn,
		Table:         "logs",
		ServiceName:   "dualwrite-example",
		BatchSize:     20,
		BatchInterval: time.Second,
		RelayTo:       tel.LoggerProvider(),
		Consistency: database.ConsistencyConfig{
			Enabled:           true,
			RelayScanInterval: 30 * time.Second,
		},
	})
	if err != nil {
		panic(err)
	}

	logger := slog.New(dbH)
	for i := range 10 {
		logger.Info("dual write record", "i", i)
	}
	// Close 排干并 flush：提交 → 同步中继 → 标记 relayed_at。
	if err := dbH.Close(); err != nil {
		panic(err)
	}
	// Telemetry Shutdown 刷尽 OTLP 侧后结束（defer）。
}
