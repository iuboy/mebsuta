// database: 日志批量写入 PostgreSQL 或 openGauss 数据库
//
// 注意：SQLite 不是 database.Config 支持的驱动（Validate 只接受
// "postgres" 与 "opengauss"）；本仓库中的 sqlite GORM 驱动仅作为
// database 包的测试依赖存在。
// 本示例面向 PostgreSQL——用以下命令启动一个一次性服务器：
//
//	docker run --rm -p 5432:5432 -e POSTGRES_PASSWORD=dev postgres:17
//
// 再把 MEBSUTA_DATABASE_DSN 指向它（见下文）。
package main

import (
	"log/slog"
	"os"
	"time"

	"github.com/iuboy/mebsuta"
	"github.com/iuboy/mebsuta/database"
)

func main() {
	// DSN 从环境变量读取，凭证因此不落入源码树。示例：
	//	MEBSUTA_DATABASE_DSN='postgres://postgres:dev@localhost:5432/postgres?sslmode=disable'
	dsn := os.Getenv("MEBSUTA_DATABASE_DSN")
	if dsn == "" {
		panic("MEBSUTA_DATABASE_DSN is required, e.g. " +
			"MEBSUTA_DATABASE_DSN='postgres://postgres:dev@localhost:5432/postgres?sslmode=disable' " +
			"(start a server with: docker run --rm -p 5432:5432 -e POSTGRES_PASSWORD=dev postgres:17)")
	}

	cfg := database.Config{
		Driver:        "postgres",
		DSN:           dsn,
		Table:         "logs",
		BatchSize:     50,
		BatchInterval: 2 * time.Second,
	}
	dbH, err := database.NewHandler(cfg)
	if err != nil {
		panic(err)
	}

	logger, err := mebsuta.New(
		mebsuta.UseStdout(mebsuta.StdoutConfig{}),
		mebsuta.WithHandler(dbH),
	)
	if err != nil {
		// H6：关闭 handler 做清理，但用真正的 err panic——
		// 原来的 `panic(dbH.Close())` 丢弃了 err，Close 成功时甚至
		// 会 panic(nil)。
		_ = dbH.Close()
		panic(err)
	}
	slog.SetDefault(logger)
	defer func() { _ = mebsuta.CloseAll(logger.Handler()) }()

	// Config.Sanitize 返回 DSN 凭证已脱敏的副本——可安全记录日志；
	// 直接打印 cfg 本身也会经其 String 方法走同样的脱敏流程，
	// 但脱敏副本让意图更明确。
	slog.Info("logging to both stdout and database", "config", cfg.Sanitize(), "source", "example")
	slog.Error("error also persisted", "code", 500)
}
