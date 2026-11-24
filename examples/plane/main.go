// plane: 管理面/业务面/审计面分流——业务写文件,管理面写 stdout,
// 审计面独立落盘(仅 LevelAudit 记录)。
package main

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/iuboy/mebsuta"
	"github.com/iuboy/mebsuta/audit"
	"github.com/iuboy/mebsuta/filerotate"
)

func main() {
	dir, _ := os.MkdirTemp("", "mebsuta-plane")
	defer func() { _ = os.RemoveAll(dir) }()

	logger, err := mebsuta.Init(
		// 业务面 = 默认链:写文件。
		mebsuta.UseFile(filerotate.Config{
			Path: filepath.Join(dir, "business.log"),
		}, mebsuta.FileConfig{}),

		// 管理面:独立链,console 格式写 stdout。
		mebsuta.UsePlane(mebsuta.PlaneManagement,
			mebsuta.UseStdout(mebsuta.StdoutConfig{Format: "console"})),

		// 审计面:独立文件,Level=LevelAudit 即只收审计级记录。
		mebsuta.UsePlane(mebsuta.PlaneAudit,
			mebsuta.UseFile(filerotate.Config{
				Path: filepath.Join(dir, "audit.log"),
			}, mebsuta.FileConfig{
				Level: mebsuta.LevelAudit,
			})),
	)
	if err != nil {
		panic(err)
	}
	defer func() { _ = mebsuta.CloseAll(logger.Handler()) }()

	// 业务面:直接 slog 调用,无感。
	slog.Info("order created", "order_id", 42)
	slog.Warn("slow query", "took_ms", 900)

	// 管理面:经 Plane 派生的 logger(推荐在组件构造时取一次持为字段)。
	mgmt := mebsuta.Plane(mebsuta.PlaneManagement)
	mgmt.Info("listening", "addr", ":8080")
	mgmt.Info("config reloaded")

	// 审计面:audit 包零改动,LevelAudit 自动路由到审计面。
	audit.AuditEvent(audit.EventLogin, "user login",
		"actor", "user:42",
		"success", true,
	)

	// 业务面的普通 Error 不会进审计面;审计面的记录也不会混进业务文件。
	slog.Error("payment failed", "order_id", 42)

	// 输出三个目的地的内容。
	for _, name := range []string{"business.log", "audit.log"} {
		b, _ := os.ReadFile(filepath.Join(dir, name))
		fmt.Printf("== %s ==\n%s\n", name, b)
	}
}
