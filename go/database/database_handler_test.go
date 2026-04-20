package database

import (
	"context"
	"log/slog"
	"testing"

	"github.com/iuboy/mebsuta"
	"github.com/iuboy/mebsuta/config"
)

// =============================================================================
// DatabaseHandler 配置验证测试（不需要真实连接）
// =============================================================================

func TestNewDatabaseHandler_UnsupportedDriver(t *testing.T) {
	_, err := NewDatabaseHandler(config.DatabaseConfig{
		DriverName: "sqlite",
	}, slog.LevelInfo)
	if err == nil {
		t.Fatal("expected error for unsupported driver")
	}
}

func TestNewDatabaseHandler_EmptyDSN(t *testing.T) {
	_, err := NewDatabaseHandler(config.DatabaseConfig{
		DriverName: "mysql",
	}, slog.LevelInfo)
	if err == nil {
		t.Fatal("expected error for empty DSN")
	}
}

func TestDatabaseHandler_Enabled(t *testing.T) {
	h := &DatabaseHandler{
		LevelHandler: mebsuta.LevelHandler{Level: slog.LevelError},
	}
	if h.Enabled(context.Background(), slog.LevelInfo) {
		t.Error("Info should not be enabled at Error level")
	}
	if !h.Enabled(context.Background(), slog.LevelError) {
		t.Error("Error should be enabled at Error level")
	}
}

func TestDatabaseHandler_WithAttrs(t *testing.T) {
	var _ slog.Handler = (*DatabaseHandler)(nil)
	var _ slog.Handler = (*dbAttrsHandler)(nil)
	var _ slog.Handler = (*dbGroupHandler)(nil)
}

// Regression: ISSUE-002 — DatabaseHandler 必须实现非导出的 setErrorHandler 方法
// Found by /qa on 2026-04-15
// propagateErrorHandler 依赖 errorHandlerSetter 接口（要求 setErrorHandler 方法）。
// 如果只实现未导出的 setErrorHandler，WithErrorHandler option 会被静默忽略。
func TestDatabaseHandler_HasSetErrorHandler(t *testing.T) {
	// 验证 setErrorHandler 存在且可以调用（编译期检查）
	h := &DatabaseHandler{}
	h.setErrorHandler(mebsuta.DefaultErrorHandler)
}
