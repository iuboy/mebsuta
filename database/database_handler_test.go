package database

import (
	"context"
	"log/slog"
	"testing"

	"github.com/iuboy/mebsuta"
)

// =============================================================================
// Handler 配置验证测试（不需要真实连接）
// =============================================================================

func TestNewHandler_UnsupportedDriver(t *testing.T) {
	// 使用有效的 DSN 格式，但不支持的驱动程序
	cfg := Config{Driver: "sqlite", DSN: "file:test.db", Table: "logs", Level: slog.LevelInfo}
	_, err := NewHandler(cfg)
	if err == nil {
		t.Fatal("expected error for unsupported driver")
	}
}

func TestNewHandler_EmptyDSN(t *testing.T) {
	cfg := Config{Driver: "mysql", DSN: "", Table: "logs"}
	_, err := NewHandler(cfg)
	// Validate 应该返回错误，因为 DSN 不能为空
	if err == nil {
		t.Fatal("NewHandler should reject empty DSN")
	}
}

func TestHandler_Enabled(t *testing.T) {
	h := &Handler{
		leveler: slog.LevelError,
	}
	if h.Enabled(context.Background(), slog.LevelInfo) {
		t.Error("Info should not be enabled at Error level")
	}
	if !h.Enabled(context.Background(), slog.LevelError) {
		t.Error("Error should be enabled at Error level")
	}
}

func TestHandler_WithAttrs(t *testing.T) {
	var _ slog.Handler = (*Handler)(nil)
	var _ slog.Handler = (*mebsuta.AttrsSub)(nil)
	var _ slog.Handler = (*mebsuta.GroupSub)(nil)
}

// Regression: ISSUE-002 — Handler 必须实现非导出的 setErrorHandler 方法
// Found by /qa on 2026-04-15
// propagateErrorHandler 依赖 errorHandlerSetter 接口（要求 setErrorHandler 方法）。
// 如果只实现未导出的 setErrorHandler，WithErrorHandler option 会被静默忽略。
func TestHandler_HasSetErrorHandler(t *testing.T) {
	// 验证 setErrorHandler 存在且可以调用（编译期检查）
	h := &Handler{}
	h.setErrorHandler(mebsuta.DefaultErrorHandler)
}
