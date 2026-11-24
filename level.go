// 日志级别运行时热调（walk-based）：与 SetFileMaxAge 同款 handler 图遍历
// （unwrap 链 + safeMulti fanout + handlerIdentity 去重），对每个支持
// SetLevel 的 handler 应用新级别。热调的前提是构造期传入 *slog.LevelVar
// （NewLevelVar 便捷构造）——固定级别 handler 进入 skipped 清单，不静默
// 假装成功。
package mebsuta

import (
	"fmt"
	"log/slog"
)

// LevelVarSetter 是运行时级别热调的统一接口(0.1.0-26 起取消并行的
// 未导出接口 levelSetter——两套方法集完全相同,多一套只会各自漂移)。
// 根包与子包 handler(stdout、file、syslog、database、mbta)一律实现
// 本导出接口。
type LevelVarSetter interface {
	SetLevel(level slog.Level) bool
}

// NewLevelVar 返回以 level 为初值的 *slog.LevelVar——传给任一 handler 的
// Config.Level 即获得原子热调能力（slog 标准机制，mebsuta 全部 handler
// 的 Level 字段均为 slog.Leveler 接口）。
func NewLevelVar(level slog.Level) *slog.LevelVar {
	lv := new(slog.LevelVar)
	lv.Set(level)
	return lv
}

// SetLevel 遍历 logger 的 handler 图热调级别，返回（生效数， 未生效的
// handler 类型清单， 错误）。仅构造期传入 *slog.LevelVar 的 handler 生效；
// 固定级别 handler 进入 skipped（类型名形式）——运维面诚实可见，避免
// "调了级别却没变"的静默失败。nil handler 无害。
func SetLevel(h slog.Handler, level slog.Level) (int, []string, error) {
	if h == nil {
		return 0, nil, nil
	}
	var (
		applied int
		skipped []string
	)
	err := walkHandlers(h, func(h slog.Handler) error {
		if ls, ok := h.(LevelVarSetter); ok {
			if ls.SetLevel(level) {
				applied++
			} else {
				skipped = append(skipped, fmt.Sprintf("%T", h))
			}
		}
		return nil
	})
	return applied, skipped, err
}
