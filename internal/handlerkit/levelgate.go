package handlerkit

import "log/slog"

// LevelGate 封装 handler 的级别判定与 *slog.LevelVar 热调。此前
// SetLevel 的"仅 LevelVar 生效"判定与 Enabled 的 SafeLevel 比较在
// stdout/file/syslog/database/mbta 五个 handler 里各有一份逐字拷贝。
//
// 零值门限为 slog.LevelInfo(SafeLevel 对 nil Leveler 的缺省),与各
// handler 构造期 Validate 的默认值一致。
type LevelGate struct {
	Leveler slog.Leveler
}

// NewLevelGate 返回以 l 为门限的 LevelGate。
func NewLevelGate(l slog.Leveler) LevelGate { return LevelGate{Leveler: l} }

// Enabled 报告 level 是否达到门限。经 SafeLevel 防御类型化 nil
// Leveler（如 (*slog.Level)(nil)）的 panic。
func (g LevelGate) Enabled(level slog.Level) bool {
	return level >= SafeLevel(g.Leveler)
}

// Set 热调级别：仅当构造期传入 *slog.LevelVar 时生效并返回 true；
// 固定级别返回 false（进入 mebsuta.SetLevel 的 skipped 诚实面）。
func (g LevelGate) Set(level slog.Level) bool {
	if lv, ok := g.Leveler.(*slog.LevelVar); ok {
		lv.Set(level)
		return true
	}
	return false
}
