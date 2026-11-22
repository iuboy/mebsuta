package handlerkit

import "log/slog"

// IsNilLeveler 检查 l 是否为 nil 接口或持有 nil 指针，
// 两种情况在调用 l.Level() 时都会 panic。
func IsNilLeveler(l slog.Leveler) bool {
	if l == nil {
		return true
	}
	// 检测接口中存储的类型化 nil 指针。slog.Level 和 slog.LevelVar 都
	// 通过指针接收者实现 Leveler；nil 的 *slog.Level 或 *slog.LevelVar
	// 传入接口后接口非 nil（持有类型信息），但调用 l.Level() 会解引用
	// nil 并 panic。
	if lv, ok := l.(*slog.Level); ok && lv == nil {
		return true
	}
	if lv, ok := l.(*slog.LevelVar); ok && lv == nil {
		return true
	}
	return false
}

// SafeLevel 防御性地调用 l.Level()。若 l 为 nil 或持有 nil 指针
// （如 Leveler 接口中存储的 (*slog.Level)(nil) 或 (*slog.LevelVar)(nil)），
// 返回 slog.LevelInfo 作为安全默认值而非 panic。
func SafeLevel(l slog.Leveler) slog.Level {
	if IsNilLeveler(l) {
		return slog.LevelInfo
	}
	return l.Level()
}
