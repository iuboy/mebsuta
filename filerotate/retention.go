// 运行时保留窗调整（wasat 查询日志保留键热更消费面）。
// 语义：仅改 MaxAgeDays——Path / MaxSizeMB / MaxBackups / 压缩位等构造期参数
// 不在运行时面（重建 Writer 涉及文件句柄迁移，属重启域）。
package filerotate

import "fmt"

// SetMaxAgeDays 运行时调整按龄清理窗。语义与构造期一致：
// 正数 = 天数；UnlimitedAge(-1) = 不按时间删除。0 与其他负值拒绝
// ——构造期 0 表示"取默认 30 天"，运行期传 0 想表达"关闭"时应用
// UnlimitedAge，静默两义会埋下"以为关了还在删"的误操作
// （0.1.0-24 起收紧，此前 0 = 关闭）。下次轮转触发的
// cleanupBackupsLocked 按新值执行。
func (w *Writer) SetMaxAgeDays(days int) error {
	if days == 0 {
		return fmt.Errorf("MaxAgeDays must be positive or UnlimitedAge(%d), got 0 (0 selects the 30-day default at construction time; use UnlimitedAge to disable age-based cleanup)", UnlimitedAge)
	}
	if days < UnlimitedAge {
		return fmt.Errorf("MaxAgeDays must be positive or UnlimitedAge(%d), got %d", UnlimitedAge, days)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.cfg.MaxAgeDays = days
	return nil
}

// MaxAgeDays 读当前按龄清理窗（天；UnlimitedAge = 不按时间删除）。
func (w *Writer) MaxAgeDays() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.cfg.MaxAgeDays
}
