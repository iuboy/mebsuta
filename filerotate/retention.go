// 运行时保留窗调整（wasat 查询日志保留键热更消费面）。
// 语义：仅改 MaxAgeDays——Path / MaxSizeMB / MaxBackups / 压缩位等构造期参数
// 不在运行时面（重建 Writer 涉及文件句柄迁移，属重启域）。
package filerotate

import "fmt"

// SetMaxAgeDays 运行时调整按龄清理窗（天；0 = 关闭按龄清理，负值非法原值
// 不变）。下次轮转触发的 cleanupBackupsLocked 按新值执行。
func (w *Writer) SetMaxAgeDays(days int) error {
	if days < 0 {
		return fmt.Errorf("MaxAgeDays must be >= 0, got %d", days)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.cfg.MaxAgeDays = days
	return nil
}

// MaxAgeDays 读当前按龄清理窗（天；0 = 关闭）。
func (w *Writer) MaxAgeDays() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.cfg.MaxAgeDays
}
