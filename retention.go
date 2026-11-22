// 查询日志保留窗的 Logger 级运行时调整面：遍历 handler 图（unwrap + 多路
// fanout，与 CloseAll 同一访问语义），对每个 FileHandler 内的 filerotate
// Writer 应用 SetMaxAgeDays。公共库能力（运维保留窗热调），wasat 经
// log.query_retention_days 键消费。
package mebsuta

import (
	"fmt"
	"log/slog"
)

// SetFileMaxAge 调整 logger 后全部文件 handler 的按龄清理窗（天；0 = 关闭）。
// 非文件 handler 忽略；无可达文件 handler 不构成错误（stdout 形态等）。
func SetFileMaxAge(l *slog.Logger, days int) error {
	if l == nil {
		return nil
	}
	if days < 0 {
		return fmt.Errorf("MaxAgeDays must be >= 0, got %d", days)
	}
	return walkHandlers(l.Handler(), func(h slog.Handler) error {
		if fh, ok := h.(*FileHandler); ok && fh.writer != nil {
			if err := fh.writer.SetMaxAgeDays(days); err != nil {
				return fmt.Errorf("set max age days: %w", err)
			}
		}
		return nil
	})
}
