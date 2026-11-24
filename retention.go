// 查询日志保留窗的 Logger 级运行时调整面：遍历 handler 图（unwrap + 多路
// fanout，与 CloseAll 同一访问语义），对每个 FileHandler 内的 filerotate
// Writer 应用 SetMaxAgeDays。公共库能力（运维保留窗热调），wasat 经
// log.query_retention_days 键消费。
package mebsuta

import (
	"fmt"
	"log/slog"

	"github.com/iuboy/mebsuta/filerotate"
)

// SetFileMaxAge 调整 logger 后全部文件 handler 的按龄清理窗。
// 语义与 filerotate.Writer.SetMaxAgeDays 一致：正数 = 天数，
// filerotate.UnlimitedAge = 不按时间删除；0 与其他负值以错误拒绝。
// 非文件 handler 忽略；无可达文件 handler 不构成错误（stdout 形态等）。
func SetFileMaxAge(h slog.Handler, days int) error {
	if h == nil {
		return nil
	}
	if days <= 0 && days != filerotate.UnlimitedAge {
		return fmt.Errorf("MaxAgeDays must be positive or filerotate.UnlimitedAge(%d), got %d", filerotate.UnlimitedAge, days)
	}
	return walkHandlers(h, func(fh slog.Handler) error {
		if fh, ok := fh.(*FileHandler); ok && fh.writer != nil {
			if err := fh.writer.SetMaxAgeDays(days); err != nil {
				return fmt.Errorf("set max age days: %w", err)
			}
		}
		return nil
	})
}
