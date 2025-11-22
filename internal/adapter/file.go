package adapter

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/iuboy/mebsuta/config"
	"github.com/iuboy/mebsuta/core"
	"github.com/natefinch/lumberjack"
)

type fileAdapter struct {
	lj     *lumberjack.Logger
	mu     sync.RWMutex
	closed atomic.Bool
}

// type FileOption func(*lumberjack.Logger)

func newFileAdapter(config config.FileConfig) (core.WriteSyncer, error) {
	if config.Path == "" {
		return nil, fmt.Errorf("文件路径不能为空")
	}

	if err := os.MkdirAll(filepath.Dir(config.Path), 0755); err != nil {
		return nil, err
	}

	if config.RotateOnStartup {
		if err := rotateLogFileOnStartup(config.Path); err != nil {
			return nil, err
		}
	}

	fa := &fileAdapter{
		lj: &lumberjack.Logger{
			Filename:   config.Path,
			MaxSize:    config.MaxSizeMB,
			MaxBackups: config.MaxBackups,
			MaxAge:     config.MaxAgeDays,
			Compress:   config.Compress,
			LocalTime:  config.LocalTime,
		},
	}

	return fa, nil
}

func (f *fileAdapter) Write(p []byte) (n int, err error) {
	if f.closed.Load() {
		return 0, os.ErrClosed
	}
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.lj.Write(p)
}

func (f *fileAdapter) Sync() error {
	// Lumberjack已经在Write时刷新，无需额外操作
	return nil
}
func (f *fileAdapter) Close() error {
	if f.closed.Swap(true) {
		return nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()

	if err := f.lj.Close(); err != nil {
		return fmt.Errorf("file close failed: %w", err)
	}
	return nil
}

func rotateLogFileOnStartup(logPath string) error {
	// 检查文件是否存在
	if _, err := os.Stat(logPath); os.IsNotExist(err) {
		// 文件不存在，无需重命名
		return nil
	} else if err != nil {
		// 其他错误
		return fmt.Errorf("检查日志文件状态失败: %w", err)
	}

	// 文件存在，尝试重命名
	backup := fmt.Sprintf("%s.%s", logPath, time.Now().Format("20060102_150405"))

	// 添加重试机制
	var lastErr error
	for i := 0; i < 3; i++ {
		if err := os.Rename(logPath, backup); err != nil {
			// 如果是文件不存在错误，说明可能已被其他进程处理
			if os.IsNotExist(err) {
				return nil
			}
			lastErr = err
			time.Sleep(time.Millisecond * 100 * time.Duration(i+1))
			continue
		}
		return nil
	}

	return fmt.Errorf("日志重命名失败（已重试）: %w", lastErr)
}
