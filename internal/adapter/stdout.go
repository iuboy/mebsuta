package adapter

import (
	"io"
	"os"

	"github.com/iuboy/mebsuta/core"
	"go.uber.org/zap/zapcore"
)

type stdoutAdapter struct{}

func newStdoutAdapter() (core.WriteSyncer, error) {
	if os.Stdout == nil {
		return nil, os.ErrInvalid
	}

	adapter := &stdoutAdapter{}
	return struct {
		zapcore.WriteSyncer
		io.Closer
	}{
		// 使用Lock代替AddSync，确保日志立即刷新
		// Lock会在每次Write后自动Sync，保证日志不丢失
		WriteSyncer: zapcore.Lock(adapter),
		Closer:      adapter,
	}, nil
}

func (s stdoutAdapter) Write(p []byte) (n int, err error) {
	return os.Stdout.Write(p)
}
func (s *stdoutAdapter) Sync() error {
	return os.Stdout.Sync()
}

func (s *stdoutAdapter) Close() error {
	// 标准输出不应该被关闭
	// 返回 nil 表示成功关闭（无操作）
	return nil
}
