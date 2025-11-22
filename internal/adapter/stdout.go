package adapter

import (
	"io"
	"mebsuta/core"
	"os"

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
		WriteSyncer: zapcore.AddSync(adapter),
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
	return os.Stdout.Close()
}
