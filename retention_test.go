// SetFileMaxAge 单元测试：多路 + 文件 handler 图可达性、stdout-only 无害、
// 负值拒绝。
package mebsuta

import (
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/iuboy/mebsuta/filerotate"
	"github.com/stretchr/testify/require"
)

func TestSetFileMaxAgeReachesFileHandler(t *testing.T) {
	dir := t.TempDir()
	l, err := New(
		UseFile(filerotate.Config{Path: filepath.Join(dir, "q.log")}, FileConfig{Level: slog.LevelInfo, Format: "json"}),
		UseStdout(StdoutConfig{Level: slog.LevelInfo, Format: "json"}),
	)
	require.NoError(t, err)
	require.NoError(t, SetFileMaxAge(l, 7), "SetFileMaxAge")
	// 图内文件 handler 的 writer 保留窗已改（in-package 可达性断言）。
	h := l.Handler()
	sm, ok := h.(*safeMulti)
	require.True(t, ok, "handler 形态 %T", h)
	for _, hh := range sm.handlers {
		if fh, ok := hh.(*FileHandler); ok {
			require.Equal(t, 7, fh.writer.MaxAgeDays(), "MaxAgeDays")
			return
		}
	}
	require.FailNow(t, "图内未找到 FileHandler")
}

func TestSetFileMaxAgeStdoutOnlyAndNegative(t *testing.T) {
	l, err := New(UseStdout(StdoutConfig{}))
	require.NoError(t, err)
	require.NoError(t, SetFileMaxAge(l, 3), "stdout-only 应无害")
	require.Error(t, SetFileMaxAge(l, 0), "0 应拒绝(构造期 0 是默认 30 天;关闭用 UnlimitedAge)")
	require.Error(t, SetFileMaxAge(l, -2), "其他负值应拒绝")
	require.NoError(t, SetFileMaxAge(nil, 3), "nil logger 应无害")
}
