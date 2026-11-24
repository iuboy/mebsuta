package mebsuta

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSeverityNumber(t *testing.T) {
	cases := []struct {
		level slog.Level
		want  int
	}{
		// slog base levels land on their OTel band bases.
		{slog.LevelDebug, 5},
		{slog.LevelInfo, 9},
		{slog.LevelWarn, 13},
		{slog.LevelError, 17},
		// LevelAudit sits above Error and maps into the fatal band.
		{LevelAudit, 21},
		// Custom levels stay in their band, including band edges.
		{slog.LevelDebug - 4, 5},  // below Debug clamps to the debug band
		{slog.LevelDebug + 3, 5},  // just under Info
		{slog.LevelInfo + 3, 9},   // just under Warn
		{slog.LevelWarn + 3, 13},  // just under Error
		{slog.LevelError + 3, 17}, // just under LevelAudit
		{LevelAudit + 4, 21},      // anything at or above audit stays fatal
	}
	for _, tc := range cases {
		got := SeverityNumber(tc.level)
		require.Equal(t, tc.want, got, "SeverityNumber(%v)", tc.level)
	}
}

// TestLevelName:文本渲染的唯一规范映射(B7)——AUDIT 渲染为 "AUDIT"
// 而非 slog 数值形式 "ERROR+4"(此前 console 与 OTLP severity text
// 各自内联处理或漏掉)。
func TestLevelName(t *testing.T) {
	require.Equal(t, "AUDIT", LevelName(LevelAudit))
	require.Equal(t, "ERROR", LevelName(slog.LevelError))
	require.Equal(t, "WARN", LevelName(slog.LevelWarn))
	require.Equal(t, "INFO", LevelName(slog.LevelInfo))
	require.Equal(t, "DEBUG", LevelName(slog.LevelDebug))
	// 其他自定义级别维持 slog 数值渲染(只有 AUDIT 是契约级名称)。
	require.Equal(t, "ERROR+2", LevelName(slog.LevelError+2))
}
