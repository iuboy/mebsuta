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
