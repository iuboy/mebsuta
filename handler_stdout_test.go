package mebsuta

import (
	"bytes"
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestStdoutHandler_ConsoleAuditLevel:console(TextHandler)输出下
// AUDIT 渲染为规范文本而非 "ERROR+4"(B7)。
func TestStdoutHandler_ConsoleAuditLevel(t *testing.T) {
	var buf bytes.Buffer
	h, err := newStdoutHandlerWithWriter(&buf, StdoutConfig{Format: "console"})
	require.NoError(t, err)

	r := slog.NewRecord(time.Now(), LevelAudit, "config reloaded", 0)
	require.NoError(t, h.Handle(context.Background(), r))
	require.Contains(t, buf.String(), "level=AUDIT", "console renders AUDIT as a named level")
	require.NotContains(t, buf.String(), "ERROR+4", "numeric slog rendering must not leak")
}
