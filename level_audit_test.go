package mebsuta

import (
	"log/slog"
	"testing"

	"github.com/iuboy/mebsuta/audit"
	"github.com/stretchr/testify/require"
)

func TestLevelAudit_MatchesAuditPackage(t *testing.T) {
	require.Equal(t, LevelAudit, audit.LevelAudit,
		"mebsuta.LevelAudit must match audit.LevelAudit")
}

func TestLevelAudit_AboveError(t *testing.T) {
	require.True(t, LevelAudit >= slog.LevelError,
		"LevelAudit must be >= LevelError so handlers at Error level accept Audit records")
}
