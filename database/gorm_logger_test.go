//go:build unix

package database

// Tests for the gorm-logger silencing decision (newGORMConfig).
//
// gorm's default logger captures os.Stdout's file descriptor at gorm package
// init, so intercepting its output requires duplicating file descriptors at
// the OS level — swapping the os.Stdout variable would NOT intercept it. The
// tests therefore redirect fd 1 into a pipe around the observed writes, and
// are unix-only because of syscall.Dup.

import (
	"bytes"
	"io"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// captureFD1 redirects file descriptor 1 into a pipe for the duration of fn
// and returns everything written to it.
func captureFD1(t *testing.T, fn func()) string {
	t.Helper()

	pipeR, pipeW, err := os.Pipe()
	require.NoError(t, err)

	saved, err := syscall.Dup(1)
	require.NoError(t, err)

	// Make fd 1 point at the pipe write end, then drop the original handle
	// so fd 1 holds the only reference to the write end.
	require.NoError(t, syscall.Close(1))
	if _, err := syscall.Dup(int(pipeW.Fd())); err != nil {
		// Best-effort restore before failing the test.
		_, _ = syscall.Dup(saved)
		_ = syscall.Close(saved)
		_ = pipeR.Close()
		_ = pipeW.Close()
		t.Fatalf("dup pipe onto stdout: %v", err)
	}
	_ = pipeW.Close()

	fn()

	// Restore the real stdout before draining the pipe: closing fd 1 and
	// duplicating saved over it releases the last write-end reference, so
	// the read below hits EOF instead of blocking forever.
	require.NoError(t, syscall.Close(1))
	_, err = syscall.Dup(saved)
	require.NoError(t, err)
	require.NoError(t, syscall.Close(saved))

	var out bytes.Buffer
	_, err = io.Copy(&out, pipeR)
	require.NoError(t, err)
	require.NoError(t, pipeR.Close())
	return out.String()
}

// TestNewHandler_GormConfigDiscardsLogger pins the silencing decision: every
// gorm session opened through the handler must use logger.Discard.
func TestNewHandler_GormConfigDiscardsLogger(t *testing.T) {
	require.True(t, newGORMConfig().Logger == logger.Discard,
		"newGORMConfig must install gorm's Discard logger: the default logger renders slow/failed statements with all bound values interpolated onto stdout (memory x2 at peak, unredacted sensitive content)")
}

// TestGormConfig_FailedStatementWritesNothingToStdout proves the silencing
// end to end. Control: with gorm's default config, a failed INSERT renders
// the statement and bound values onto fd 1 — this also validates the capture
// mechanism itself. Treatment: with newGORMConfig, nothing is written.
//
// The failure is an execution-time error (missing table). Errors at
// transaction-begin (e.g. "sql: database is closed") short-circuit inside
// gorm's create callback before any SQL is built and never reach the logger,
// so they cannot serve as the trigger here.
func TestGormConfig_FailedStatementWritesNothingToStdout(t *testing.T) {
	run := func(cfg *gorm.Config) string {
		gdb, err := gorm.Open(sqlite.Open(":memory:"), cfg)
		require.NoError(t, err)
		require.NoError(t, gdb.Table("logs").AutoMigrate(&dbLogEntry{}))
		require.NoError(t, gdb.Exec("DROP TABLE logs").Error)

		batch := []dbLogEntry{{
			Time: time.Now(), Level: "INFO", Message: "secret-message",
			Fields: []byte(`{"token":"hunter2"}`),
		}}
		return captureFD1(t, func() {
			_ = gdb.Table("logs").CreateInBatches(batch, 10).Error //nolint:errcheck // the error itself is not under test; only its side effect on stdout is
		})
	}

	control := run(&gorm.Config{})
	require.NotEmpty(t, control,
		"expected gorm's default logger to render the failed statement — the capture mechanism itself is broken otherwise")
	require.Contains(t, control, "hunter2",
		"the default logger interpolates bound values — exactly what the handler must not leak")

	silent := run(newGORMConfig())
	require.Empty(t, silent,
		"newGORMConfig must silence gorm completely: no SQL, no bound values on stdout")
}
