package mebsuta

import (
	"context"
	"log/slog"
	"sync"
	"testing"

	"github.com/iuboy/mebsuta/filerotate"
	"github.com/stretchr/testify/require"
)

// TestFileHandler_DynamicLevel verifies that modifying a *slog.LevelVar at runtime
// is immediately reflected in FileHandler.Enabled().
func TestFileHandler_DynamicLevel(t *testing.T) {
	lv := &slog.LevelVar{}
	lv.Set(slog.LevelInfo)

	h, err := NewFileHandler(filerotate.Config{Path: t.TempDir() + "/test.log"}, FileConfig{Level: lv})
	require.NoError(t, err)
	defer func() { _ = h.Close() }()

	// At Info: Debug disabled, Info enabled
	require.False(t, h.Enabled(context.Background(), slog.LevelDebug))
	require.True(t, h.Enabled(context.Background(), slog.LevelInfo))

	// Change to Debug at runtime
	lv.Set(slog.LevelDebug)
	require.True(t, h.Enabled(context.Background(), slog.LevelDebug))

	// Change to Error at runtime
	lv.Set(slog.LevelError)
	require.False(t, h.Enabled(context.Background(), slog.LevelInfo))
	require.True(t, h.Enabled(context.Background(), slog.LevelError))
	require.True(t, h.Enabled(context.Background(), slog.LevelError+4))
}

// TestStdoutHandler_DynamicLevel verifies dynamic level for StdoutHandler.
func TestStdoutHandler_DynamicLevel(t *testing.T) {
	lv := &slog.LevelVar{}
	lv.Set(slog.LevelWarn)

	h, err := NewStdoutHandler(StdoutConfig{Level: lv})
	require.NoError(t, err)

	require.False(t, h.Enabled(context.Background(), slog.LevelInfo))
	require.True(t, h.Enabled(context.Background(), slog.LevelWarn))

	lv.Set(slog.LevelDebug)
	require.True(t, h.Enabled(context.Background(), slog.LevelInfo))
}

// TestLevelVar_ConcurrentReadWrite verifies that concurrent reads and writes
// to *slog.LevelVar are safe (no data races).
func TestLevelVar_ConcurrentReadWrite(t *testing.T) {
	lv := &slog.LevelVar{}
	lv.Set(slog.LevelInfo)

	h, err := NewFileHandler(filerotate.Config{Path: t.TempDir() + "/test.log"}, FileConfig{Level: lv})
	require.NoError(t, err)
	defer func() { _ = h.Close() }()

	var wg sync.WaitGroup
	ctx := context.Background()

	// Writer goroutine: cycles through levels
	wg.Add(1)
	go func() {
		defer wg.Done()
		for range 1000 {
			lv.Set(slog.LevelDebug)
			lv.Set(slog.LevelInfo)
			lv.Set(slog.LevelWarn)
			lv.Set(slog.LevelError)
		}
	}()

	// Reader goroutines: check Enabled
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 1000 {
				_ = h.Enabled(ctx, slog.LevelInfo)
				_ = h.Enabled(ctx, slog.LevelWarn)
			}
		}()
	}

	wg.Wait()
	// No assert needed — this test is for the race detector.
}
