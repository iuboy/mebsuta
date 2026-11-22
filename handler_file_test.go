package mebsuta

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/iuboy/mebsuta/filerotate"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// 辅助函数
// =============================================================================

func newTestFileHandler(t *testing.T, cfgOverrides ...func(*FileConfig)) (*FileHandler, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")
	fc := FileConfig{}
	for _, o := range cfgOverrides {
		o(&fc)
	}
	h, err := NewFileHandler(filerotate.Config{Path: path}, fc)
	require.NoError(t, err, "NewFileHandler")
	return h, path
}

func withFormat(f string) func(*FileConfig) {
	return func(c *FileConfig) { c.Format = f }
}

func readLogFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err, "read %s", path)
	return data
}

func assertRestrictedLogFileMode(t *testing.T, path string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file permissions are not meaningful on Windows")
	}
	info, err := os.Stat(path)
	require.NoError(t, err, "stat %s", path)
	require.Equal(t, filerotate.DefaultFileMode, info.Mode().Perm(), "log file mode")
}

// =============================================================================
// 基础功能测试
// =============================================================================

func TestFileHandler_JSONFormat(t *testing.T) {
	h, path := newTestFileHandler(t, withFormat("json"))
	defer func() { _ = h.Close() }()

	logger := slog.New(h)
	logger.Info("hello", "key", "value")

	data := readLogFile(t, path)
	var result map[string]any
	require.NoError(t, json.Unmarshal(data, &result), "invalid JSON: %s", string(data))
	require.Equal(t, "hello", result["message"], "message")
	attrs, ok := result["attributes"].(map[string]any)
	require.True(t, ok, "attributes missing or invalid: %v", result["attributes"])
	require.Equal(t, "value", attrs["key"], "attributes.key")
	require.Equal(t, "INFO", result["level"], "level")
}

func TestFileHandler_JSONFormat_NonFiniteFloats(t *testing.T) {
	h, path := newTestFileHandler(t, withFormat("json"))
	defer func() { _ = h.Close() }()

	logger := slog.New(h)
	logger.Info("floats", "nan", math.NaN(), "pos_inf", math.Inf(1), "neg_inf", math.Inf(-1))

	data := readLogFile(t, path)
	var result map[string]any
	require.NoError(t, json.Unmarshal(data, &result), "invalid JSON for non-finite floats: %s", string(data))
	for _, key := range []string{"nan", "pos_inf", "neg_inf"} {
		attrs, ok := result["attributes"].(map[string]any)
		require.True(t, ok, "attributes missing from JSON output: %s", string(data))
		require.Contains(t, attrs, key, "JSON output: %s", string(data))
	}
}

func TestFileHandler_ConsoleFormat(t *testing.T) {
	h, path := newTestFileHandler(t, withFormat("console"))
	defer func() { _ = h.Close() }()

	logger := slog.New(h)
	logger.Info("hello", "key", "value")

	data := readLogFile(t, path)
	output := string(data)
	require.Contains(t, output, "hello")
	require.Contains(t, output, "key=value")
}

func TestFileHandler_DefaultFormat(t *testing.T) {
	h, path := newTestFileHandler(t)
	defer func() { _ = h.Close() }()

	logger := slog.New(h)
	logger.Info("test")

	data := readLogFile(t, path)
	var result map[string]any
	require.NoError(t, json.Unmarshal(data, &result), "expected JSON output for default format, got: %s", string(data))
}

func TestFileHandler_FilePermissionsRestricted(t *testing.T) {
	h, path := newTestFileHandler(t)
	defer func() { _ = h.Close() }()

	assertRestrictedLogFileMode(t, path)
}

// =============================================================================
// Level 过滤
// =============================================================================

func TestFileHandler_LevelFilter(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")
	h, err := NewFileHandler(filerotate.Config{Path: path}, FileConfig{Format: "json", Level: slog.LevelWarn})
	require.NoError(t, err, "NewFileHandler")
	defer func() { _ = h.Close() }()

	logger := slog.New(h)
	logger.Info("should be filtered")

	data := readLogFile(t, path)
	require.Empty(t, data, "Info should be filtered at Warn level")

	logger.Warn("should pass")
	data = readLogFile(t, path)
	require.NotEmpty(t, data, "Warn should pass at Warn level")
}

// =============================================================================
// WithAttrs / WithGroup
// =============================================================================

func TestFileHandler_WithAttrs(t *testing.T) {
	h, path := newTestFileHandler(t, withFormat("json"))
	defer func() { _ = h.Close() }()

	child := h.WithAttrs([]slog.Attr{slog.String("preset", "value")})
	logger := slog.New(child)
	logger.Info("test")

	data := readLogFile(t, path)
	var result map[string]any
	require.NoError(t, json.Unmarshal(data, &result), "invalid JSON")
	attrs := result["attributes"].(map[string]any)
	require.Equal(t, "value", attrs["preset"], "attributes.preset")
}

func TestFileHandler_WithGroup(t *testing.T) {
	h, path := newTestFileHandler(t, withFormat("json"))
	defer func() { _ = h.Close() }()

	child := h.WithGroup("request")
	logger := slog.New(child)
	logger.Info("test", "id", "123")

	data := readLogFile(t, path)
	var result map[string]any
	require.NoError(t, json.Unmarshal(data, &result), "invalid JSON")
	attrs := result["attributes"].(map[string]any)
	require.Equal(t, "123", attrs["request.id"], "attributes[request.id]")
}

// =============================================================================
// 并发写入
// =============================================================================

func TestFileHandler_ConcurrentWrites(t *testing.T) {
	h, path := newTestFileHandler(t, withFormat("json"))
	defer func() { _ = h.Close() }()

	logger := slog.New(h)

	const goroutines = 100
	done := make(chan struct{})

	for i := range goroutines {
		go func(n int) {
			logger.Info("concurrent", "n", n)
			done <- struct{}{}
		}(i)
	}

	for range goroutines {
		<-done
	}

	data := readLogFile(t, path)
	lines := bytes.Count(data, []byte("\n"))
	require.Equal(t, goroutines, lines, "expected lines")
}

// =============================================================================
// Close
// =============================================================================

func TestFileHandler_Close(t *testing.T) {
	h, _ := newTestFileHandler(t, withFormat("json"))

	require.NoError(t, h.Close(), "Close() error")
	require.NoError(t, h.Close(), "double Close() error")

	// Close 后写入应该是 nop
	logger := slog.New(h)
	logger.Info("after close")
	// 不应该 panic
}

// =============================================================================
// NewFileHandler 错误
// =============================================================================

func TestNewFileHandler_EmptyPath(t *testing.T) {
	_, err := NewFileHandler(filerotate.Config{Path: ""}, FileConfig{})
	require.Error(t, err, "expected error for empty path")
	require.Contains(t, err.Error(), "file path is required", "error should mention path required")
}

func TestNewFileHandler_InvalidDirectory(t *testing.T) {
	_, err := NewFileHandler(filerotate.Config{Path: "/proc/nonexistent/test.log"}, FileConfig{})
	require.Error(t, err, "expected error for invalid directory")
}

// =============================================================================
// WithAttrs 子 Handler 共享文件
// =============================================================================

func TestFileHandler_WithAttrsSharedState(t *testing.T) {
	h, path := newTestFileHandler(t, withFormat("json"))
	defer func() { _ = h.Close() }()

	child1 := h.WithAttrs([]slog.Attr{slog.String("source", "handler1")})
	child2 := h.WithAttrs([]slog.Attr{slog.String("source", "handler2")})

	logger1 := slog.New(child1)
	logger2 := slog.New(child2)

	logger1.Info("from handler1")
	logger2.Info("from handler2")

	data := readLogFile(t, path)
	lines := bytes.Count(data, []byte("\n"))
	require.Equal(t, 2, lines, "expected 2 lines")
}

// =============================================================================
// Enabled 继承 levelHandler
// =============================================================================

func TestFileHandler_Enabled(t *testing.T) {
	h, _ := newTestFileHandler(t)
	defer func() { _ = h.Close() }()

	require.False(t, h.Enabled(context.Background(), slog.LevelDebug), "Debug should not be enabled at Warn level")
	require.True(t, h.Enabled(context.Background(), slog.LevelError), "Error should be enabled at Warn level")
}
