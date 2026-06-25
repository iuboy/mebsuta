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
	"strings"
	"testing"

	"github.com/iuboy/mebsuta/filerotate"
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
	if err != nil {
		t.Fatalf("NewFileHandler: %v", err)
	}
	return h, path
}

func withFormat(f string) func(*FileConfig) {
	return func(c *FileConfig) { c.Format = f }
}

func readLogFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return data
}

func assertRestrictedLogFileMode(t *testing.T, path string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file permissions are not meaningful on Windows")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if got := info.Mode().Perm(); got != filerotate.DefaultFileMode {
		t.Fatalf("log file mode = %v, want %v", got, filerotate.DefaultFileMode)
	}
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
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("invalid JSON: %v, got: %s", err, string(data))
	}
	if result["message"] != "hello" {
		t.Errorf("message = %v, want hello", result["message"])
	}
	attrs, ok := result["attributes"].(map[string]any)
	if !ok {
		t.Fatalf("attributes missing or invalid: %v", result["attributes"])
	}
	if attrs["key"] != "value" {
		t.Errorf("attributes.key = %v, want value", attrs["key"])
	}
	if result["level"] != "INFO" {
		t.Errorf("level = %v, want INFO", result["level"])
	}
}

func TestFileHandler_JSONFormat_NonFiniteFloats(t *testing.T) {
	h, path := newTestFileHandler(t, withFormat("json"))
	defer func() { _ = h.Close() }()

	logger := slog.New(h)
	logger.Info("floats", "nan", math.NaN(), "pos_inf", math.Inf(1), "neg_inf", math.Inf(-1))

	data := readLogFile(t, path)
	var result map[string]any
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("invalid JSON for non-finite floats: %v, got: %s", err, string(data))
	}
	for _, key := range []string{"nan", "pos_inf", "neg_inf"} {
		attrs, ok := result["attributes"].(map[string]any)
		if !ok {
			t.Fatalf("attributes missing from JSON output: %s", string(data))
		}
		if _, ok := attrs[key]; !ok {
			t.Fatalf("%s missing from JSON output: %s", key, string(data))
		}
	}
}

func TestFileHandler_ConsoleFormat(t *testing.T) {
	h, path := newTestFileHandler(t, withFormat("console"))
	defer func() { _ = h.Close() }()

	logger := slog.New(h)
	logger.Info("hello", "key", "value")

	data := readLogFile(t, path)
	output := string(data)
	if !strings.Contains(output, "hello") {
		t.Errorf("output should contain 'hello', got: %s", output)
	}
	if !strings.Contains(output, "key=value") {
		t.Errorf("output should contain 'key=value', got: %s", output)
	}
}

func TestFileHandler_DefaultFormat(t *testing.T) {
	h, path := newTestFileHandler(t)
	defer func() { _ = h.Close() }()

	logger := slog.New(h)
	logger.Info("test")

	data := readLogFile(t, path)
	var result map[string]any
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("expected JSON output for default format, got: %s", string(data))
	}
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
	if err != nil {
		t.Fatalf("NewFileHandler: %v", err)
	}
	defer func() { _ = h.Close() }()

	logger := slog.New(h)
	logger.Info("should be filtered")

	data := readLogFile(t, path)
	if len(data) > 0 {
		t.Errorf("Info should be filtered at Warn level, got: %s", string(data))
	}

	logger.Warn("should pass")
	data = readLogFile(t, path)
	if len(data) == 0 {
		t.Error("Warn should pass at Warn level")
	}
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
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	attrs := result["attributes"].(map[string]any)
	if attrs["preset"] != "value" {
		t.Errorf("attributes.preset = %v, want value", attrs["preset"])
	}
}

func TestFileHandler_WithGroup(t *testing.T) {
	h, path := newTestFileHandler(t, withFormat("json"))
	defer func() { _ = h.Close() }()

	child := h.WithGroup("request")
	logger := slog.New(child)
	logger.Info("test", "id", "123")

	data := readLogFile(t, path)
	var result map[string]any
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	attrs := result["attributes"].(map[string]any)
	if attrs["request.id"] != "123" {
		t.Errorf("attributes[request.id] = %v, want 123", attrs["request.id"])
	}
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
	if lines != goroutines {
		t.Errorf("expected %d lines, got %d", goroutines, lines)
	}
}

// =============================================================================
// Close
// =============================================================================

func TestFileHandler_Close(t *testing.T) {
	h, _ := newTestFileHandler(t, withFormat("json"))

	if err := h.Close(); err != nil {
		t.Errorf("Close() error: %v", err)
	}

	if err := h.Close(); err != nil {
		t.Errorf("double Close() error: %v", err)
	}

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
	if err == nil {
		t.Fatal("expected error for empty path")
	}
	if !strings.Contains(err.Error(), "file path is required") {
		t.Errorf("error should mention path required, got: %v", err)
	}
}

func TestNewFileHandler_InvalidDirectory(t *testing.T) {
	_, err := NewFileHandler(filerotate.Config{Path: "/proc/nonexistent/test.log"}, FileConfig{})
	if err == nil {
		t.Fatal("expected error for invalid directory")
	}
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
	if lines != 2 {
		t.Errorf("expected 2 lines, got %d", lines)
	}
}

// =============================================================================
// Enabled 继承 levelHandler
// =============================================================================

func TestFileHandler_Enabled(t *testing.T) {
	h, _ := newTestFileHandler(t)
	defer func() { _ = h.Close() }()

	if h.Enabled(context.Background(), slog.LevelDebug) {
		t.Error("Debug should not be enabled at Warn level")
	}
	if !h.Enabled(context.Background(), slog.LevelError) {
		t.Error("Error should be enabled at Warn level")
	}
}
