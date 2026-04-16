package mebsuta

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/iuboy/mebsuta/config"
)

// =============================================================================
// 辅助函数
// =============================================================================

func newTestFileHandler(t *testing.T, cfg config.FileConfig, level slog.Level) (*FileHandler, string) {
	t.Helper()
	dir := t.TempDir()
	cfg.Path = filepath.Join(dir, "test.log")
	h, err := NewFileHandler(cfg, level)
	if err != nil {
		t.Fatalf("NewFileHandler: %v", err)
	}
	return h, cfg.Path
}

func readLogFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return data
}

// =============================================================================
// 基础功能测试
// =============================================================================

func TestFileHandler_JSONFormat(t *testing.T) {
	h, path := newTestFileHandler(t, config.FileConfig{Format: string(JSON)}, slog.LevelInfo)
	defer h.Close()

	logger := slog.New(h)
	logger.Info("hello", "key", "value")

	data := readLogFile(t, path)
	var result map[string]any
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("invalid JSON: %v, got: %s", err, string(data))
	}
	if result["msg"] != "hello" {
		t.Errorf("msg = %v, want hello", result["msg"])
	}
	if result["key"] != "value" {
		t.Errorf("key = %v, want value", result["key"])
	}
	if result["level"] != "INFO" {
		t.Errorf("level = %v, want INFO", result["level"])
	}
}

func TestFileHandler_ConsoleFormat(t *testing.T) {
	h, path := newTestFileHandler(t, config.FileConfig{Format: string(Console)}, slog.LevelInfo)
	defer h.Close()

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
	// 空 Format 默认为 JSON
	h, path := newTestFileHandler(t, config.FileConfig{}, slog.LevelInfo)
	defer h.Close()

	logger := slog.New(h)
	logger.Info("test")

	data := readLogFile(t, path)
	var result map[string]any
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("expected JSON output for default format, got: %s", string(data))
	}
}

// =============================================================================
// Level 过滤
// =============================================================================

func TestFileHandler_LevelFilter(t *testing.T) {
	h, path := newTestFileHandler(t, config.FileConfig{Format: string(JSON)}, slog.LevelWarn)
	defer h.Close()

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
	h, path := newTestFileHandler(t, config.FileConfig{Format: string(JSON)}, slog.LevelInfo)
	defer h.Close()

	child := h.WithAttrs([]slog.Attr{slog.String("preset", "value")})
	logger := slog.New(child)
	logger.Info("test")

	data := readLogFile(t, path)
	var result map[string]any
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if result["preset"] != "value" {
		t.Errorf("preset = %v, want value", result["preset"])
	}
}

func TestFileHandler_WithGroup(t *testing.T) {
	h, path := newTestFileHandler(t, config.FileConfig{Format: string(JSON)}, slog.LevelInfo)
	defer h.Close()

	child := h.WithGroup("request")
	logger := slog.New(child)
	logger.Info("test", "id", "123")

	data := readLogFile(t, path)
	var result map[string]any
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	req, ok := result["request"].(map[string]any)
	if !ok {
		t.Fatalf("request should be a group, got: %v", result["request"])
	}
	if req["id"] != "123" {
		t.Errorf("request.id = %v, want 123", req["id"])
	}
}

// =============================================================================
// 并发写入
// =============================================================================

func TestFileHandler_ConcurrentWrites(t *testing.T) {
	h, path := newTestFileHandler(t, config.FileConfig{Format: string(JSON)}, slog.LevelInfo)
	defer h.Close()

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
	h, _ := newTestFileHandler(t, config.FileConfig{Format: string(JSON)}, slog.LevelInfo)

	if err := h.Close(); err != nil {
		t.Errorf("Close() error: %v", err)
	}

	// 双重 Close 应该是 nop
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
	_, err := NewFileHandler(config.FileConfig{}, slog.LevelInfo)
	if err == nil {
		t.Fatal("expected error for empty path")
	}
	if !strings.Contains(err.Error(), "file path is required") {
		t.Errorf("error should mention path required, got: %v", err)
	}
}

func TestNewFileHandler_InvalidDirectory(t *testing.T) {
	_, err := NewFileHandler(config.FileConfig{Path: "/proc/nonexistent/test.log"}, slog.LevelInfo)
	if err == nil {
		t.Fatal("expected error for invalid directory")
	}
}

// =============================================================================
// 大小轮转
// =============================================================================

func TestFileHandler_SizeRotation(t *testing.T) {
	// MaxSizeMB = 1 字节大小（最小单位测试）
	h, path := newTestFileHandler(t, config.FileConfig{
		MaxSizeMB: 1, // 1 MB
		Format:    string(JSON),
	}, slog.LevelInfo)
	defer h.Close()

	logger := slog.New(h)

	// 写入足够多的数据触发轮转（1MB）
	msg := strings.Repeat("x", 1024) // 1KB per message
	for range 1100 {
		logger.Info("fill", "data", msg)
	}

	// 等待轮转完成（大小检查是同步的）
	backups := matchBackups(path)
	if len(backups) == 0 {
		t.Errorf("expected rotation to create backup files, found none")
	}

	// 新文件应该存在
	if _, err := os.Stat(path); err != nil {
		t.Errorf("new log file should exist: %v", err)
	}
}

// =============================================================================
// MaxBackups 清理
// =============================================================================

func TestFileHandler_MaxBackups(t *testing.T) {
	h, path := newTestFileHandler(t, config.FileConfig{
		MaxSizeMB:  1, // 1 MB
		MaxBackups: 2,
		Format:     string(JSON),
	}, slog.LevelInfo)
	defer h.Close()

	logger := slog.New(h)

	// 写入足够多的数据触发多次轮转
	msg := strings.Repeat("x", 1024)
	for range 3300 {
		logger.Info("fill", "data", msg)
	}

	// 等待异步操作
	time.Sleep(100 * time.Millisecond)

	backups := matchBackups(path)
	if len(backups) > 2 {
		t.Errorf("expected at most 2 backups, got %d: %v", len(backups), backups)
	}
}

// =============================================================================
// gzip 压缩
// =============================================================================

func TestFileHandler_Compress(t *testing.T) {
	h, path := newTestFileHandler(t, config.FileConfig{
		MaxSizeMB: 1,
		Compress:  true,
		Format:    string(JSON),
	}, slog.LevelInfo)
	defer h.Close()

	logger := slog.New(h)

	// 写入足够多的数据触发轮转
	msg := strings.Repeat("x", 1024)
	for range 1100 {
		logger.Info("fill", "data", msg)
	}

	// 等待异步压缩完成
	time.Sleep(500 * time.Millisecond)

	backups := matchBackups(path)
	hasGz := false
	for _, b := range backups {
		if strings.HasSuffix(b, ".gz") {
			hasGz = true
			break
		}
	}
	if !hasGz {
		t.Errorf("expected compressed backup (.gz) files, got: %v", backups)
	}
}

// =============================================================================
// 启动时残留文件压缩
// =============================================================================

func TestCompressResidual(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "test.log")

	// 模拟残留的未压缩轮转文件
	backup1 := logPath + ".20260401-000000"
	if err := os.WriteFile(backup1, []byte("old log data\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// 模拟残留的 .gz.tmp 崩溃中间文件
	tmpFile := logPath + ".20260401-000000.gz.tmp"
	if err := os.WriteFile(tmpFile, []byte("partial gzip"), 0644); err != nil {
		t.Fatal(err)
	}

	compressResidual(logPath, true)

	// 等待异步压缩
	time.Sleep(200 * time.Millisecond)

	// .tmp 文件应该被清理
	if _, err := os.Stat(tmpFile); err == nil {
		t.Error(".tmp file should be cleaned up")
	}

	// 原始备份应该被压缩
	if _, err := os.Stat(backup1 + ".gz"); err != nil {
		t.Errorf("backup should be compressed to .gz: %v", err)
	}
}

// =============================================================================
// compressFile 直接测试
// =============================================================================

func TestCompressFile(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "source.txt")
	gzPath := src + ".gz"

	// 创建源文件
	content := strings.Repeat("log line\n", 1000)
	if err := os.WriteFile(src, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	compressFile(src, DefaultErrorHandler)

	// 压缩文件应该存在
	if _, err := os.Stat(gzPath); err != nil {
		t.Fatal("compressed file should exist")
	}

	// 原始文件应该被删除
	if _, err := os.Stat(src); err == nil {
		t.Error("original file should be removed after compression")
	}

	// 压缩文件应该比原始文件小
	gzInfo, _ := os.Stat(gzPath)
	if gzInfo == nil {
		t.Fatal("cannot stat compressed file")
	}
	if gzInfo.Size() >= int64(len(content)) {
		t.Errorf("compressed file (%d) should be smaller than original (%d)", gzInfo.Size(), len(content))
	}
}

// =============================================================================
// WithAttrs 子 Handler 共享文件
// =============================================================================

func TestFileHandler_WithAttrsSharedState(t *testing.T) {
	h, path := newTestFileHandler(t, config.FileConfig{Format: string(JSON)}, slog.LevelInfo)
	defer h.Close()

	// 创建两个子 Handler
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
	h, _ := newTestFileHandler(t, config.FileConfig{}, slog.LevelWarn)
	defer h.Close()

	if h.Enabled(context.Background(), slog.LevelDebug) {
		t.Error("Debug should not be enabled at Warn level")
	}
	if !h.Enabled(context.Background(), slog.LevelError) {
		t.Error("Error should be enabled at Warn level")
	}
}
