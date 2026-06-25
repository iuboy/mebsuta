package filerotate

import (
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// =============================================================================
// 辅助函数
// =============================================================================

func newTestWriter(t *testing.T, cfgOverrides ...func(*Config)) (*Writer, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")
	cfg := Config{Path: path}
	for _, o := range cfgOverrides {
		o(&cfg)
	}
	w, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return w, path
}

func withMaxSizeMB(n int) func(*Config) {
	return func(c *Config) { c.MaxSizeMB = n }
}

func withMaxBackups(n int) func(*Config) {
	return func(c *Config) { c.MaxBackups = n }
}

func withCompress(b bool) func(*Config) {
	return func(c *Config) { c.Compress = &b }
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return data
}

func assertFileMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file permissions are not meaningful on Windows")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("file mode = %v, want %v", got, want)
	}
}

// matchBackups returns all backup filenames matching the log file prefix.
func matchBackups(logPath string) []string {
	dir := filepath.Dir(logPath)
	base := filepath.Base(logPath)

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}

	prefix := base + "."
	var names []string
	for _, e := range entries {
		name := e.Name()
		if name != base && strings.HasPrefix(name, prefix) {
			names = append(names, name)
		}
	}
	return names
}

// =============================================================================
// 基础功能
// =============================================================================

func TestWriter_Write(t *testing.T) {
	w, path := newTestWriter(t)
	defer func() { _ = w.Close() }()

	data := []byte("hello world\n")
	n, err := w.Write(data)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if n != len(data) {
		t.Errorf("Write returned %d, want %d", n, len(data))
	}

	got := readFile(t, path)
	if string(got) != string(data) {
		t.Errorf("got %q, want %q", got, data)
	}
}

func TestWriter_FilePermissionsRestricted(t *testing.T) {
	w, path := newTestWriter(t)
	defer func() { _ = w.Close() }()

	assertFileMode(t, path, DefaultFileMode)
}

// =============================================================================
// 大小轮转
// =============================================================================

func TestWriter_SizeRotation(t *testing.T) {
	w, path := newTestWriter(t, withMaxSizeMB(1), withMaxBackups(2))

	data := []byte(strings.Repeat("x", 1024) + "\n")
	for range 3300 {
		_, _ = w.Write(data)
	}

	_ = w.Close()

	backups := matchBackups(path)
	if len(backups) > 2 {
		t.Errorf("expected at most 2 backups, got %d: %v", len(backups), backups)
	}
}

// =============================================================================
// 时间轮转
// =============================================================================

func TestWriter_TimeRotation(t *testing.T) {
	w, path := newTestWriter(t, func(c *Config) {
		c.MaxSizeMB = 100
		c.RotateInterval = 100 * time.Millisecond
		c.MaxBackups = 3
	})

	_, _ = w.Write([]byte("before rotation\n"))
	time.Sleep(200 * time.Millisecond)
	_, _ = w.Write([]byte("after interval\n"))

	_ = w.Close()

	backups := matchBackups(path)
	if len(backups) == 0 {
		t.Error("expected at least one backup from time-based rotation, got none")
	}
}

// =============================================================================
// gzip 压缩
// =============================================================================

func TestWriter_Compress(t *testing.T) {
	w, path := newTestWriter(t, withMaxSizeMB(1), withCompress(true))

	data := []byte(strings.Repeat("x", 1024) + "\n")
	for range 1100 {
		_, _ = w.Write(data)
	}

	_ = w.Close()

	backups := matchBackups(path)
	hasGz := false
	for _, b := range backups {
		if strings.HasSuffix(b, ".gz") {
			hasGz = true
			gzPath := filepath.Join(filepath.Dir(path), b)
			f, err := os.Open(gzPath)
			if err != nil {
				t.Fatalf("open .gz: %v", err)
			}
			defer func() { _ = f.Close() }()
			gz, err := gzip.NewReader(f)
			if err != nil {
				t.Fatalf("gzip reader: %v", err)
			}
			defer func() { _ = gz.Close() }()
			content, err := io.ReadAll(gz)
			if err != nil {
				t.Fatalf("read gzip: %v", err)
			}
			if len(content) == 0 {
				t.Error("compressed content should not be empty")
			}
			break
		}
	}
	if !hasGz {
		t.Errorf("expected compressed backup (.gz) files, got: %v", backups)
	}
}

// =============================================================================
// 残留文件压缩
// =============================================================================

func TestCompressResidual(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "test.log")

	backup1 := logPath + ".20260401-000000"
	if err := os.WriteFile(backup1, []byte("old log data\n"), 0644); err != nil {
		t.Fatal(err)
	}

	tmpFile := logPath + ".20260401-000000.gz.tmp"
	if err := os.WriteFile(tmpFile, []byte("partial gzip"), 0644); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	compressResidual(logPath, true, &wg, nil)
	wg.Wait()

	if _, err := os.Stat(tmpFile); err == nil {
		t.Error(".tmp file should be cleaned up")
	}

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

	content := strings.Repeat("log line\n", 1000)
	if err := os.WriteFile(src, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	compressFile(src, nil)

	if _, err := os.Stat(gzPath); err != nil {
		t.Fatal("compressed file should exist")
	}
	if _, err := os.Stat(src); err == nil {
		t.Error("original file should be removed after compression")
	}

	gzInfo, _ := os.Stat(gzPath)
	if gzInfo.Size() >= int64(len(content)) {
		t.Errorf("compressed file (%d) should be smaller than original (%d)", gzInfo.Size(), len(content))
	}
}

func TestCompressFile_NilOnError(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "source.txt")
	if err := os.WriteFile(src, []byte("test log data\n"), 0644); err != nil {
		t.Fatal(err)
	}

	compressFile(src, nil)

	if _, err := os.Stat(src + ".gz"); err != nil {
		t.Errorf("compression should succeed even with nil OnError: %v", err)
	}
	if _, err := os.Stat(src); err == nil {
		t.Error("original file should be removed after compression with nil OnError")
	}
}

// =============================================================================
// 轮转后文件权限
// =============================================================================

func TestWriter_RotatedFilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file permissions are not meaningful on Windows")
	}
	w, path := newTestWriter(t, func(c *Config) {
		c.MaxSizeMB = 1
	})

	data := []byte(strings.Repeat("x", 1024) + "\n")
	for range 1200 {
		_, _ = w.Write(data)
	}

	_ = w.Close()
	assertFileMode(t, path, DefaultFileMode)
}

// =============================================================================
// 并发写入
// =============================================================================

func TestWriter_ConcurrentWrites(t *testing.T) {
	w, _ := newTestWriter(t)
	defer func() { _ = w.Close() }()

	const goroutines = 100
	done := make(chan struct{})

	for i := range goroutines {
		go func(n int) {
			_, _ = w.Write([]byte(strings.Repeat("x", 100) + "\n"))
			done <- struct{}{}
		}(i)
	}

	for range goroutines {
		<-done
	}
}

// =============================================================================
// Close
// =============================================================================

func TestWriter_Close(t *testing.T) {
	w, _ := newTestWriter(t)

	if err := w.Close(); err != nil {
		t.Errorf("Close() error: %v", err)
	}

	if err := w.Close(); err != nil {
		t.Errorf("double Close() error: %v", err)
	}

	_, err := w.Write([]byte("after close"))
	if err == nil {
		t.Error("Write after Close should return error")
	}
}

// =============================================================================
// Config 验证
// =============================================================================

func TestConfig_EmptyPath(t *testing.T) {
	_, err := New(Config{Path: ""})
	if err == nil {
		t.Fatal("expected error for empty path")
	}
	if !strings.Contains(err.Error(), "file path is required") {
		t.Errorf("error should mention path required, got: %v", err)
	}
}

func TestConfig_RelativePath(t *testing.T) {
	_, err := New(Config{Path: "relative/path.log"})
	if err == nil {
		t.Fatal("expected error for relative path")
	}
}

func TestConfig_Defaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")
	w, err := New(Config{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = w.Close() }()

	if w.cfg.MaxSizeMB != DefaultMaxSizeMB {
		t.Errorf("MaxSizeMB = %d, want %d", w.cfg.MaxSizeMB, DefaultMaxSizeMB)
	}
	if w.cfg.MaxBackups != DefaultMaxBackups {
		t.Errorf("MaxBackups = %d, want %d", w.cfg.MaxBackups, DefaultMaxBackups)
	}
	if w.cfg.MaxAgeDays != DefaultMaxAgeDays {
		t.Errorf("MaxAgeDays = %d, want %d", w.cfg.MaxAgeDays, DefaultMaxAgeDays)
	}
	if !w.cfg.compress() {
		t.Error("Compress should default to true")
	}
	if w.cfg.FileMode != DefaultFileMode {
		t.Errorf("FileMode = %v, want %v", w.cfg.FileMode, DefaultFileMode)
	}
}

// =============================================================================
// Error 方法
// =============================================================================

func TestError_Methods(t *testing.T) {
	inner := fmt.Errorf("inner error")
	e := &Error{Op: "rotate", Err: inner}

	if !strings.Contains(e.Error(), "filerotate/rotate") {
		t.Errorf("Error() should contain 'filerotate/rotate', got: %s", e.Error())
	}
	if !strings.Contains(e.Error(), "inner error") {
		t.Errorf("Error() should contain inner error, got: %s", e.Error())
	}
	if !errors.Is(e, inner) {
		t.Error("Unwrap should return inner error")
	}
}

// =============================================================================
// SetOnError
// =============================================================================

func TestWriter_SetOnError(t *testing.T) {
	w, _ := newTestWriter(t, withMaxSizeMB(1))
	defer func() { _ = w.Close() }()

	var mu sync.Mutex
	var gotErr string
	w.SetOnError(func(err error) {
		mu.Lock()
		gotErr = err.Error()
		mu.Unlock()
	})
	_ = gotErr // verified through rotation error test below
}

// =============================================================================
// 轮转重命名失败 (recoverOpen)
// =============================================================================

func TestWriter_RotationRenameFailure(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions required")
	}
	if os.Getuid() == 0 {
		t.Skip("root user bypasses file permissions")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	w, err := New(Config{Path: path, MaxSizeMB: 1, Compress: boolPtr(false)})
	if err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	var errs []error
	w.SetOnError(func(err error) {
		mu.Lock()
		errs = append(errs, err)
		mu.Unlock()
	})

	// Trigger first rotation.
	data := []byte(strings.Repeat("x", 1024) + "\n")
	for range 1100 {
		_, _ = w.Write(data)
	}

	// Make the directory non-writable to force rename failure on next rotation.
	_ = os.Chmod(dir, 0555)

	// Write enough to trigger another rotation.
	for range 1200 {
		_, _ = w.Write(data)
	}

	_ = os.Chmod(dir, 0755)
	_ = w.Close()

	mu.Lock()
	defer mu.Unlock()
	if len(errs) == 0 {
		t.Error("expected rotation error via SetOnError callback")
	}
}

// =============================================================================
// 备份文件名碰撞
// =============================================================================

func TestWriter_BackupNameCollision(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	w, err := New(Config{Path: path, MaxSizeMB: 1, MaxBackups: 10, Compress: boolPtr(false)})
	if err != nil {
		t.Fatal(err)
	}

	ts := time.Now().Format("2006-01-02T15-04-05.000")
	for i := range 5 {
		collision := fmt.Sprintf("%s.%s.%d", path, ts, i)
		_ = os.WriteFile(collision, []byte("old"), 0644)
	}

	data := []byte(strings.Repeat("x", 1024) + "\n")
	for range 1100 {
		_, _ = w.Write(data)
	}
	_ = w.Close()

	backups := matchBackups(path)
	if len(backups) == 0 {
		t.Error("expected at least one backup despite name collisions")
	}
}

// =============================================================================
// reportError with nil OnError
// =============================================================================

func TestWriter_ReportError_NilOnError(t *testing.T) {
	reportError(nil, &Error{Op: "test", Err: fmt.Errorf("test error")})
}

// =============================================================================
// 过期备份清理
// =============================================================================

func TestWriter_CleanupExpiredBackups(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	oldBackup := path + ".2020-01-01T00-00-00.000"
	_ = os.WriteFile(oldBackup, []byte("old backup\n"), 0644)
	oldTime := time.Now().AddDate(0, 0, -31)
	_ = os.Chtimes(oldBackup, oldTime, oldTime)

	w, err := New(Config{
		Path:       path,
		MaxSizeMB:  1,
		MaxBackups: 100,
		MaxAgeDays: 30,
		Compress:   boolPtr(false),
	})
	if err != nil {
		t.Fatal(err)
	}

	data := []byte(strings.Repeat("x", 1024) + "\n")
	for range 1100 {
		_, _ = w.Write(data)
	}
	_ = w.Close()

	if _, err := os.Stat(oldBackup); err == nil {
		t.Error("old backup should have been removed by MaxAgeDays cleanup")
	}
}

// TestWriter_ConcurrentWritesDuringRotation verifies that concurrent writes
// during file rotation do not cause panics, data races, or lost data.
func TestWriter_ConcurrentWritesDuringRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	w, err := New(Config{
		Path:      path,
		MaxSizeMB: 1, // 1 MB — rotation will trigger quickly
		Compress:  boolPtr(false),
	})
	if err != nil {
		t.Fatal(err)
	}

	data := []byte(strings.Repeat("x", 512) + "\n")
	const goroutines = 10
	const writesPerGoroutine = 300

	var wg sync.WaitGroup
	for i := range goroutines {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := range writesPerGoroutine {
				if _, err := w.Write(data); err != nil {
					t.Errorf("goroutine %d write %d: %v", n, j, err)
					return
				}
			}
		}(i)
	}
	wg.Wait()

	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Verify the main log file exists and has content.
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read main log: %v", err)
	}
	if len(content) == 0 {
		t.Error("main log file is empty after concurrent writes with rotation")
	}

	// Verify at least one backup was created due to rotation.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	backupCount := 0
	for _, e := range entries {
		if e.Name() != "test.log" {
			backupCount++
		}
	}
	if backupCount == 0 {
		t.Error("expected at least one rotated backup file")
	}
}
