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

	"github.com/stretchr/testify/require"
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
	require.NoError(t, err)
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
	require.NoError(t, err)
	return data
}

func assertFileMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file permissions are not meaningful on Windows")
	}
	info, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, want, info.Mode().Perm())
}

// matchBackups 返回与日志文件前缀匹配的全部备份文件名。
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
	require.NoError(t, err)
	require.Equal(t, len(data), n)

	got := readFile(t, path)
	require.Equal(t, string(data), string(got))
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
	require.LessOrEqual(t, len(backups), 2, "expected at most 2 backups, got: %v", backups)
}

// =============================================================================
// 时间轮转
// =============================================================================

func TestWriter_TimeRotation(t *testing.T) {
	w, path := newTestWriter(t, func(c *Config) {
		c.MaxSizeMB = 100
		c.RotateInterval = time.Second
		c.MaxBackups = 3
	})

	_, _ = w.Write([]byte("before rotation\n"))
	// 将 rotatedAt 回拨而非真实等待（≥1s，见
	// minRotateInterval）周期：低于一秒的 RotateInterval 现在
	// 会在构造时被拒绝，基于 sleep 的测试会拖慢整个套件。
	w.mu.Lock()
	w.rotatedAt = time.Now().Add(-2 * time.Second)
	w.mu.Unlock()
	_, _ = w.Write([]byte("after interval\n"))

	_ = w.Close()

	backups := matchBackups(path)
	require.NotEmpty(t, backups, "expected at least one backup from time-based rotation, got none")
}

// TestConfig_RotateIntervalFloor 验证 fail-fast 下限：正的亚秒间隔被拒绝
// （1ns 间隔会让几乎每次 Write 都轮转——实测写入慢约 1700 倍），而 0（仅按大小）
// 与不小于 minRotateInterval 的值都被接受。错误信息必须
// 说明合法范围。
func TestConfig_RotateIntervalFloor(t *testing.T) {
	dir := t.TempDir()
	for _, interval := range []time.Duration{time.Nanosecond, time.Millisecond, 999 * time.Millisecond} {
		_, err := New(Config{Path: filepath.Join(dir, "floor.log"), RotateInterval: interval})
		require.Error(t, err, "RotateInterval=%v: expected error, got nil", interval)
		require.ErrorContains(t, err, "RotateInterval")
		require.ErrorContains(t, err, minRotateInterval.String())
	}
	for _, interval := range []time.Duration{0, time.Second, 30 * time.Second} {
		w, err := New(Config{Path: filepath.Join(dir, "ok.log"), RotateInterval: interval})
		require.NoError(t, err, "RotateInterval=%v: expected acceptance", interval)
		_ = w.Close()
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
			require.NoError(t, err)
			defer func() { _ = f.Close() }()
			gz, err := gzip.NewReader(f)
			require.NoError(t, err)
			defer func() { _ = gz.Close() }()
			content, err := io.ReadAll(gz)
			require.NoError(t, err)
			require.NotEmpty(t, content, "compressed content should not be empty")
			break
		}
	}
	require.True(t, hasGz, "expected compressed backup (.gz) files, got: %v", backups)
}

// TestWriter_RotateCompressionBounded 验证轮转路径的压缩
// 信号量：轮转压力下同一时刻最多存在 maxRotateCompressors 个压缩
// goroutine。若没有上限，连续越过 MaxSizeMB 的 Write 风暴会为每次轮转
// 衍生一个 gzip goroutine——goroutine 与文件描述符无界
// （每次压缩至多持有 2 个 fd，goroutine 上限即蕴含 fd 上限）。
func TestWriter_RotateCompressionBounded(t *testing.T) {
	if testing.Short() {
		t.Skip("compression stress test skipped in -short mode")
	}
	w, _ := newTestWriter(t, withMaxSizeMB(1), withCompress(true), func(c *Config) {
		c.MaxBackups = UnlimitedBackups // 突发期间不受清理干扰
	})
	defer func() { _ = w.Close() }()

	// 一次超过 MaxSizeMB 的 Write 触发写后轮转；连续 12 次
	// 足以让多次压缩重叠。
	data := make([]byte, mib+1024)
	for i := range data {
		data[i] = byte(i)
	}

	base := runtime.NumGoroutine()
	for i := range 12 {
		_, err := w.Write(data)
		require.NoError(t, err, "write %d", i)
		// 突发中途采样：信号量任一时刻至多放行 maxRotateCompressors
		// 个压缩 goroutine（外加本测试 goroutine 与
		// 调度框架的余量）。
		live := runtime.NumGoroutine()
		require.LessOrEqual(t, live, base+maxRotateCompressors+2,
			"goroutines = %d after rotation %d", live, i)
	}

	// Close 会等待 compressWg，因此它返回后不应再有压缩
	// goroutine 残留。
	require.NoError(t, w.Close())
	live := runtime.NumGoroutine()
	require.LessOrEqual(t, live, base+2, "goroutines after Close = %d, want ≈ base %d — compression goroutines outlived Close", live, base)
}

// TestWriter_LogicalBackupCount 验证 MaxBackups 统计的是逻辑
// 备份而非文件数：未压缩备份与其 .gz 压缩副本共享同一
// 逻辑身份（去掉 ".gz" 后同名），必须记为一个。没有去重修复时，
// 压缩开启 + MaxBackups=3 可能保留约 6 个文件（3 对），或更常见地
// 因原始与 .gz 分别计数而删得过狠。
func TestWriter_LogicalBackupCount(t *testing.T) {
	const maxBackups = 3
	w, path := newTestWriter(t, withMaxSizeMB(1), withMaxBackups(maxBackups), withCompress(true))

	// 强制产生远多于 maxBackups 次轮转。
	data := []byte(strings.Repeat("x", 1024) + "\n")
	for range 2000 {
		_, _ = w.Write(data)
	}
	_ = w.Close() // 等待在途压缩结束

	// 收集去重后的逻辑备份键（去掉尾部 ".gz" 的名字）。
	backups := matchBackups(path)
	keys := make(map[string]struct{}, len(backups))
	raw, gz := 0, 0
	for _, b := range backups {
		if strings.HasSuffix(b, ".gz.tmp") {
			continue
		}
		if strings.HasSuffix(b, ".gz") {
			gz++
		} else if !strings.HasSuffix(b, ".tmp") {
			raw++
		}
		keys[strings.TrimSuffix(b, ".gz")] = struct{}{}
	}

	// 压缩完成后，每个备份都应是 .gz 且原始
	// 副本已被删除——不应残留裸备份。
	require.Zero(t, raw, "expected all backups compressed (.gz), but found %d raw (uncompressed) backups: %v", raw, backups)
	require.NotZero(t, gz, "expected compressed backups, got: %v", backups)
	// 逻辑备份数不得超过 MaxBackups。
	require.LessOrEqual(t, len(keys), maxBackups, "logical backup count = %d (keys=%v)", len(keys), keys)
}

// =============================================================================
// 残留文件压缩
// =============================================================================

func TestCompressResidual(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "test.log")

	// 真正的轮转产物：writer 格式的时间戳后缀。
	backup1 := logPath + ".2026-04-01T00-00-00.000"
	require.NoError(t, os.WriteFile(backup1, []byte("old log data\n"), 0644))

	tmpFile := backup1 + ".gz.tmp"
	require.NoError(t, os.WriteFile(tmpFile, []byte("partial gzip"), 0644))

	// 同前缀但并非轮转产物的文件必须原样保留：
	// 仅按前缀匹配会把它们 gzip 压缩并在每次启动时删除原始文件
	//（Compress 默认开启）。
	notes := logPath + ".notes"
	require.NoError(t, os.WriteFile(notes, []byte("operator notes\n"), 0644))
	manual := logPath + ".2020-manual"
	require.NoError(t, os.WriteFile(manual, []byte("manually archived\n"), 0644))

	var wg sync.WaitGroup
	compressResidual(logPath, true, &wg, nil)
	wg.Wait()

	_, err := os.Stat(tmpFile)
	require.Error(t, err, ".tmp file should be cleaned up")

	_, err = os.Stat(backup1 + ".gz")
	require.NoError(t, err, "backup should be compressed to .gz")
	_, err = os.Stat(backup1)
	require.Error(t, err, "compressed original should be removed after .gz creation")

	_, err = os.Stat(notes)
	require.NoError(t, err, "unrelated same-prefix file test.log.notes must not be compressed/removed")
	_, err = os.Stat(manual)
	require.NoError(t, err, "unrelated same-prefix file test.log.2020-manual must not be compressed/removed")
}

// =============================================================================
// compressFile 直接测试
// =============================================================================

func TestCompressFile(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "source.txt")
	gzPath := src + ".gz"

	content := strings.Repeat("log line\n", 1000)
	require.NoError(t, os.WriteFile(src, []byte(content), 0644))

	compressFile(src, nil)

	_, err := os.Stat(gzPath)
	require.NoError(t, err, "compressed file should exist")
	_, err = os.Stat(src)
	require.Error(t, err, "original file should be removed after compression")

	gzInfo, _ := os.Stat(gzPath)
	require.Less(t, gzInfo.Size(), int64(len(content)),
		"compressed file (%d) should be smaller than original (%d)", gzInfo.Size(), len(content))
}

func TestCompressFile_NilOnError(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "source.txt")
	require.NoError(t, os.WriteFile(src, []byte("test log data\n"), 0644))

	compressFile(src, nil)

	_, err := os.Stat(src + ".gz")
	require.NoError(t, err, "compression should succeed even with nil OnError")
	_, err = os.Stat(src)
	require.Error(t, err, "original file should be removed after compression with nil OnError")
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

	require.NoError(t, w.Close())
	require.NoError(t, w.Close(), "double Close() error")

	_, err := w.Write([]byte("after close"))
	require.Error(t, err, "Write after Close should return error")
}

// =============================================================================
// Config 验证
// =============================================================================

func TestConfig_EmptyPath(t *testing.T) {
	_, err := New(Config{Path: ""})
	require.Error(t, err, "expected error for empty path")
	require.ErrorContains(t, err, "file path is required")
}

func TestConfig_RelativePath(t *testing.T) {
	_, err := New(Config{Path: "relative/path.log"})
	require.Error(t, err, "expected error for relative path")
}

// TestConfig_NegativeRotateInterval 验证负的 RotateInterval 会被
// 拒绝。负间隔使 time.Since(rotatedAt) >= interval 恒为
// 真，每次 Write 都被迫轮转。
func TestConfig_NegativeRotateInterval(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")
	_, err := New(Config{Path: path, RotateInterval: -1 * time.Second})
	require.Error(t, err, "expected error for negative RotateInterval")
	require.ErrorContains(t, err, "RotateInterval")
}

func TestConfig_Defaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")
	w, err := New(Config{Path: path})
	require.NoError(t, err)
	defer func() { _ = w.Close() }()

	require.Equal(t, DefaultMaxSizeMB, w.cfg.MaxSizeMB)
	require.Equal(t, DefaultMaxBackups, w.cfg.MaxBackups)
	require.Equal(t, DefaultMaxAgeDays, w.cfg.MaxAgeDays)
	require.True(t, w.cfg.compress(), "Compress should default to true")
	require.Equal(t, DefaultFileMode, w.cfg.FileMode)
}

// =============================================================================
// Error 方法
// =============================================================================

func TestError_Methods(t *testing.T) {
	inner := fmt.Errorf("inner error")
	e := &Error{Op: "rotate", Err: inner}

	require.Contains(t, e.Error(), "filerotate/rotate")
	require.Contains(t, e.Error(), "inner error")
	require.True(t, errors.Is(e, inner), "Unwrap should return inner error")
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
	_ = gotErr // 由下方的轮转错误测试验证
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
	require.NoError(t, err)

	var mu sync.Mutex
	var errs []error
	w.SetOnError(func(err error) {
		mu.Lock()
		errs = append(errs, err)
		mu.Unlock()
	})

	// 触发第一次轮转。
	data := []byte(strings.Repeat("x", 1024) + "\n")
	for range 1100 {
		_, _ = w.Write(data)
	}

	// 将目录置为不可写，强制下一次轮转的重命名失败。
	_ = os.Chmod(dir, 0555)

	// 写入足量数据以触发再一次轮转。
	for range 1200 {
		_, _ = w.Write(data)
	}

	_ = os.Chmod(dir, 0755)
	_ = w.Close()

	mu.Lock()
	defer mu.Unlock()
	require.NotEmpty(t, errs, "expected rotation error via SetOnError callback")
}

// =============================================================================
// 备份文件名碰撞
// =============================================================================

func TestWriter_BackupNameCollision(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	w, err := New(Config{Path: path, MaxSizeMB: 1, MaxBackups: 10, Compress: boolPtr(false)})
	require.NoError(t, err)

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
	require.NotEmpty(t, backups, "expected at least one backup despite name collisions")
}

// =============================================================================
// reportError 与 nil OnError
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
	require.NoError(t, err)

	data := []byte(strings.Repeat("x", 1024) + "\n")
	for range 1100 {
		_, _ = w.Write(data)
	}
	_ = w.Close()

	_, err = os.Stat(oldBackup)
	require.Error(t, err, "old backup should have been removed by MaxAgeDays cleanup")
}

// TestWriter_ConcurrentWritesDuringRotation 验证文件轮转期间的并发写入
// 不会导致 panic、数据竞争或数据丢失。
func TestWriter_ConcurrentWritesDuringRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	w, err := New(Config{
		Path:      path,
		MaxSizeMB: 1, // 1 MB——轮转会很快触发
		Compress:  boolPtr(false),
	})
	require.NoError(t, err)

	data := []byte(strings.Repeat("x", 512) + "\n")
	const goroutines = 10
	const writesPerGoroutine = 300

	var wg sync.WaitGroup
	for i := range goroutines {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := range writesPerGoroutine {
				_, err := w.Write(data)
				require.NoError(t, err, "goroutine %d write %d", n, j)
			}
		}(i)
	}
	wg.Wait()

	require.NoError(t, w.Close(), "close")

	// 验证主日志文件存在且有内容。
	content, err := os.ReadFile(path)
	require.NoError(t, err, "read main log")
	require.NotEmpty(t, content, "main log file is empty after concurrent writes with rotation")

	// 验证轮转至少产生了一个备份。
	entries, err := os.ReadDir(dir)
	require.NoError(t, err, "readdir")
	backupCount := 0
	for _, e := range entries {
		if e.Name() != "test.log" {
			backupCount++
		}
	}
	require.NotZero(t, backupCount, "expected at least one rotated backup file")
}

// TestIsBackupName 验证只有真正的轮转产物才被识别，
// 清理才不会误扫同目录下无关的同前缀文件。
func TestIsBackupName(t *testing.T) {
	const base = "app.log"
	cases := []struct {
		name string
		want bool
	}{
		{"app.log", false}, // base 本身，不是备份
		{"app.log.2026-06-28T13-04-05.000", true},
		{"app.log.2026-06-28T13-04-05.000.1", true},
		{"app.log.2026-06-28T13-04-05.000.gz", true},
		{"app.log.2026-06-28T13-04-05.000.12.gz", true},
		{"app.log.1700000000000000000", true}, // unix-nano 兜底
		{"app.log.1700000000000000000.gz", true},
		{"app.log.other", false},                     // 无关同前缀文件
		{"app.log.", false},                          // 空后缀
		{"other.log.2026-06-28T13-04-05.000", false}, // 错误的 base
		{"app.log.NOTALOG", false},
	}
	for _, c := range cases {
		got := isBackupName(base, c.name)
		require.Equal(t, c.want, got, "isBackupName(%q)", c.name)
	}
}

// TestOpenAppend_RefusesSymlink 是符号链接 TOCTOU 写劫持的
// 回归测试：当日志路径是符号链接时（正是攻击者在轮转重命名窗口
// 埋下的状态），打开必须失败。
func TestOpenAppend_RefusesSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("O_NOFOLLOW is Unix-only; inode check remains on Windows")
	}
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim.txt")
	require.NoError(t, os.WriteFile(victim, []byte("do not touch\n"), 0600))
	link := filepath.Join(dir, "app.log")
	if err := os.Symlink(victim, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	f, _, err := openAppend(link, 0600)
	if err == nil {
		// 反正马上要判定失败；fd 随之销毁
		_ = f.Close()
	}
	require.Error(t, err, "openAppend accepted a symlink — writes would land on the victim file")
	// 受害文件必须原封不动。
	data, err := os.ReadFile(victim)
	require.NoError(t, err)
	require.Equal(t, "do not touch\n", string(data))
}

// TestNew_RefusesSymlinkedPath 覆盖构造期检查。
func TestNew_RefusesSymlinkedPath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics differ on Windows")
	}
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim.txt")
	require.NoError(t, os.WriteFile(victim, nil, 0600))
	link := filepath.Join(dir, "app.log")
	if err := os.Symlink(victim, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	_, err := New(Config{Path: link})
	require.Error(t, err, "New accepted a symlinked log path")
}

// TestClose_OnErrorReentrancy 是 M4 死锁的回归测试：
// Close 过去在仍持有 w.mu 时上报待处理轮转错误，
// 重入 Writer 的 OnError 回调会永久死锁。
func TestClose_OnErrorReentrancy(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.log")
	w, err := New(Config{Path: path, MaxSizeMB: 1, Compress: boolPtr(false)})
	require.NoError(t, err)

	reentered := make(chan struct{})
	w.SetOnError(func(err error) {
		select {
		case <-reentered:
		default:
			close(reentered)
		}
		// 从错误回调内部重入 Writer——修复前
		// 会死锁，现在必须能完成。
		_, _ = w.Write([]byte("reentry probe"))
	})

	w.addRotateErrors(&Error{Op: "rotate", Err: errTest})
	done := make(chan error, 1)
	go func() { done <- w.Close() }()

	select {
	case <-reentered:
		// 回调已执行并成功重入
	case <-time.After(5 * time.Second):
		require.FailNow(t, "OnError was never invoked from Close")
	}
	select {
	case err := <-done:
		require.NoError(t, err, "Close returned error")
	case <-time.After(5 * time.Second):
		require.FailNow(t, "Close deadlocked: OnError re-entry blocked on w.mu")
	}
}

var errTest = &Error{Op: "test", Err: os.ErrDeadlineExceeded}

// TestCompressFile_TmpIsExclusive：.gz.tmp 必须以 O_EXCL 创建，
// 预先埋在该名字上的符号链接才无法被截断写入。
func TestCompressFile_TmpIsExclusive(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics differ on Windows")
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "src.log")
	require.NoError(t, os.WriteFile(src, []byte("data\n"), 0600))
	victim := filepath.Join(dir, "victim.txt")
	require.NoError(t, os.WriteFile(victim, []byte("precious\n"), 0600))
	// 预先把临时名做成指向受害文件的符号链接。
	if err := os.Symlink(victim, src+".gz.tmp"); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	compressFile(src, func(error) {})

	data, err := os.ReadFile(victim)
	require.NoError(t, err)
	require.Equal(t, "precious\n", string(data), "victim truncated through tmp symlink")
	// 预埋的符号链接也不应被成功的压缩
	// 替换——源文件应仍然存在。
	_, err = os.Stat(src)
	require.NoError(t, err, "source removed despite tmp conflict")
	// 清理预埋链接，保证 TempDir 清理正常。
	_ = os.Remove(src + ".gz.tmp")
}

// TestIsBackupName_NanoFallbackTightness：unix-nano 兜底分支
// 要求至少 15 位数字，无关的 <base>.<digits> 文件（app.log.12345）
// 才不会被当作轮转产物——否则 compressResidual 会在 Compress 默认
// 开启时于每次启动将它们 gzip 压缩并删除。
func TestIsBackupName_NanoFallbackTightness(t *testing.T) {
	base := "app.log"
	yes := []string{
		"app.log.1760000000000000000",          // nano 兜底
		"app.log.1760000000000000000.3",        // nano + 序号
		"app.log.1760000000000000000.gz",       // nano + gz
		"app.log.2026-04-01T00-00-00.000",      // 时间戳
		"app.log.2026-04-01T00-00-00.000.2.gz", // 时间戳 + 序号 + gz
	}
	no := []string{
		"app.log.12345", // 短数字串——不是轮转产物
		"app.log.12345.gz",
		"app.log.notes",
		"app.log.2020-manual",
	}
	for _, n := range yes {
		require.True(t, isBackupName(base, n), "isBackupName(%q) = false, want true", n)
	}
	for _, n := range no {
		require.False(t, isBackupName(base, n), "isBackupName(%q) = true, want false", n)
	}
}
