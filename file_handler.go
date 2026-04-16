package mebsuta

import (
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/iuboy/mebsuta/config"
)

// =============================================================================
// FileHandler — 文件输出 slog.Handler
// =============================================================================

// FileHandler 将日志记录输出到文件，支持大小+时间轮转和 gzip 压缩。
// 实现 slog.Handler 和 io.Closer 接口。
type FileHandler struct {
	LevelHandler
	format EncodingType
	inner  slog.Handler // 底层 slog.JSONHandler 或 slog.TextHandler
	state  *fileState   // 共享可变状态（跨 WithAttrs/WithGroup 子 Handler）
	cw     *countingWriter
}

// fileState 保存文件相关的共享可变状态。
// 同一个文件的所有 FileHandler（通过 WithAttrs/WithGroup 创建的子 Handler）共享同一个 fileState。
type fileState struct {
	mu           sync.RWMutex // 写入 RLock，轮转 Lock
	file         *os.File
	size         atomic.Int64 // 已写入字节数
	rotatedAt    time.Time    // 上次轮转时间
	closed       atomic.Bool
	errCount     atomic.Int64
	cfg          config.FileConfig
	errorHandler atomic.Pointer[ErrorHandler]
}

// countingWriter 包装当前文件，同时追踪写入字节数。
// 作为 io.Writer 传给底层 slog Handler。
type countingWriter struct {
	state *fileState
}

func (w *countingWriter) Write(p []byte) (int, error) {
	// state.mu RLock 由 FileHandler.Handle 持有，state.file 稳定可读
	if w.state.file == nil {
		return 0, os.ErrClosed
	}
	n, err := w.state.file.Write(p)
	if n > 0 {
		w.state.size.Add(int64(n))
	}
	return n, err
}

// NewFileHandler 创建输出到文件的 slog.Handler。
// level 控制日志级别过滤。cfg 配置文件路径、轮转策略等。
func NewFileHandler(cfg config.FileConfig, level slog.Level) (*FileHandler, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("mebsuta: %w", err)
	}

	// 确保目录存在
	if err := os.MkdirAll(filepath.Dir(cfg.Path), 0750); err != nil {
		return nil, fmt.Errorf("mebsuta: create log directory: %w", err)
	}

	// 启动时检测并压缩残留的未压缩轮转文件
	compressResidual(cfg.Path, cfg.Compress)

	// 打开日志文件
	f, err := os.OpenFile(cfg.Path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, fmt.Errorf("mebsuta: open log file: %w", err)
	}

	// 获取当前文件大小
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("mebsuta: stat log file: %w", err)
	}

	format := EncodingType(cfg.Format)
	if format == "" {
		format = JSON
	}

	state := &fileState{
		file:      f,
		rotatedAt: time.Now(),
		cfg:       cfg,
	}
	state.size.Store(fi.Size())

	cw := &countingWriter{state: state}
	inner := newInnerHandler(cw, format)

	h := &FileHandler{
		LevelHandler: LevelHandler{Level: level},
		format:       format,
		inner:        inner,
		state:        state,
		cw:           cw,
	}
	eh := DefaultErrorHandler
	h.state.errorHandler.Store(&eh)
	return h, nil
}

// Handle 处理一条日志记录，写入文件。
func (h *FileHandler) Handle(ctx context.Context, r slog.Record) error {
	if h.state.closed.Load() {
		return nil
	}

	// 检查是否需要轮转（RLock 下读取状态）
	h.state.mu.RLock()
	needsRotate := h.needsRotation()
	h.state.mu.RUnlock()

	if needsRotate {
		h.doRotate()
	}

	// 写入日志
	h.state.mu.RLock()
	defer h.state.mu.RUnlock()

	if h.state.closed.Load() {
		return nil
	}

	if err := h.inner.Handle(ctx, r); err != nil {
		h.state.errCount.Add(1)
		ReportError(loadErrorHandler(&h.state.errorHandler), "file", err)
		return err
	}

	return nil
}

// WithAttrs 返回带有预置属性的新 FileHandler。
func (h *FileHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &FileHandler{
		LevelHandler: h.LevelHandler,
		format:       h.format,
		inner:        h.inner.WithAttrs(attrs),
		state:        h.state,
		cw:           h.cw,
	}
}

// WithGroup 返回带有分组前缀的新 FileHandler。
func (h *FileHandler) WithGroup(name string) slog.Handler {
	return &FileHandler{
		LevelHandler: h.LevelHandler,
		format:       h.format,
		inner:        h.inner.WithGroup(name),
		state:        h.state,
		cw:           h.cw,
	}
}

// Close 刷新并关闭文件（实现 io.Closer）。
func (h *FileHandler) Close() error {
	if !h.state.closed.CompareAndSwap(false, true) {
		return nil
	}

	h.state.mu.Lock()
	defer h.state.mu.Unlock()

	if h.state.file == nil {
		return nil
	}
	err := h.state.file.Close()
	h.state.file = nil
	return err
}

// setErrorHandler 设置内部错误处理函数（由 buildHandler 传播调用）。
func (h *FileHandler) setErrorHandler(fn ErrorHandler) {
	h.state.errorHandler.Store(&fn)
}

// =============================================================================
// 轮转逻辑
// =============================================================================

// needsRotation 检查是否需要轮转。调用方必须持有 state.mu（至少 RLock）。
func (h *FileHandler) needsRotation() bool {
	cfg := h.state.cfg
	// 大小轮转
	maxBytes := int64(cfg.MaxSizeMB) * 1024 * 1024
	if maxBytes > 0 && h.state.size.Load() >= maxBytes {
		return true
	}
	// 时间轮转
	if cfg.RotateInterval > 0 && time.Since(h.state.rotatedAt) >= cfg.RotateInterval {
		return true
	}
	return false
}

// doRotate 执行轮转。获取 Lock 后再次检查条件，避免惊群。
func (h *FileHandler) doRotate() {
	h.state.mu.Lock()
	defer h.state.mu.Unlock()

	// Lock 后二次检查
	if h.state.closed.Load() || h.state.file == nil {
		return
	}
	if !h.needsRotation() {
		return
	}

	cfg := h.state.cfg

	// 关闭当前文件
	if err := h.state.file.Close(); err != nil {
		ReportError(loadErrorHandler(&h.state.errorHandler), "file", fmt.Errorf("close for rotation: %w", err))
	}
	h.state.file = nil

	// 生成备份文件名并重命名
	backup := h.backupNameLocked()
	if err := os.Rename(cfg.Path, backup); err != nil {
		ReportError(loadErrorHandler(&h.state.errorHandler), "file", fmt.Errorf("rename for rotation: %w", err))
		// 尝试重新打开原文件继续写入
		f, openErr := os.OpenFile(cfg.Path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if openErr != nil {
			ReportError(loadErrorHandler(&h.state.errorHandler), "file", fmt.Errorf("reopen after failed rotation: %w", openErr))
			return
		}
		h.state.file = f
		return
	}

	// 创建新文件
	f, err := os.OpenFile(cfg.Path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		ReportError(loadErrorHandler(&h.state.errorHandler), "file", fmt.Errorf("create new log file: %w", err))
		h.state.closed.Store(true)
		return
	}

	h.state.file = f
	h.state.size.Store(0)
	h.state.rotatedAt = time.Now()

	// 异步压缩备份
	if cfg.Compress {
		eh := loadErrorHandler(&h.state.errorHandler)
		go compressFile(backup, eh)
	}

	// 清理旧备份
	h.cleanupBackupsLocked()
}

// backupNameLocked 生成唯一的备份文件名。调用方必须持有 state.mu Lock。
func (h *FileHandler) backupNameLocked() string {
	ts := time.Now().Format("20060102-150405")
	name := h.state.cfg.Path + "." + ts
	if _, err := os.Stat(name); err != nil {
		return name
	}
	// 同一秒内多次轮转，加序号后缀
	for i := 1; i < 100; i++ {
		candidate := fmt.Sprintf("%s.%s.%d", h.state.cfg.Path, ts, i)
		if _, err := os.Stat(candidate); err != nil {
			return candidate
		}
	}
	return name
}

// cleanupBackupsLocked 清理超过 MaxBackups 或 MaxAgeDays 的旧备份文件。
// 调用方必须持有 state.mu Lock。
func (h *FileHandler) cleanupBackupsLocked() {
	cfg := h.state.cfg
	if cfg.MaxBackups <= 0 && cfg.MaxAgeDays <= 0 {
		return
	}

	dir := filepath.Dir(cfg.Path)
	base := filepath.Base(cfg.Path)

	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}

	// 收集备份文件（包含 .gz 后缀的已压缩文件）
	type backupInfo struct {
		name    string
		modTime time.Time
	}
	var backups []backupInfo
	prefix := base + "."
	for _, e := range entries {
		name := e.Name()
		if name == base || !strings.HasPrefix(name, prefix) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		backups = append(backups, backupInfo{name: name, modTime: info.ModTime()})
	}

	// 按修改时间排序（最新在前）
	sort.Slice(backups, func(i, j int) bool {
		return backups[i].modTime.After(backups[j].modTime)
	})

	// 按 MaxBackups 清理
	if cfg.MaxBackups > 0 && len(backups) > cfg.MaxBackups {
		for _, b := range backups[cfg.MaxBackups:] {
			os.Remove(filepath.Join(dir, b.name))
		}
		backups = backups[:cfg.MaxBackups]
	}

	// 按 MaxAgeDays 清理
	if cfg.MaxAgeDays > 0 {
		cutoff := time.Now().AddDate(0, 0, -cfg.MaxAgeDays)
		for _, b := range backups {
			if b.modTime.Before(cutoff) {
				os.Remove(filepath.Join(dir, b.name))
			}
		}
	}
}

// =============================================================================
// gzip 压缩
// =============================================================================

// compressFile 将文件异步压缩为 .gz（使用临时文件 + 原子 rename）。
func compressFile(path string, eh ErrorHandler) {
	if eh == nil {
		return
	}
	gzPath := path + ".gz"
	tmpPath := gzPath + ".tmp"

	src, err := os.Open(path)
	if err != nil {
		eh("file", fmt.Errorf("compress open %s: %w", path, err))
		return
	}
	defer src.Close()

	dst, err := os.Create(tmpPath)
	if err != nil {
		eh("file", fmt.Errorf("compress create temp: %w", err))
		return
	}

	gw := gzip.NewWriter(dst)
	_, err = io.Copy(gw, src)
	if err != nil {
		dst.Close()
		os.Remove(tmpPath)
		eh("file", fmt.Errorf("compress data: %w", err))
		return
	}

	if err := gw.Close(); err != nil {
		dst.Close()
		os.Remove(tmpPath)
		eh("file", fmt.Errorf("compress flush: %w", err))
		return
	}

	if err := dst.Close(); err != nil {
		os.Remove(tmpPath)
		eh("file", fmt.Errorf("compress close temp: %w", err))
		return
	}

	// 原子 rename
	if err := os.Rename(tmpPath, gzPath); err != nil {
		os.Remove(tmpPath)
		eh("file", fmt.Errorf("compress rename: %w", err))
		return
	}

	// 删除原文件
	if err := os.Remove(path); err != nil {
		eh("file", fmt.Errorf("compress remove original %s: %w", path, err))
	}
}

// compressResidual 在启动时检测并压缩上次崩溃留下的未压缩轮转文件。
func compressResidual(logPath string, compress bool) {
	dir := filepath.Dir(logPath)
	base := filepath.Base(logPath)

	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}

	prefix := base + "."
	for _, e := range entries {
		name := e.Name()
		if name == base || !strings.HasPrefix(name, prefix) {
			continue
		}
		// 跳过已压缩的文件
		if strings.HasSuffix(name, ".gz") || strings.HasSuffix(name, ".tmp") {
			continue
		}
		// 跳过 .tmp 压缩中间文件（清理）
		if strings.HasSuffix(name, ".gz.tmp") {
			os.Remove(filepath.Join(dir, name))
			continue
		}

		if compress {
			go compressFile(filepath.Join(dir, name), DefaultErrorHandler)
		}
	}
}

// =============================================================================
// 辅助：备份文件匹配
// =============================================================================

// matchBackups 返回目录中匹配日志文件前缀的所有备份文件名。
// 用于测试。
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

// 编译期断言
var _ io.Closer = (*FileHandler)(nil)
