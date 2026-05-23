package mebsuta

import (
	"compress/gzip"
	"context"
	"errors"
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
)

const logFileMode os.FileMode = 0600

// FileHandler writes log records to a file with size and time-based rotation and optional gzip compression.
type FileHandler struct {
	leveler slog.Leveler
	format  EncodingType
	inner   slog.Handler // underlying slog.JSONHandler or slog.TextHandler
	state   *fileState   // shared mutable state (across WithAttrs/WithGroup sub-handlers)
	cw      *countingWriter
}

// fileState holds file-related shared mutable state, shared across WithAttrs/WithGroup sub-handlers.
type fileState struct {
	mu           sync.RWMutex // write takes RLock, rotation takes Lock
	file         *os.File
	size         atomic.Int64 // bytes written
	rotatedAt    time.Time    // last rotation time
	closed       atomic.Bool
	errCount     atomic.Int64
	cfg          *FileConfig
	errorHandler atomic.Pointer[ErrorHandler]
	compressWg   sync.WaitGroup // tracks async compression goroutines
}

// countingWriter tracks bytes written, passed as io.Writer to the underlying slog handler.
type countingWriter struct {
	state *fileState
}

func (w *countingWriter) Write(p []byte) (int, error) {
	// state.mu RLock is held by FileHandler.Handle; state.file is stable and readable
	if w.state.file == nil {
		return 0, os.ErrClosed
	}
	n, err := w.state.file.Write(p)
	if n > 0 {
		w.state.size.Add(int64(n))
	}
	return n, err
}

// NewFileHandler creates a FileHandler that writes to the file specified in cfg.
func NewFileHandler(cfg FileConfig) (*FileHandler, error) {
	cfg, err := cfg.Validate()
	if err != nil {
		return nil, fmt.Errorf("mebsuta: %w", err)
	}

	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(cfg.Path), 0750); err != nil {
		return nil, fmt.Errorf("mebsuta: create log directory: %w", err)
	}

	// Open log file
	f, err := os.OpenFile(cfg.Path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, logFileMode)
	if err != nil {
		return nil, fmt.Errorf("mebsuta: open log file: %w", err)
	}

	// Get current file size
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
		cfg:       &cfg,
	}
	state.size.Store(fi.Size())

	// Detect and compress residual uncompressed rotated files at startup
	compressResidual(cfg.Path, cfg.compress(), &state.compressWg)

	cw := &countingWriter{state: state}
	inner := newInnerHandler(cw, format)

	h := &FileHandler{
		leveler: cfg.Level,
		format:  format,
		inner:   inner,
		state:   state,
		cw:      cw,
	}
	eh := DefaultErrorHandler
	h.state.errorHandler.Store(&eh)
	return h, nil
}

// Enabled implements slog.Handler.
func (h *FileHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.leveler.Level()
}

// Handle implements slog.Handler.
func (h *FileHandler) Handle(ctx context.Context, r slog.Record) error {
	if h.state.closed.Load() {
		return nil
	}

	// Check if rotation is needed (read state under RLock)
	h.state.mu.RLock()
	needsRotate := h.needsRotation()
	h.state.mu.RUnlock()

	if needsRotate {
		h.doRotate()
	}

	// Write log record
	h.state.mu.RLock()
	defer h.state.mu.RUnlock()

	if h.state.closed.Load() {
		return nil
	}

	if err := h.inner.Handle(ctx, r); err != nil {
		h.state.errCount.Add(1)
		ReportError(loadErrorHandler(&h.state.errorHandler), HandlerError{Component: "file", Operation: "write", Err: err})
		return err
	}

	return nil
}

// WithAttrs implements slog.Handler.
func (h *FileHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &FileHandler{
		leveler: h.leveler,
		format:  h.format,
		inner:   h.inner.WithAttrs(attrs),
		state:   h.state,
		cw:      h.cw,
	}
}

// WithGroup implements slog.Handler.
func (h *FileHandler) WithGroup(name string) slog.Handler {
	return &FileHandler{
		leveler: h.leveler,
		format:  h.format,
		inner:   h.inner.WithGroup(name),
		state:   h.state,
		cw:      h.cw,
	}
}

// Close implements io.Closer.
func (h *FileHandler) Close() error {
	if !h.state.closed.CompareAndSwap(false, true) {
		return nil
	}

	// Wait for all async compression to finish before closing the file
	h.state.compressWg.Wait()

	h.state.mu.Lock()
	defer h.state.mu.Unlock()

	if h.state.file == nil {
		return nil
	}
	err := h.state.file.Close()
	h.state.file = nil
	return err
}

func (h *FileHandler) setErrorHandler(fn ErrorHandler) {
	h.state.errorHandler.Store(&fn)
}

// needsRotation checks whether rotation is needed. Caller must hold state.mu (at least RLock).
func (h *FileHandler) needsRotation() bool {
	cfg := h.state.cfg
	// Size-based rotation
	maxBytes := int64(cfg.MaxSizeMB) * 1024 * 1024
	if maxBytes > 0 && h.state.size.Load() >= maxBytes {
		return true
	}
	// Time-based rotation
	if cfg.RotateInterval > 0 && time.Since(h.state.rotatedAt) >= cfg.RotateInterval {
		return true
	}
	return false
}

// doRotate performs rotation. Re-checks conditions after acquiring Lock to avoid thundering herd.
func (h *FileHandler) doRotate() {
	h.state.mu.Lock()
	defer h.state.mu.Unlock()

	// Double-check after acquiring Lock
	if h.state.closed.Load() || h.state.file == nil {
		return
	}
	if !h.needsRotation() {
		return
	}

	cfg := h.state.cfg

	// Close current file
	if err := h.state.file.Close(); err != nil {
		ReportError(loadErrorHandler(&h.state.errorHandler), HandlerError{Component: "file", Operation: "rotate", Err: fmt.Errorf("close for rotation: %w", err)})
	}
	h.state.file = nil

	// Generate backup filename and rename
	backup := h.backupNameLocked()
	if err := os.Rename(cfg.Path, backup); err != nil {
		ReportError(loadErrorHandler(&h.state.errorHandler), HandlerError{Component: "file", Operation: "rotate", Err: fmt.Errorf("rename for rotation: %w", err)})
		// Attempt to reopen the original file to continue writing
		f, openErr := os.OpenFile(cfg.Path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, logFileMode)
		if openErr != nil {
			ReportError(loadErrorHandler(&h.state.errorHandler), HandlerError{Component: "file", Operation: "rotate", Err: fmt.Errorf("reopen after failed rotation: %w", openErr)})
			return
		}
		h.state.file = f
		return
	}

	// Create new file
	f, err := os.OpenFile(cfg.Path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, logFileMode)
	if err != nil {
		ReportError(loadErrorHandler(&h.state.errorHandler), HandlerError{Component: "file", Operation: "rotate", Err: fmt.Errorf("create new log file: %w", err)})
		// Try to rename the backup back so we can reopen the original
		if renameBackErr := os.Rename(backup, cfg.Path); renameBackErr != nil {
			ReportError(loadErrorHandler(&h.state.errorHandler), HandlerError{Component: "file", Operation: "rotate", Err: fmt.Errorf("rename backup back failed: %w", renameBackErr)})
		}
		fallback, fbErr := os.OpenFile(cfg.Path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, logFileMode)
		if fbErr != nil {
			ReportError(loadErrorHandler(&h.state.errorHandler), HandlerError{Component: "file", Operation: "rotate", Err: fmt.Errorf("fallback open also failed: %w", fbErr)})
			h.state.closed.Store(true)
			return
		}
		h.state.file = fallback
		return
	}

	h.state.file = f
	h.state.size.Store(0)
	h.state.rotatedAt = time.Now()

	// Async compress backup
	if cfg.compress() {
		eh := loadErrorHandler(&h.state.errorHandler)
		h.state.compressWg.Add(1)
		go func() {
			defer h.state.compressWg.Done()
			compressFile(backup, eh)
		}()
	}

	// Clean up old backups
	h.cleanupBackupsLocked()
}

// backupNameLocked generates a unique backup filename. Caller must hold state.mu Lock.
func (h *FileHandler) backupNameLocked() string {
	ts := time.Now().Format("20060102-150405")
	name := h.state.cfg.Path + "." + ts
	if _, err := os.Stat(name); err != nil {
		if !os.IsNotExist(err) {
			ReportError(loadErrorHandler(&h.state.errorHandler), HandlerError{Component: "file", Operation: "cleanup", Err: fmt.Errorf("backup name stat %s: %w", name, err)})
		}
		return name
	}
	// Multiple rotations within the same second: append a sequence number suffix
	for i := 1; i < 1000; i++ {
		candidate := fmt.Sprintf("%s.%s.%d", h.state.cfg.Path, ts, i)
		if _, err := os.Stat(candidate); err != nil {
			return candidate
		}
	}
	// Edge case: use nanosecond timestamp as fallback
	return h.state.cfg.Path + "." + time.Now().Format("20060102-150405.000000000")
}

// cleanupBackupsLocked removes old backup files that exceed MaxBackups or MaxAgeDays.
// Caller must hold state.mu Lock.
func (h *FileHandler) cleanupBackupsLocked() {
	cfg := h.state.cfg
	if cfg.MaxBackups <= 0 && cfg.MaxAgeDays <= 0 {
		return
	}

	dir := filepath.Dir(cfg.Path)
	base := filepath.Base(cfg.Path)

	entries, err := os.ReadDir(dir)
	if err != nil {
		ReportError(loadErrorHandler(&h.state.errorHandler), HandlerError{Component: "file", Operation: "cleanup", Err: fmt.Errorf("cleanup backups: readdir %s: %w", dir, err)})
		return
	}

	// Collect backup files (including compressed files with .gz suffix)
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

	// Sort by modification time (newest first)
	sort.Slice(backups, func(i, j int) bool {
		return backups[i].modTime.After(backups[j].modTime)
	})

	// Clean up by MaxBackups
	if cfg.MaxBackups > 0 && len(backups) > cfg.MaxBackups {
		var cleanupErrs []error
		for _, b := range backups[cfg.MaxBackups:] {
			path := filepath.Join(dir, b.name)
			if err := os.Remove(path); err != nil {
				cleanupErrs = append(cleanupErrs, fmt.Errorf("remove old backup %s: %w", path, err))
			}
		}
		if len(cleanupErrs) > 0 {
			ReportError(loadErrorHandler(&h.state.errorHandler), HandlerError{Component: "file", Operation: "cleanup", Err: fmt.Errorf("cleanup old backups: %v", errors.Join(cleanupErrs...))})
		}
		backups = backups[:cfg.MaxBackups]
	}

	// Clean up by MaxAgeDays
	if cfg.MaxAgeDays > 0 {
		cutoff := time.Now().AddDate(0, 0, -cfg.MaxAgeDays)
		var cleanupErrs []error
		for _, b := range backups {
			if b.modTime.Before(cutoff) {
				path := filepath.Join(dir, b.name)
				if err := os.Remove(path); err != nil {
					cleanupErrs = append(cleanupErrs, fmt.Errorf("remove expired backup %s: %w", path, err))
				}
			}
		}
		if len(cleanupErrs) > 0 {
			ReportError(loadErrorHandler(&h.state.errorHandler), HandlerError{Component: "file", Operation: "cleanup", Err: fmt.Errorf("cleanup expired backups: %v", errors.Join(cleanupErrs...))})
		}
	}
}

// compressFile compresses a file to .gz (using a temp file + atomic rename).
func compressFile(path string, eh ErrorHandler) {
	gzPath := path + ".gz"
	tmpPath := gzPath + ".tmp"

	src, err := os.Open(path)
	if err != nil {
		ReportError(eh, HandlerError{Component: "file", Operation: "compress", Err: fmt.Errorf("compress open %s: %w", path, err)})
		return
	}
	defer src.Close()

	dst, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		ReportError(eh, HandlerError{Component: "file", Operation: "compress", Err: fmt.Errorf("compress create temp: %w", err)})
		return
	}

	gw := gzip.NewWriter(dst)
	_, err = io.Copy(gw, src)
	if err != nil {
		dst.Close()
		os.Remove(tmpPath)
		ReportError(eh, HandlerError{Component: "file", Operation: "compress", Err: fmt.Errorf("compress data: %w", err)})
		return
	}

	if err := gw.Close(); err != nil {
		dst.Close()
		os.Remove(tmpPath)
		ReportError(eh, HandlerError{Component: "file", Operation: "compress", Err: fmt.Errorf("compress flush: %w", err)})
		return
	}

	if err := dst.Close(); err != nil {
		os.Remove(tmpPath)
		ReportError(eh, HandlerError{Component: "file", Operation: "compress", Err: fmt.Errorf("compress close temp: %w", err)})
		return
	}

	if err := os.Rename(tmpPath, gzPath); err != nil {
		os.Remove(tmpPath)
		ReportError(eh, HandlerError{Component: "file", Operation: "compress", Err: fmt.Errorf("compress rename: %w", err)})
		return
	}

	if err := os.Remove(path); err != nil {
		ReportError(eh, HandlerError{Component: "file", Operation: "compress", Err: fmt.Errorf("compress remove original %s: %w", path, err)})
	}
}

// compressResidual detects and compresses uncompressed rotated files left behind by a previous crash at startup.
func compressResidual(logPath string, compress bool, wg *sync.WaitGroup) {
	dir := filepath.Dir(logPath)
	base := filepath.Base(logPath)

	entries, err := os.ReadDir(dir)
	if err != nil {
		ReportError(DefaultErrorHandler, HandlerError{Component: "file", Operation: "compress", Err: fmt.Errorf("compress residual: readdir %s: %w", dir, err)})
		return
	}

	prefix := base + "."
	for _, e := range entries {
		name := e.Name()
		if name == base || !strings.HasPrefix(name, prefix) {
			continue
		}
		// Clean up stale compression intermediates
		if strings.HasSuffix(name, ".gz.tmp") {
			os.Remove(filepath.Join(dir, name))
			continue
		}
		// Skip already-compressed or temp files
		if strings.HasSuffix(name, ".gz") || strings.HasSuffix(name, ".tmp") {
			continue
		}

		if compress {
			wg.Add(1)
			go func(path string) {
				defer wg.Done()
				compressFile(path, DefaultErrorHandler)
			}(filepath.Join(dir, name))
		}
	}
}

// matchBackups returns all backup filenames in the directory that match the log file prefix. Used for testing.
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

// Compile-time assertions
var (
	_ slog.Handler = (*FileHandler)(nil)
	_ io.Closer    = (*FileHandler)(nil)
)
