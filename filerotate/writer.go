package filerotate

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Writer is a rotating file writer implementing io.Writer and io.Closer.
// It handles size-based and time-based rotation, backup management, and optional
// gzip compression.
type Writer struct {
	mu         sync.RWMutex
	file       *os.File
	size       atomic.Int64
	maxBytes   int64 // pre-computed from cfg.MaxSizeMB * MiB, avoids multiplication on every Write
	rotatedAt  time.Time
	closed     atomic.Bool
	cfg        Config
	onError    atomic.Pointer[errorFunc]
	compressWg sync.WaitGroup
}

// errorFunc wraps a function type for use with atomic.Pointer.
type errorFunc struct {
	fn func(error)
}

// New creates a rotating file writer for the given config.
func New(cfg Config) (*Writer, error) {
	cfg, err := cfg.Validate()
	if err != nil {
		return nil, err
	}

	if err := os.MkdirAll(filepath.Dir(cfg.Path), 0700); err != nil {
		return nil, fmt.Errorf("create log directory: %w", err)
	}

	if err := checkNotSymlink(cfg.Path); err != nil {
		return nil, err
	}

	f, err := os.OpenFile(cfg.Path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, cfg.FileMode)
	if err != nil {
		return nil, fmt.Errorf("open log file: %w", err)
	}

	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("stat log file: %w", err)
	}

	w := &Writer{
		file:      f,
		maxBytes:  int64(cfg.MaxSizeMB) * MiB,
		rotatedAt: time.Now(),
		cfg:       cfg,
	}
	w.size.Store(fi.Size())

	onErrorFn := cfg.OnError
	if onErrorFn == nil {
		onErrorFn = defaultOnError
	}
	w.onError.Store(&errorFunc{fn: onErrorFn})

	compressResidual(cfg.Path, cfg.compress(), &w.compressWg, w.loadOnError())

	return w, nil
}

// Write writes bytes to the log file, triggering rotation if needed.
func (w *Writer) Write(p []byte) (int, error) {
	if w.closed.Load() {
		return 0, os.ErrClosed
	}

	w.mu.RLock()
	needsRotate := w.needsRotation()
	w.mu.RUnlock()

	if needsRotate {
		w.rotate()
	}

	w.mu.RLock()
	defer w.mu.RUnlock()

	if w.closed.Load() || w.file == nil {
		return 0, os.ErrClosed
	}

	n, err := w.file.Write(p)
	if n > 0 {
		w.size.Add(int64(n))
	}

	// Post-write rotation check: if this write pushed past the limit,
	// rotate immediately so the oversized file doesn't persist until
	// the next Write call (which may never come for low-frequency logs).
	// mu.RLock is still held, so needsRotation is safe to call.
	if err == nil && w.needsRotation() {
		w.mu.RUnlock()
		w.rotate()
		// rotate() acquired and released the write lock; re-acquire read
		// lock so the deferred RUnlock matches.
		w.mu.RLock()
	}

	return n, err
}

// Close waits for async compression to finish, then closes the file.
func (w *Writer) Close() error {
	if !w.closed.CompareAndSwap(false, true) {
		return nil
	}

	// Acquire write lock before Wait to prevent a concurrent rotate() from
	// calling compressWg.Add(1) after Wait returns. Without this lock, the
	// sequence is: Close sets closed=true, Wait sees 0 goroutines, Lock+close
	// file — while a rotate() that already passed its closed.Load() check
	// starts a new compression goroutine that outlives Close.
	w.mu.Lock()
	defer w.mu.Unlock()

	w.compressWg.Wait()

	if w.file == nil {
		return nil
	}
	err := w.file.Close()
	w.file = nil
	return err
}

// SetOnError updates the error callback. Safe to call concurrently.
func (w *Writer) SetOnError(fn func(error)) {
	w.onError.Store(&errorFunc{fn: fn})
}

func (w *Writer) loadOnError() func(error) {
	v := w.onError.Load()
	if v == nil {
		return defaultOnError
	}
	return v.fn
}

// needsRotation checks whether rotation is needed. Caller must hold w.mu (at least RLock).
func (w *Writer) needsRotation() bool {
	if w.maxBytes > 0 && w.size.Load() >= w.maxBytes {
		return true
	}
	if w.cfg.RotateInterval > 0 && time.Since(w.rotatedAt) >= w.cfg.RotateInterval {
		return true
	}
	return false
}

// rotate performs rotation. Re-checks conditions after acquiring Lock to avoid thundering herd.
func (w *Writer) rotate() {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed.Load() || w.file == nil {
		return
	}
	if !w.needsRotation() {
		return
	}

	onError := w.loadOnError()

	if err := w.file.Close(); err != nil {
		reportError(onError, &Error{Op: "rotate", Err: fmt.Errorf("close for rotation: %w", err)})
	}
	w.file = nil

	backup := w.backupNameLocked()
	if err := os.Rename(w.cfg.Path, backup); err != nil {
		reportError(onError, &Error{Op: "rotate", Err: fmt.Errorf("rename for rotation: %w", err)})
		w.recoverOpen(w.cfg.Path, onError)
		return
	}

	f, err := os.OpenFile(w.cfg.Path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, w.cfg.FileMode)
	if err != nil {
		reportError(onError, &Error{Op: "rotate", Err: fmt.Errorf("create new log file: %w", err)})
		if renameBackErr := os.Rename(backup, w.cfg.Path); renameBackErr != nil {
			reportError(onError, &Error{Op: "rotate", Err: fmt.Errorf("rename backup back failed: %w", renameBackErr)})
		}
		w.recoverOpen(w.cfg.Path, onError)
		return
	}

	w.file = f
	w.size.Store(0)
	w.rotatedAt = time.Now()

	if w.cfg.compress() {
		w.compressWg.Add(1)
		go func() {
			defer w.compressWg.Done()
			compressFile(backup, onError)
		}()
	}

	w.cleanupBackupsLocked()
}

// recoverOpen attempts to reopen the log file after a rotation failure.
func (w *Writer) recoverOpen(path string, onError func(error)) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, w.cfg.FileMode)
	if err != nil {
		reportError(onError, &Error{Op: "rotate", Err: fmt.Errorf("recover open failed: %w", err)})
		w.closed.Store(true)
		return
	}
	w.file = f
}

// backupNameLocked generates a unique backup filename. Caller must hold w.mu Lock.
// Uses a single ReadDir call + in-memory set to avoid up to MaxRotationSuffixSeq Stat syscalls.
func (w *Writer) backupNameLocked() string {
	ts := time.Now().Format("2006-01-02T15-04-05.000")
	name := w.cfg.Path + "." + ts

	// Single ReadDir to get all existing files in the log directory.
	dir := filepath.Dir(w.cfg.Path)
	entries, err := os.ReadDir(dir)
	if err != nil {
		// Fallback: can't read dir, just use the name directly.
		return name
	}

	// Build a set of existing filenames for O(1) lookup.
	existing := make(map[string]struct{}, len(entries))
	for _, e := range entries {
		existing[e.Name()] = struct{}{}
	}

	base := filepath.Base(name)
	if _, found := existing[base]; !found {
		return name
	}
	for i := 1; i < MaxRotationSuffixSeq; i++ {
		candidate := fmt.Sprintf("%s.%d", base, i)
		if _, found := existing[candidate]; !found {
			return filepath.Join(dir, candidate)
		}
	}
	return w.cfg.Path + "." + fmt.Sprintf("%d", time.Now().UnixNano())
}

// cleanupBackupsLocked removes old backup files that exceed MaxBackups or MaxAgeDays.
// Caller must hold w.mu Lock.
func (w *Writer) cleanupBackupsLocked() {
	cfg := w.cfg
	if cfg.MaxBackups <= 0 && cfg.MaxAgeDays <= 0 {
		return
	}

	dir := filepath.Dir(cfg.Path)
	base := filepath.Base(cfg.Path)

	entries, err := os.ReadDir(dir)
	if err != nil {
		reportError(w.loadOnError(), &Error{Op: "cleanup", Err: fmt.Errorf("readdir %s: %w", dir, err)})
		return
	}

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

	sort.Slice(backups, func(i, j int) bool {
		return backups[i].modTime.After(backups[j].modTime)
	})

	keep := backups
	if cfg.MaxBackups > 0 && len(keep) > cfg.MaxBackups {
		keep = keep[:cfg.MaxBackups]
	}

	cutoff := time.Time{}
	if cfg.MaxAgeDays > 0 {
		cutoff = time.Now().AddDate(0, 0, -cfg.MaxAgeDays)
	}

	var cleanupErrs []error
	for _, b := range backups[len(keep):] {
		path := filepath.Join(dir, b.name)
		if err := os.Remove(path); err != nil {
			cleanupErrs = append(cleanupErrs, fmt.Errorf("remove old backup %s: %w", path, err))
		}
	}
	if !cutoff.IsZero() {
		for _, b := range keep {
			if b.modTime.Before(cutoff) {
				path := filepath.Join(dir, b.name)
				if err := os.Remove(path); err != nil {
					cleanupErrs = append(cleanupErrs, fmt.Errorf("remove expired backup %s: %w", path, err))
				}
			}
		}
	}
	if len(cleanupErrs) > 0 {
		reportError(w.loadOnError(), &Error{Op: "cleanup", Err: fmt.Errorf("cleanup backups: %v", errors.Join(cleanupErrs...))})
	}
}

// reportError calls onError if non-nil, otherwise falls back to stderr.
func reportError(onError func(error), err error) {
	if onError != nil {
		onError(err)
	}
}

// defaultOnError writes error details to os.Stderr.
func defaultOnError(err error) {
	fmt.Fprintf(os.Stderr, "mebsuta/file: %v\n", err)
}

// Compile-time assertions.
var (
	_ io.Writer = (*Writer)(nil)
	_ io.Closer = (*Writer)(nil)
)

// checkNotSymlink verifies the log file path is not a symlink. If the file does not
// exist yet, it checks the parent directory. Returns an error if a symlink is detected.
func checkNotSymlink(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("stat log file: %w", err)
		}
		// File doesn't exist yet — check parent directory.
		dir := filepath.Dir(path)
		di, err := os.Lstat(dir)
		if err != nil {
			return fmt.Errorf("stat log directory: %w", err)
		}
		if di.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("log directory %s is a symlink, refusing to write", dir)
		}
		return nil
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("log file %s is a symlink, refusing to write", path)
	}
	return nil
}
