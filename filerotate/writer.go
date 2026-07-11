package filerotate

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
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
	mu         sync.Mutex
	file       *os.File
	size       atomic.Int64
	maxBytes   int64 // pre-computed from cfg.MaxSizeMB * MiB, avoids multiplication on every Write
	rotatedAt  time.Time
	closed     atomic.Bool
	cfg        Config
	onError    atomic.Pointer[errorFunc]
	compressWg sync.WaitGroup
	// H2: paths currently being compressed; cleanupBackupsLocked skips these.
	// Has its own mutex so the compression goroutine can mark a path done
	// without acquiring w.mu — Close() holds w.mu while waiting on
	// compressWg, so re-locking w.mu from the goroutine would deadlock.
	compressMu  sync.Mutex
	compressing map[string]struct{}
	// M4: rotateLocked (under w.mu) appends errors here; reportRotateErrors
	// (outside w.mu, concurrent across Write callers) drains them. A separate
	// mutex guards the slice so the unlock-then-report pattern stays race-free.
	errMu               sync.Mutex
	pendingRotateErrors []error
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

	f, fi, err := openAppend(cfg.Path, cfg.FileMode)
	if err != nil {
		return nil, fmt.Errorf("open log file: %w", err)
	}

	w := &Writer{
		file:        f,
		maxBytes:    int64(cfg.MaxSizeMB) * MiB,
		rotatedAt:   time.Now(),
		cfg:         cfg,
		compressing: make(map[string]struct{}),
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

	w.mu.Lock()

	if w.closed.Load() || w.file == nil {
		w.mu.Unlock()
		return 0, os.ErrClosed
	}

	// Pre-write rotation check.
	if w.needsRotation() {
		w.rotateLocked()
	}

	// H1: rotateLocked may fail (disk full, permission, recovery failure),
	// leaving w.file == nil. Re-check to avoid nil-pointer panic.
	if w.file == nil {
		w.mu.Unlock()
		w.reportRotateErrors()
		return 0, os.ErrClosed
	}

	n, err := w.file.Write(p)
	if n > 0 {
		w.size.Add(int64(n))
	}

	// Post-write rotation check: if this write pushed past the limit,
	// rotate immediately so the oversized file doesn't persist until
	// the next Write call (which may never come for low-frequency logs).
	if err == nil && w.needsRotation() {
		w.rotateLocked()
	}
	closedAfter := w.closed.Load()
	w.mu.Unlock()

	// M4: report rotation errors outside the lock to prevent deadlock if
	// the user's onError callback re-enters the Writer.
	w.reportRotateErrors()

	// If post-write rotation failed and closed the writer, the write itself
	// still succeeded — surface the count but let the next Write return ErrClosed.
	if closedAfter {
		return n, os.ErrClosed
	}

	return n, err
}

// Close waits for async compression to finish, then closes the file.
//
// M6: Close blocks until all in-flight gzip compressions finish. There is no
// deadline — a very large backup on a slow disk can delay shutdown indefinitely.
// If your shutdown path requires a bound, drain compressions out-of-band before
// calling Close, or skip Close and let the process exit reap the goroutines.
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

	// H2: after all compressions finish, re-run cleanup to reap any backups
	// that were skipped earlier because they were mid-compression. Without
	// this, a high-frequency rotation burst can leave stale backups.
	if w.file != nil {
		w.cleanupBackupsLocked()
		w.reportRotateErrors()
	}

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

// needsRotation checks whether rotation is needed. Caller must hold w.mu.
func (w *Writer) needsRotation() bool {
	if w.maxBytes > 0 && w.size.Load() >= w.maxBytes {
		return true
	}
	if w.cfg.RotateInterval > 0 && time.Since(w.rotatedAt) >= w.cfg.RotateInterval {
		return true
	}
	return false
}

// rotateLocked performs rotation. Re-checks conditions to avoid thundering herd.
// Caller must hold w.mu.
//
// M4: errors are collected and reported via reportRotateErrors *after* the lock
// is released (by the caller, Write/rotateAndReport), so a user-provided
// onError callback that touches the Writer cannot deadlock on the non-reentrant
// w.mu.
func (w *Writer) rotateLocked() {
	if w.closed.Load() || w.file == nil {
		return
	}
	if !w.needsRotation() {
		return
	}

	// M5: best-effort fsync before close so page-cache data survives a crash
	// immediately after rotation. Sync errors are non-fatal (may be a pipe or
	// a filesystem that doesn't support fsync); collect and continue to close.
	var errs []error
	if err := w.file.Sync(); err != nil {
		errs = append(errs, &Error{Op: "rotate", Err: fmt.Errorf("sync for rotation: %w", err)})
	}
	if err := w.file.Close(); err != nil {
		errs = append(errs, &Error{Op: "rotate", Err: fmt.Errorf("close for rotation: %w", err)})
	}
	w.file = nil

	backup := w.backupNameLocked()
	if err := os.Rename(w.cfg.Path, backup); err != nil {
		errs = append(errs, &Error{Op: "rotate", Err: fmt.Errorf("rename for rotation: %w", err)})
		w.addRotateErrors(errs...)
		w.recoverOpen(w.cfg.Path)
		return
	}

	f, _, err := openAppend(w.cfg.Path, w.cfg.FileMode)
	if err != nil {
		errs = append(errs, &Error{Op: "rotate", Err: fmt.Errorf("create new log file: %w", err)})
		if renameBackErr := os.Rename(backup, w.cfg.Path); renameBackErr != nil {
			errs = append(errs, &Error{Op: "rotate", Err: fmt.Errorf("rename backup back failed: %w", renameBackErr)})
		}
		w.addRotateErrors(errs...)
		w.recoverOpen(w.cfg.Path)
		return
	}

	w.file = f
	w.size.Store(0)
	w.rotatedAt = time.Now()

	if w.cfg.compress() {
		// H2: track the in-flight compression path so cleanupBackupsLocked
		// can skip it, preventing deletion of a backup still being compressed.
		// compressMu (not w.mu) protects compressing because Close() holds
		// w.mu while waiting on compressWg — locking w.mu here would deadlock.
		w.compressMu.Lock()
		w.compressing[backup] = struct{}{}
		w.compressMu.Unlock()
		w.compressWg.Add(1)
		go func() {
			defer w.compressWg.Done()
			compressFile(backup, w.loadOnError())
			w.compressMu.Lock()
			delete(w.compressing, backup)
			w.compressMu.Unlock()
		}()
	}

	w.cleanupBackupsLocked()
	w.addRotateErrors(errs...)
}

// reportRotateErrors drains pending rotation errors and reports them via onError.
// Caller must NOT hold w.mu — this is the M4 deadlock fix. The pending slice
// is guarded by errMu so concurrent Write callers can drain it safely.
func (w *Writer) reportRotateErrors() {
	w.errMu.Lock()
	errs := w.pendingRotateErrors
	w.pendingRotateErrors = nil
	w.errMu.Unlock()

	onError := w.loadOnError()
	for _, e := range errs {
		reportError(onError, e)
	}
}

// addRotateErrors appends errors to the pending slice under errMu. Safe to
// call while holding w.mu — the lock order is w.mu → errMu (consistent with
// reportRotateErrors which takes errMu without w.mu).
func (w *Writer) addRotateErrors(errs ...error) {
	if len(errs) == 0 {
		return
	}
	w.errMu.Lock()
	w.pendingRotateErrors = append(w.pendingRotateErrors, errs...)
	w.errMu.Unlock()
}

// recoverOpen attempts to reopen the log file after a rotation failure.
// M3: updates w.size and w.rotatedAt from the reopened file so the next
// needsRotation() check reflects reality instead of triggering an immediate
// re-rotation loop. Errors are collected into pendingRotateErrors and drained
// by reportRotateErrors() outside the lock (M4).
func (w *Writer) recoverOpen(path string) {
	f, fi, err := openAppend(path, w.cfg.FileMode)
	if err != nil {
		w.addRotateErrors(&Error{Op: "rotate", Err: fmt.Errorf("recover open failed: %w", err)})
		w.closed.Store(true)
		return
	}
	w.file = f
	w.size.Store(fi.Size())
	w.rotatedAt = time.Now()
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
		w.addRotateErrors(&Error{Op: "cleanup", Err: fmt.Errorf("readdir %s: %w", dir, err)})
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
		// Only consider files whose suffix matches a real rotation artifact
		// (timestamp, optional sequence number, optional .gz). A bare prefix
		// match could otherwise sweep up unrelated same-prefix files that
		// happen to share the log directory.
		if !isBackupName(base, name) {
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

	// H2: snapshot the in-flight compression set under compressMu so cleanup
	// can skip backups still being compressed. compressMu is a separate lock
	// from w.mu to avoid the Close→Wait vs goroutine→Lock deadlock.
	w.compressMu.Lock()
	inFlight := make(map[string]struct{}, len(w.compressing))
	for k := range w.compressing {
		inFlight[k] = struct{}{}
	}
	w.compressMu.Unlock()

	var cleanupErrs []error
	// H2: collect errors but report them via pendingRotateErrors (drained
	// outside the lock by reportRotateErrors) to honor the M4 non-reentrancy
	// contract on w.mu.
	for _, b := range backups[len(keep):] {
		path := filepath.Join(dir, b.name)
		// H2: skip backups still being compressed; the compression goroutine
		// will remove the tracking entry when done, and a later cleanup pass
		// will reap it.
		if _, busy := inFlight[path]; busy {
			continue
		}
		if err := os.Remove(path); err != nil {
			cleanupErrs = append(cleanupErrs, fmt.Errorf("remove old backup %s: %w", path, err))
		}
	}
	if !cutoff.IsZero() {
		for _, b := range keep {
			if b.modTime.Before(cutoff) {
				path := filepath.Join(dir, b.name)
				if _, busy := inFlight[path]; busy {
					continue
				}
				if err := os.Remove(path); err != nil {
					cleanupErrs = append(cleanupErrs, fmt.Errorf("remove expired backup %s: %w", path, err))
				}
			}
		}
	}
	if len(cleanupErrs) > 0 {
		w.addRotateErrors(&Error{Op: "cleanup", Err: fmt.Errorf("cleanup backups: %v", errors.Join(cleanupErrs...))})
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
	fmt.Fprintf(os.Stderr, "filerotate: %v\n", err)
}

// backupSuffixRe matches the suffix appended to a rotated backup filename:
// either a millisecond timestamp (with optional sequence number) or a
// unix-nano fallback, each optionally followed by ".gz" for compressed copies.
// Used to avoid deleting unrelated same-prefix files during cleanup.
var backupSuffixRe = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}\.\d{3}|\d+)(\.\d+)?(\.gz)?$`)

// isBackupName reports whether name is a rotation artifact of base
// (i.e. base + "." + a suffix matching backupSuffixRe).
func isBackupName(base, name string) bool {
	suffix, ok := strings.CutPrefix(name, base+".")
	if !ok {
		return false
	}
	return backupSuffixRe.MatchString(suffix)
}

// Compile-time assertions.
var (
	_ io.Writer = (*Writer)(nil)
	_ io.Closer = (*Writer)(nil)
)

// checkNotSymlink verifies the log file path is not a symlink. If the file does not
// exist yet, it checks the parent directory. Intermediate system directories (e.g.
// macOS /var → /private/var) are intentionally not walked — those are legitimate
// symlinks, and TOCTOU protection is handled by openAppend's post-open inode check.
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

// openAppend opens path for create+append and defends against symlink substitution
// (TOCTOU): if the file existed before open, the opened descriptor's inode must
// match the pre-open Lstat. Without this check, an attacker who replaces the log
// path with a symlink between checkNotSymlink and OpenFile could redirect log
// writes to an arbitrary file.
func openAppend(path string, mode os.FileMode) (*os.File, os.FileInfo, error) {
	lstat, lerr := os.Lstat(path)
	preExist := lerr == nil

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, mode)
	if err != nil {
		return nil, nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, nil, err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		_ = f.Close()
		return nil, nil, fmt.Errorf("log file %s resolved to a symlink, refusing to write", path)
	}
	if preExist && !os.SameFile(lstat, fi) {
		_ = f.Close()
		return nil, nil, fmt.Errorf("log file %s was replaced between stat and open (possible symlink substitution)", path)
	}
	return f, fi, nil
}
