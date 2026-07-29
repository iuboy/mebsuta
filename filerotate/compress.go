package filerotate

import (
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// cleanupTemp closes dst (if non-nil) and removes tmpPath, reporting any failure.
// It centralizes the error-path cleanup for compressFile so that cleanup errors
// are not silently dropped (errcheck) while still reporting the original failure.
func cleanupTemp(dst io.Closer, tmpPath string, onError func(error)) {
	if dst != nil {
		if err := dst.Close(); err != nil {
			reportError(onError, &Error{Op: "compress", Err: fmt.Errorf("close temp on cleanup: %w", err)})
		}
	}
	if err := os.Remove(tmpPath); err != nil && !os.IsNotExist(err) {
		reportError(onError, &Error{Op: "compress", Err: fmt.Errorf("remove temp %s on cleanup: %w", tmpPath, err)})
	}
}

// compressFile compresses a file to .gz using a temp file + atomic rename.
func compressFile(path string, onError func(error)) {
	gzPath := path + ".gz"
	tmpPath := gzPath + ".tmp"

	src, err := os.Open(path)
	if err != nil {
		reportError(onError, &Error{Op: "compress", Err: fmt.Errorf("open %s: %w", path, err)})
		return
	}
	defer func() {
		if err := src.Close(); err != nil {
			reportError(onError, &Error{Op: "compress", Err: fmt.Errorf("close source %s: %w", path, err)})
		}
	}()

	dst, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		reportError(onError, &Error{Op: "compress", Err: fmt.Errorf("create temp: %w", err)})
		return
	}
	// Ensure dst is always closed — gzip.Writer.Close() does NOT close the
	// underlying writer (contrary to common assumption). Without this, the
	// temp file descriptor leaks on every compression, eventually causing
	// EMFILE ("too many open files") in long-running processes.
	dstClosed := false
	defer func() {
		if !dstClosed {
			dst.Close()
		}
	}()

	gw := gzip.NewWriter(dst)
	_, err = io.Copy(gw, src)
	if err != nil {
		gw.Close()
		cleanupTemp(dst, tmpPath, onError)
		dstClosed = true
		reportError(onError, &Error{Op: "compress", Err: fmt.Errorf("compress data: %w", err)})
		return
	}

	// gw.Close() flushes the gzip footer; it does NOT close dst.
	if err := gw.Close(); err != nil {
		cleanupTemp(dst, tmpPath, onError)
		dstClosed = true
		reportError(onError, &Error{Op: "compress", Err: fmt.Errorf("flush: %w", err)})
		return
	}

	// Close dst before renaming — on Windows, renaming an open file fails.
	if err := dst.Close(); err != nil {
		cleanupTemp(nil, tmpPath, onError) // dst already closed
		dstClosed = true
		reportError(onError, &Error{Op: "compress", Err: fmt.Errorf("close temp: %w", err)})
		return
	}
	dstClosed = true

	if err := os.Rename(tmpPath, gzPath); err != nil {
		cleanupTemp(nil, tmpPath, onError)
		reportError(onError, &Error{Op: "compress", Err: fmt.Errorf("rename: %w", err)})
		return
	}

	// Remove the original uncompressed file after successful compression.
	// If removal fails, both .gz and the original coexist — remove the .gz
	// (not rename it back) to avoid corrupting the original log with gzip bytes.
	if err := os.Remove(path); err != nil {
		reportError(onError, &Error{Op: "compress", Err: fmt.Errorf("remove original %s: %w", path, err)})
		// Best-effort: remove the .gz so compressResidual re-attempts on next
		// startup. Do NOT rename .gz→path (that would overwrite the original
		// uncompressed log with gzip binary data).
		if rerr := os.Remove(gzPath); rerr != nil {
			reportError(onError, &Error{Op: "compress", Err: fmt.Errorf("cleanup orphaned .gz %s: %w", gzPath, rerr)})
		}
	}
}

// compressResidual detects and compresses uncompressed rotated files left behind by a previous crash.
func compressResidual(logPath string, compress bool, wg *sync.WaitGroup, onError func(error)) {
	dir := filepath.Dir(logPath)
	base := filepath.Base(logPath)

	entries, err := os.ReadDir(dir)
	if err != nil {
		reportError(onError, &Error{Op: "compress", Err: fmt.Errorf("readdir %s: %w", dir, err)})
		return
	}

	prefix := base + "."
	var toCompress []string
	for _, e := range entries {
		name := e.Name()
		if name == base || !strings.HasPrefix(name, prefix) {
			continue
		}
		if strings.HasSuffix(name, ".gz.tmp") {
			if err := os.Remove(filepath.Join(dir, name)); err != nil && !os.IsNotExist(err) {
				reportError(onError, &Error{Op: "compress", Err: fmt.Errorf("remove stale temp %s: %w", name, err)})
			}
			continue
		}
		if strings.HasSuffix(name, ".gz") || strings.HasSuffix(name, ".tmp") {
			continue
		}

		if compress {
			fullPath := filepath.Join(dir, name)
			// Skip if .gz already exists — avoids duplicate compression on
			// repeated New calls (e.g., after a crash restart).
			if _, err := os.Stat(fullPath + ".gz"); err == nil {
				continue
			}
			toCompress = append(toCompress, fullPath)
		}
	}

	if len(toCompress) == 0 {
		return
	}

	const maxConcurrent = 4
	sem := make(chan struct{}, maxConcurrent)
	for _, path := range toCompress {
		// M7: register with the WaitGroup BEFORE acquiring the semaphore slot.
		// The previous order (sem <- then wg.Add) left a window where the caller
		// held a slot but the goroutine was not yet tracked — if New() returned
		// and Close() ran in that gap, Wait could observe zero goroutines while a
		// compression was about to start. Add-then-acquire guarantees every
		// in-flight slot is also Wait-tracked.
		wg.Add(1)
		sem <- struct{}{}
		go func(path string) {
			defer wg.Done()
			defer func() { <-sem }()
			compressFile(path, onError)
		}(path)
	}
}
