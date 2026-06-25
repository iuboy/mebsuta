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

	gw := gzip.NewWriter(dst)
	_, err = io.Copy(gw, src)
	if err != nil {
		cleanupTemp(dst, tmpPath, onError)
		reportError(onError, &Error{Op: "compress", Err: fmt.Errorf("compress data: %w", err)})
		return
	}

	if err := gw.Close(); err != nil {
		cleanupTemp(dst, tmpPath, onError)
		reportError(onError, &Error{Op: "compress", Err: fmt.Errorf("flush: %w", err)})
		return
	}

	if err := dst.Close(); err != nil {
		cleanupTemp(nil, tmpPath, onError)
		reportError(onError, &Error{Op: "compress", Err: fmt.Errorf("close temp: %w", err)})
		return
	}

	if err := os.Rename(tmpPath, gzPath); err != nil {
		cleanupTemp(nil, tmpPath, onError)
		reportError(onError, &Error{Op: "compress", Err: fmt.Errorf("rename: %w", err)})
		return
	}

	if err := os.Remove(path); err != nil {
		reportError(onError, &Error{Op: "compress", Err: fmt.Errorf("remove original %s: %w", path, err)})
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
			toCompress = append(toCompress, filepath.Join(dir, name))
		}
	}

	if len(toCompress) == 0 {
		return
	}

	const maxConcurrent = 4
	sem := make(chan struct{}, maxConcurrent)
	for _, path := range toCompress {
		sem <- struct{}{}
		wg.Add(1)
		go func(path string) {
			defer wg.Done()
			defer func() { <-sem }()
			compressFile(path, onError)
		}(path)
	}
}
