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

// compressFile compresses a file to .gz using a temp file + atomic rename.
func compressFile(path string, onError func(error)) {
	gzPath := path + ".gz"
	tmpPath := gzPath + ".tmp"

	src, err := os.Open(path)
	if err != nil {
		reportError(onError, &Error{Op: "compress", Err: fmt.Errorf("open %s: %w", path, err)})
		return
	}
	defer src.Close()

	dst, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		reportError(onError, &Error{Op: "compress", Err: fmt.Errorf("create temp: %w", err)})
		return
	}

	gw := gzip.NewWriter(dst)
	_, err = io.Copy(gw, src)
	if err != nil {
		dst.Close()
		os.Remove(tmpPath)
		reportError(onError, &Error{Op: "compress", Err: fmt.Errorf("compress data: %w", err)})
		return
	}

	if err := gw.Close(); err != nil {
		dst.Close()
		os.Remove(tmpPath)
		reportError(onError, &Error{Op: "compress", Err: fmt.Errorf("flush: %w", err)})
		return
	}

	if err := dst.Close(); err != nil {
		os.Remove(tmpPath)
		reportError(onError, &Error{Op: "compress", Err: fmt.Errorf("close temp: %w", err)})
		return
	}

	if err := os.Rename(tmpPath, gzPath); err != nil {
		os.Remove(tmpPath)
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
	for _, e := range entries {
		name := e.Name()
		if name == base || !strings.HasPrefix(name, prefix) {
			continue
		}
		if strings.HasSuffix(name, ".gz.tmp") {
			os.Remove(filepath.Join(dir, name))
			continue
		}
		if strings.HasSuffix(name, ".gz") || strings.HasSuffix(name, ".tmp") {
			continue
		}

		if compress {
			wg.Add(1)
			go func(path string) {
				defer wg.Done()
				compressFile(path, onError)
			}(filepath.Join(dir, name))
		}
	}
}
