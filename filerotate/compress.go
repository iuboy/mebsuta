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

// cleanupTemp 关闭 dst（若非 nil）并删除 tmpPath，任何失败都会上报。
// 它集中处理 compressFile 的错误路径清理，避免清理错误
// 被（errcheck）静默丢弃，同时不影响上报原始失败。
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

// compressFile 通过临时文件 + 原子重命名将文件压缩为 .gz。
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

	// O_EXCL：绝不跟随 tmpPath 上预先埋好的符号链接。若用普通
	// O_TRUNC，监听轮转时机的攻击者可以事先放置指向受害文件的
	// <backup>.gz.tmp 符号链接，使其先被截断、后被 gzip
	// 字节覆盖。
	dst, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		reportError(onError, &Error{Op: "compress", Err: fmt.Errorf("create temp: %w", err)})
		return
	}
	// 确保 dst 始终被关闭——gzip.Writer.Close() 并不会关闭
	// 底层 writer（与常见认知相反）。若不如此，每次压缩都会
	// 泄漏一个临时文件描述符，长期运行的进程最终会触发
	// EMFILE（"too many open files"）。
	dstClosed := false
	defer func() {
		if !dstClosed {
			// 尽力而为的双重关闭防护：此处返回错误只发生在
			// 下方已上报过更早的失败之后，
			// 因此丢弃它可让最初的错误作为对外呈现的那个。
			_ = dst.Close()
		}
	}()

	gw := gzip.NewWriter(dst)
	_, err = io.Copy(gw, src)
	if err != nil {
		// 对注定失败的 writer 尽力刷新：下方的拷贝失败才是
		// 真正原因且已上报——此处再报刷新错误只会
		// 在同一失败路径上制造噪音。
		_ = gw.Close()
		cleanupTemp(dst, tmpPath, onError)
		dstClosed = true
		reportError(onError, &Error{Op: "compress", Err: fmt.Errorf("compress data: %w", err)})
		return
	}

	// gw.Close() 刷新 gzip 尾部；它不会关闭 dst。
	if err := gw.Close(); err != nil {
		cleanupTemp(dst, tmpPath, onError)
		dstClosed = true
		reportError(onError, &Error{Op: "compress", Err: fmt.Errorf("flush: %w", err)})
		return
	}

	// 重命名前先关闭 dst——在 Windows 上重命名打开中的文件会失败。
	if err := dst.Close(); err != nil {
		cleanupTemp(nil, tmpPath, onError) // dst 已关闭
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

	// 压缩成功后删除原始未压缩文件。
	// 若删除失败，.gz 与原文件会并存——应删除 .gz
	//（而不是改回去），以免用 gzip 字节破坏原始日志。
	if err := os.Remove(path); err != nil {
		reportError(onError, &Error{Op: "compress", Err: fmt.Errorf("remove original %s: %w", path, err)})
		// 尽力而为：删除 .gz，让 compressResidual 在下次
		// 启动时重试。绝不将 .gz 改名回 path（那会用 gzip
		// 二进制数据覆盖原始未压缩日志）。
		if rerr := os.Remove(gzPath); rerr != nil {
			reportError(onError, &Error{Op: "compress", Err: fmt.Errorf("cleanup orphaned .gz %s: %w", gzPath, rerr)})
		}
	}
}

// compressResidual 检测并压缩上次崩溃遗留的未压缩轮转文件。
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
			// 只清理我们自己的过期临时文件（备份名 + ".gz.tmp"）。
			// 仅按前缀匹配会误删只是恰好共享
			// 日志名前缀的无关文件。
			if !isBackupName(base, strings.TrimSuffix(name, ".tmp")) {
				continue
			}
			if err := os.Remove(filepath.Join(dir, name)); err != nil && !os.IsNotExist(err) {
				reportError(onError, &Error{Op: "compress", Err: fmt.Errorf("remove stale temp %s: %w", name, err)})
			}
			continue
		}
		// 只有轮转产物（备份时间戳/纳秒后缀，可选
		// .gz）才是候选。没有这道与 cleanupBackupsLocked 相同的
		// 门禁，任何同名前缀文件（app.log.notes、
		// app.log.2020-manual）都会在每次启动时被 gzip 压缩且原文件被删，
		// 而 Compress 默认开启。
		if !isBackupName(base, name) {
			continue
		}
		if strings.HasSuffix(name, ".gz") || strings.HasSuffix(name, ".tmp") {
			continue
		}

		if compress {
			fullPath := filepath.Join(dir, name)
			// 若 .gz 已存在则跳过——避免重复 New 调用
			//（如崩溃重启后）造成重复压缩。
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
		// M7：先向 WaitGroup 注册，再获取信号量槽位。
		// 之前的顺序（先 sem <- 再 wg.Add）留下了一个窗口：调用方
		// 已持有槽位但 goroutine 尚未被跟踪——若 New() 在该间隙返回
		// 且 Close() 随即执行，Wait 可能在压缩即将开始时观察到
		// 零个 goroutine。先 Add 后获取保证每个
		// 在途槽位都被 Wait 跟踪。
		wg.Add(1)
		sem <- struct{}{}
		go func(path string) {
			defer wg.Done()
			defer func() { <-sem }()
			compressFile(path, onError)
		}(path)
	}
}
