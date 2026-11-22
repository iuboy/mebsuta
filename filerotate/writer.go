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

// Writer 是实现 io.Writer 与 io.Closer 的轮转文件 writer。
// 它负责按大小与按时间轮转、备份管理以及可选的 gzip
// 压缩。
type Writer struct {
	mu         sync.Mutex
	file       *os.File
	size       atomic.Int64
	maxBytes   int64 // 由 cfg.MaxSizeMB * mib 预先算好，避免每次 Write 都做乘法
	rotatedAt  time.Time
	closed     atomic.Bool
	cfg        Config
	onError    atomic.Pointer[errorFunc]
	compressWg sync.WaitGroup
	// compressSem 将轮转路径上的并发压缩限制在
	// maxRotateCompressors（与 compressResidual 相同的上限）：轮转
	// 风暴不得衍生出无界的 gzip fan-out。rotateLocked 在启动压缩前
	// 先获取槽位，超出的压缩会排队（绝不丢弃）；获取动作
	// 发生在 w.mu 之下也是安全的，因为压缩
	// goroutine 释放槽位时从不需要 w.mu。
	compressSem chan struct{}
	// H2：当前正在压缩的路径；cleanupBackupsLocked 会跳过它们。
	// 使用独立锁，压缩 goroutine 标记路径完成时
	// 无需获取 w.mu——Close() 等待 compressWg 期间持有
	// w.mu，goroutine 里再锁 w.mu 会死锁。
	compressMu  sync.Mutex
	compressing map[string]struct{}
	// M4：rotateLocked（在 w.mu 之下）把错误追加到这里；reportRotateErrors
	//（在 w.mu 之外，多个 Write 调用方并发）负责清空。用单独的
	// 锁保护该切片，保证先解锁再上报的模式无数据竞争。
	errMu               sync.Mutex
	pendingRotateErrors []error
}

// errorFunc 包装函数类型，以便配合 atomic.Pointer 使用。
type errorFunc struct {
	fn func(error)
}

// maxRotateCompressors 是轮转备份并发 gzip 压缩的上限——
// 与 compressResidual 的 maxConcurrent=4 保持一致。
const maxRotateCompressors = 4

// New 根据给定配置创建轮转文件 writer。
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
		maxBytes:    int64(cfg.MaxSizeMB) * mib,
		rotatedAt:   time.Now(),
		cfg:         cfg,
		compressing: make(map[string]struct{}),
		compressSem: make(chan struct{}, maxRotateCompressors),
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

// Write 将字节写入日志文件，必要时触发轮转。
func (w *Writer) Write(p []byte) (int, error) {
	if w.closed.Load() {
		return 0, os.ErrClosed
	}

	w.mu.Lock()

	if w.closed.Load() || w.file == nil {
		w.mu.Unlock()
		return 0, os.ErrClosed
	}

	// 写前轮转检查。
	if w.needsRotation() {
		w.rotateLocked()
	}

	// H1：rotateLocked 可能失败（磁盘满、权限、恢复失败），
	// 导致 w.file == nil。重新检查以避免空指针 panic。
	if w.file == nil {
		w.mu.Unlock()
		w.reportRotateErrors()
		return 0, os.ErrClosed
	}

	n, err := w.file.Write(p)
	if n > 0 {
		w.size.Add(int64(n))
	}

	// 写后轮转检查：若本次写入超过上限，
	// 立即轮转，避免超限文件一直留存到下一次
	// Write 调用（低频日志可能永远等不到那次调用）。
	if err == nil && w.needsRotation() {
		w.rotateLocked()
	}
	// 仍在持有 mu 时快照 closed，避免并发的 Close
	// 让一次成功写入莫名返回 os.ErrClosed。
	isClosed := w.closed.Load()
	w.mu.Unlock()

	// M4：在锁外上报轮转错误，防止用户的
	// onError 回调重入 Writer 造成死锁。
	w.reportRotateErrors()

	// 若写后轮转失败并关闭了 writer，写入本身
	// 仍算成功——返回写入字节数，让下一次 Write 返回 ErrClosed。
	if isClosed {
		return n, os.ErrClosed
	}

	return n, err
}

// Close 等待异步压缩完成后关闭文件。
//
// M6：Close 会阻塞到所有在途 gzip 压缩结束。没有
// 超时限制——慢速磁盘上的超大备份可能无限拖延关闭。
// 若关闭路径需要上限，请在调用 Close 前另行排空压缩，
// 或跳过 Close，让进程退出时回收这些 goroutine。
func (w *Writer) Close() error {
	if !w.closed.CompareAndSwap(false, true) {
		return nil
	}

	// 在 Wait 之前先取写锁，防止并发 rotate() 在 Wait 返回后
	// 再调用 compressWg.Add(1)。没有这把锁，时序会是：
	// Close 置 closed=true，Wait 看到 0 个 goroutine，加锁+关闭
	// 文件——而一个已通过 closed.Load() 检查的 rotate()
	// 此时启动新的压缩 goroutine，存活时间超过 Close。
	w.mu.Lock()

	w.compressWg.Wait()

	// H2：全部压缩结束后重新执行清理，回收之前因正在压缩
	// 而被跳过的备份。否则高频轮转风暴
	// 可能遗留过期备份。
	var closeErr error
	if w.file != nil {
		w.cleanupBackupsLocked()
		closeErr = w.file.Close()
		w.file = nil
	}
	w.mu.Unlock()

	// M4 契约：在 w.mu 之外上报待处理的轮转错误。Write
	// 路径已遵守；在锁内上报会让任何重入 Writer 的 OnError
	// 回调死锁（例如通过同一个 writer
	// 记录该错误）。
	w.reportRotateErrors()

	return closeErr
}

// SetOnError 更新错误回调。可并发调用。
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

// needsRotation 检查是否需要轮转。调用方必须持有 w.mu。
func (w *Writer) needsRotation() bool {
	if w.maxBytes > 0 && w.size.Load() >= w.maxBytes {
		return true
	}
	if w.cfg.RotateInterval > 0 && time.Since(w.rotatedAt) >= w.cfg.RotateInterval {
		return true
	}
	return false
}

// rotateLocked 执行轮转。重新检查条件以避免惊群。
// 调用方必须持有 w.mu。
//
// M4：错误先收集，待锁释放后（由调用方 Write/rotateAndReport）经
// reportRotateErrors 上报，这样触碰 Writer 的用户自定义
// onError 回调不会在不可重入的
// w.mu 上死锁。
func (w *Writer) rotateLocked() {
	if w.closed.Load() || w.file == nil {
		return
	}
	if !w.needsRotation() {
		return
	}

	// M5：关闭前尽力 fsync，让页缓存数据在轮转后
	// 紧接着的崩溃中也能幸存。Sync 错误并非致命（可能是管道或
	// 不支持 fsync 的文件系统）；收集后继续关闭。
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
		// H2：跟踪在途压缩路径，让 cleanupBackupsLocked
		// 跳过它，避免删除仍在压缩中的备份。
		// 用 compressMu（而非 w.mu）保护 compressing，因为 Close() 等待
		// compressWg 时持有 w.mu——这里再锁 w.mu 会死锁。
		w.compressMu.Lock()
		w.compressing[backup] = struct{}{}
		w.compressMu.Unlock()
		// 将并发压缩限制在 maxRotateCompressors，与
		// compressResidual 对齐：轮转风暴（大量连续越过
		// MaxSizeMB 的 Write 调用）不得衍生出无界的 gzip fan-out
		//（goroutine 与文件描述符）。在启动压缩前先获取槽位
		// 意味着超出的压缩在此排队（绝不丢弃）；在
		// w.mu 下阻塞也不会死锁，因为压缩 goroutine 释放槽位
		//（以及结束）都不需要 w.mu。M7 顺序：先向
		// WaitGroup 注册再获取槽位，保证每个在途槽位也被
		// Wait 跟踪（Close 在 w.mu 下等待）。
		w.compressWg.Add(1)
		w.compressSem <- struct{}{}
		go func() {
			defer w.compressWg.Done()
			defer func() { <-w.compressSem }()
			compressFile(backup, w.loadOnError())
			w.compressMu.Lock()
			delete(w.compressing, backup)
			w.compressMu.Unlock()
		}()
	}

	w.cleanupBackupsLocked()
	w.addRotateErrors(errs...)
}

// reportRotateErrors 清空待处理的轮转错误并经 onError 上报。
// 调用方不得持有 w.mu——这正是 M4 死锁修复。待处理切片
// 由 errMu 保护，多个并发 Write 调用方都能安全清空。
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

// addRotateErrors 在 errMu 之下向待处理切片追加错误。持有
// w.mu 时调用也安全——加锁顺序为 w.mu → errMu（与
// 不带 w.mu 直接取 errMu 的 reportRotateErrors 一致）。
func (w *Writer) addRotateErrors(errs ...error) {
	if len(errs) == 0 {
		return
	}
	w.errMu.Lock()
	w.pendingRotateErrors = append(w.pendingRotateErrors, errs...)
	w.errMu.Unlock()
}

// recoverOpen 在轮转失败后尝试重新打开日志文件。
// M3：用重新打开的文件更新 w.size 与 w.rotatedAt，让下一次
// needsRotation() 检查符合实际，而不是立刻触发
// 重复轮转循环。错误收集进 pendingRotateErrors，由
// reportRotateErrors() 在锁外清空（M4）。
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

// backupNameLocked 生成唯一的备份文件名。调用方必须持有 w.mu 写锁。
// 用一次 ReadDir 调用 + 内存集合，避免最多 maxRotationSuffixSeq 次 Stat 系统调用。
func (w *Writer) backupNameLocked() string {
	ts := time.Now().Format("2006-01-02T15-04-05.000")
	name := w.cfg.Path + "." + ts

	// 仅一次 ReadDir 获取日志目录下全部现存文件。
	dir := filepath.Dir(w.cfg.Path)
	entries, err := os.ReadDir(dir)
	if err != nil {
		// 兜底：读不了目录，直接使用该名称。
		return name
	}

	// 构建现存文件名集合，O(1) 查找。
	existing := make(map[string]struct{}, len(entries))
	for _, e := range entries {
		existing[e.Name()] = struct{}{}
	}

	base := filepath.Base(name)
	if _, found := existing[base]; !found {
		return name
	}
	for i := 1; i < maxRotationSuffixSeq; i++ {
		candidate := fmt.Sprintf("%s.%d", base, i)
		if _, found := existing[candidate]; !found {
			return filepath.Join(dir, candidate)
		}
	}
	return w.cfg.Path + "." + fmt.Sprintf("%d", time.Now().UnixNano())
}

// cleanupBackupsLocked 删除超出 MaxBackups 或 MaxAgeDays 的旧备份文件。
// 调用方必须持有 w.mu 写锁。
func (w *Writer) cleanupBackupsLocked() {
	cfg := w.cfg
	if cfg.MaxBackups == 0 && cfg.MaxAgeDays == 0 {
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
		// 只考虑后缀是真正轮转产物
		//（时间戳、可选序号、可选 .gz）的文件。若仅按前缀
		// 匹配，可能误扫恰好同处日志目录的
		// 无关同名前缀文件。
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
	// MaxBackups 为负表示不限（保留全部备份）。
	if cfg.MaxBackups > 0 && len(keep) > cfg.MaxBackups {
		keep = keep[:cfg.MaxBackups]
	}

	cutoff := time.Time{}
	// MaxAgeDays 为负表示不限（不按时间删除）。
	if cfg.MaxAgeDays > 0 {
		cutoff = time.Now().AddDate(0, 0, -cfg.MaxAgeDays)
	}

	// H2：在 compressMu 之下快照在途压缩集合，让清理
	// 跳过仍在压缩中的备份。compressMu 独立于
	// w.mu，以避免 Close→Wait 与 goroutine→Lock 的死锁。
	w.compressMu.Lock()
	inFlight := make(map[string]struct{}, len(w.compressing))
	for k := range w.compressing {
		inFlight[k] = struct{}{}
	}
	w.compressMu.Unlock()

	var cleanupErrs []error
	// H2：收集错误但经 pendingRotateErrors 上报（由
	// reportRotateErrors 在锁外清空），以遵守 w.mu 上的 M4
	// 不可重入契约。
	for _, b := range backups[len(keep):] {
		path := filepath.Join(dir, b.name)
		// H2：跳过仍在压缩中的备份；压缩 goroutine
		// 完成后会移除跟踪条目，之后的清理
		// 会将其回收。
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

// reportError 在 onError 非 nil 时调用它，否则回退到 stderr。
func reportError(onError func(error), err error) {
	if onError != nil {
		onError(err)
	}
}

// defaultOnError 将错误详情写入 os.Stderr。
func defaultOnError(err error) {
	fmt.Fprintf(os.Stderr, "filerotate: %v\n", err)
}

// backupSuffixRe 匹配轮转备份文件名追加的后缀：
// 毫秒时间戳（可带序号）或 unix-nano 兜底，二者
// 都可后跟 ".gz" 表示压缩副本。
// nano 兜底要求至少 15 位数字：纳秒时间戳如今是 19 位，
// 近至 2001 年还有 18 位；而裸 \d+ 会误扫
// app.log.12345 这类无关同名前缀文件——compressResidual
// （Compress 默认开启）会在每次启动时将其 gzip 压缩并删除。
var backupSuffixRe = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}\.\d{3}|\d{15,})(\.\d+)?(\.gz)?$`)

// isBackupName 判断 name 是否为 base 的轮转产物
// （即 base + "." + 符合 backupSuffixRe 的后缀）。
func isBackupName(base, name string) bool {
	suffix, ok := strings.CutPrefix(name, base+".")
	if !ok {
		return false
	}
	return backupSuffixRe.MatchString(suffix)
}

// 编译期断言。
var (
	_ io.Writer = (*Writer)(nil)
	_ io.Closer = (*Writer)(nil)
)

// checkNotSymlink 校验日志文件路径不是符号链接。若文件尚不
// 存在，则检查父目录。中间系统目录（如
// macOS 的 /var → /private/var）有意不逐一检查——它们是合法的
// 符号链接，最终组件的 TOCTOU 防护由
// openAppend 的 O_NOFOLLOW 与打开后的 inode 比较承担。
func checkNotSymlink(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("stat log file: %w", err)
		}
		// 文件尚不存在——检查父目录。
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

// openAppend 以创建+追加模式打开 path，用两层防护
// 抵御符号链接替换（TOCTOU）：
//
//  1. O_NOFOLLOW（Unix）：open 自身拒绝符号链接的最终组件——
//     包括轮转期间的关键窗口，此时 os.Rename 让路径
//     短暂不存在，预先埋好的符号链接本会被 O_CREATE
//     跟随。这补上了 inode 检查覆盖不到的情形：Lstat 时
//     路径尚不存在，就没有打开前的 inode 可供
//     比较。
//  2. inode 比较：若打开前文件已存在，打开的
//     描述符的 inode 必须与打开前 Lstat 的一致。在 Windows 上
//     （没有 O_NOFOLLOW）这是已存在文件的唯一防线。
func openAppend(path string, mode os.FileMode) (*os.File, os.FileInfo, error) {
	lstat, lerr := os.Lstat(path)
	preExist := lerr == nil

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND|openNoFollow, mode)
	if err != nil {
		return nil, nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, nil, err
	}
	if preExist && !os.SameFile(lstat, fi) {
		_ = f.Close()
		return nil, nil, fmt.Errorf("log file %s was replaced between stat and open (possible symlink substitution)", path)
	}
	return f, fi, nil
}
