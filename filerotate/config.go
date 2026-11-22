// Package filerotate 为结构化日志提供轮转文件 writer。
//
// 它支持按大小与按时间轮转、带数量与时长上限的备份管理，
// 以及可选的 gzip 压缩——类似 lumberjack，但
// 是可与任意 slog.Handler 配合的 io.Writer。
//
// 用法：
//
//	w, _ := filerotate.New(filerotate.Config{Path: "/var/log/app.log", MaxSizeMB: 100})
//	defer w.Close()
//	logger := slog.New(slog.NewJSONHandler(w, nil))
//	logger.Info("hello")
package filerotate

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// 默认配置值。
const (
	DefaultMaxSizeMB  = 100
	DefaultMaxBackups = 5
	DefaultMaxAgeDays = 30

	mib                  = 1 << 20
	maxRotationSuffixSeq = 1000

	// maxConfigurableSizeMB 限制 MaxSizeMB 上限。超过它后字节换算
	//（int64 * mib）会溢出为负数，经 maxBytes > 0 检查静默
	// 禁用大小轮转。1<<20 MiB = 1 PiB。
	maxConfigurableSizeMB = 1 << 20

	// minRotateInterval 是可接受的最小按时间轮转周期。
	// 裁定（2026-11 第 4 轮审计）：亚秒级间隔会让几乎每次 Write 的
	// time.Since(rotatedAt) >= interval 都为真，而每次轮转都要付出
	// sync + close + rename + open + cleanup（Compress 路径还要加压缩）
	// 的代价——实测 1ns 间隔会使写入慢约 1700 倍。低于下限的值一律
	// 拒绝（构造时 fail-fast，绝不静默钳制），并在消息中给出合法范围；
	// 0 仍表示仅按大小轮转。
	minRotateInterval = time.Second
)

// DefaultFileMode 是日志文件与轮转备份的默认文件权限。
const DefaultFileMode os.FileMode = 0600

// Config 保存轮转文件 writer 的配置。
type Config struct {
	// Path 为日志文件的绝对路径。必填。
	//
	// 单 writer 假设：同一进程内，一个路径只能有一个 Writer——
	// 两个 Writer 各自轮转和清理，会破坏彼此的备份记账。
	// 跨进程时，同一路径上的并发写入同样不受支持：轮转归属与
	// 备份清理的交错顺序不确定。数据不会丢失
	//（轮转是重命名 + 全新追加），但 MaxBackups/MaxAgeDays 保留
	// 与按时间轮转会变得不可靠——请让每个进程
	// 写入不同路径。
	Path string
	// MaxSizeMB 为触发轮转的最大文件大小（MiB）。≤0 → 100。
	MaxSizeMB int
	// MaxBackups 为保留的轮转备份文件数量上限。
	// 0 → 默认值（5）。<0 → 不限（保留全部备份）。
	MaxBackups int
	// MaxAgeDays 为备份文件的最大保留天数。
	// 0 → 默认值（30）。<0 → 不限（不按时间删除）。
	MaxAgeDays int
	// Compress 是否对轮转备份启用 gzip 压缩。nil → true。
	Compress *bool
	// RotateInterval 按该间隔触发按时间轮转。
	// 0 = 仅按大小。亚秒级间隔会被拒绝：裁定见 minRotateInterval
	//（1ns 间隔会使写入慢约 1700 倍）。
	RotateInterval time.Duration
	// 日志文件的 FileMode。0 → 0600。
	FileMode os.FileMode
	// OnError 在内部错误（轮转失败、压缩失败等）时被调用。
	// nil → 写入 os.Stderr。
	OnError func(error)
}

// UnlimitedBackups 是 MaxBackups 的哨兵值，表示“保留全部备份”。
const UnlimitedBackups = -1

// UnlimitedAge 是 MaxAgeDays 的哨兵值，表示“不按时间删除”。
const UnlimitedAge = -1

// Validate 检查必填字段，并返回应用默认值后的规范化副本。
func (c Config) Validate() (Config, error) {
	if c.Path == "" {
		return Config{}, fmt.Errorf("file path is required")
	}
	if !filepath.IsAbs(c.Path) {
		return Config{}, fmt.Errorf("file path must be absolute: %s", c.Path)
	}
	if c.MaxSizeMB <= 0 {
		c.MaxSizeMB = DefaultMaxSizeMB
	}
	if c.MaxSizeMB > maxConfigurableSizeMB {
		return Config{}, fmt.Errorf("MaxSizeMB too large (max %d MiB): %d", maxConfigurableSizeMB, c.MaxSizeMB)
	}
	if c.MaxBackups == 0 {
		c.MaxBackups = DefaultMaxBackups
	}
	if c.MaxAgeDays == 0 {
		c.MaxAgeDays = DefaultMaxAgeDays
	}
	if c.Compress == nil {
		c.Compress = boolPtr(true)
	}
	if c.FileMode == 0 {
		c.FileMode = DefaultFileMode
	}
	// RotateInterval == 0 表示仅按大小轮转（文档如此）。负值
	// 毫无意义，会使 time.Since(rotatedAt) >= interval
	// 恒为真，每次 Write 都强制轮转——应显式拒绝
	// 而非静默退化。正的亚秒值只是以稍慢的速率触发同样的
	// 病理（实测 1ns 下写入慢约 1700 倍，见 minRotateInterval），
	// 因此同样被拒绝——按 fail-fast 约定，下限是
	// 报错而非钳制（配置错误必须在构造时暴露，
	// 绝不留作莫名其妙的运行时退化）。
	if c.RotateInterval < 0 {
		return Config{}, fmt.Errorf("RotateInterval must be >= 0, got %v", c.RotateInterval)
	}
	if c.RotateInterval > 0 && c.RotateInterval < minRotateInterval {
		return Config{}, fmt.Errorf("RotateInterval must be 0 (size-only) or at least %v, got %v", minRotateInterval, c.RotateInterval)
	}
	return c, nil
}

func (c Config) compress() bool {
	return c.Compress != nil && *c.Compress
}

func boolPtr(b bool) *bool { return &b }

// Error 表示轮转 writer 的内部错误。
type Error struct {
	Op  string // "rotate", "compress", "cleanup", "write"
	Err error
}

func (e *Error) Unwrap() error { return e.Err }

func (e *Error) Error() string {
	// H3：防御 Err 为 nil——Error 类型是导出的并会经
	// OnError 暴露给用户代码，直接构造时不能 panic。
	msg := "filerotate/" + e.Op
	if e.Err != nil {
		msg += ": " + e.Err.Error()
	}
	return msg
}
