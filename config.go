package mebsuta

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/iuboy/mebsuta/internal/handlerkit"
)

// ConfigError 表示配置校验错误。
type ConfigError struct {
	Field string
	Msg   string
}

func (e *ConfigError) Error() string {
	return e.Field + ": " + e.Msg
}

// --- FileConfig ---

// 默认配置值。
const (
	DefaultAsyncBufferSize = 256

	// DefaultErrorTimeout 限定 Error 及以上级别的记录在缓冲无空间时
	// 阻塞调用方 goroutine 的最长时间，超时后丢弃。slog 的调用方通常
	// 是请求处理者：长时间阻塞会把「慢速下游 + Error 洪峰」放大为
	// 整个服务的停摆。
	DefaultErrorTimeout = time.Second

	DefaultSamplingInitial    = 100
	DefaultSamplingThereafter = 10
	DefaultSamplingWindow     = time.Second
)

// FileConfig 持有文件日志输出的 mebsuta 专属配置（格式与级别）。
// 轮转配置由 filerotate.Config 处理。
type FileConfig struct {
	Level    slog.Leveler   // 日志级别过滤。默认 slog.LevelInfo。
	Format   string         // "json" 或 "console"。默认 "json"。
	Timezone *time.Location // 日志时间展示时区，nil 用 UTC。
}

// Validate 返回应用默认值后的规范化副本。
func (c FileConfig) Validate() (FileConfig, error) {
	if handlerkit.IsNilLeveler(c.Level) {
		c.Level = slog.LevelInfo
	}
	if err := validateFormat(c.Format); err != nil {
		return c, err
	}
	if c.Format == "" {
		c.Format = "json"
	}
	return c, nil
}

// --- StdoutConfig ---

// StdoutConfig 持有 stdout 日志输出的配置。
// 它有意与 FileConfig 保持镜像而非共享公共嵌入类型，因为文件与
// stdout 输出未来可能分道扬镳（如 stdout 增加颜色/主题选项、文件增加
// 压缩设置）。保持分离可避免二者独立演进时产生破坏性 API 变更。
type StdoutConfig struct {
	Level    slog.Leveler   // 日志级别过滤。默认 slog.LevelInfo。
	Format   string         // "json" 或 "console"。默认 "json"。
	Timezone *time.Location // 日志时间展示时区，nil 用 UTC。
}

// Validate 检查必填字段并返回应用默认值后的规范化副本。
func (c StdoutConfig) Validate() (StdoutConfig, error) {
	if handlerkit.IsNilLeveler(c.Level) {
		c.Level = slog.LevelInfo
	}
	if err := validateFormat(c.Format); err != nil {
		return c, err
	}
	if c.Format == "" {
		c.Format = "json"
	}
	return c, nil
}

// level 返回生效的 slog.Level，解析任意 Leveler 实现。
// 与直接调用 c.Level.Level() 不同，当 Leveler 接口中存有类型化 nil
// 指针（如 (*slog.Level)(nil)）时可避免 panic。
func (c StdoutConfig) level() slog.Level {
	return handlerkit.SafeLevel(c.Level)
}

// validateFormat 拒绝不支持的 Format 值（如 "text"、"yaml"），否则它们会在
// newInnerHandler 的 default 分支中静默落到 JSON——一种用户要求 console 却
// 得到 JSON 的静默配置错误。空格式合法，由调用方默认为 "json"。
func validateFormat(format string) error {
	switch format {
	case "", "json", "console":
		return nil
	default:
		return &ConfigError{Field: "Format", Msg: fmt.Sprintf("unsupported format %q (must be \"json\" or \"console\")", format)}
	}
}

// --- AsyncConfig ---

// MaxAsyncBufferSize 是 AsyncConfig.BufferSize 的上界。channel 在构造时
// 立即分配，未经校验的巨大值（如配置文件误读出的 1<<30）会造成构造期
// OOM：每个槽位都为一个完整 asyncRecord 预留空间。10000 与 syslog、
// database handler 的积压上限一致。
const MaxAsyncBufferSize = 10000

// AsyncConfig 持有异步日志处理的配置。
type AsyncConfig struct {
	// BufferSize 是 channel 缓冲大小。0 → 256；超过 MaxAsyncBufferSize
	// 的值以 *ConfigError 拒绝。
	BufferSize int
	// ErrorTimeout 限定缓冲满时 Error 及以上级别的记录阻塞调用方
	// goroutine 的最长时间，超时后丢弃该记录。0 → 1s。
	ErrorTimeout time.Duration
}

// Validate 检查必填字段并返回应用默认值后的规范化副本。
func (c AsyncConfig) Validate() (AsyncConfig, error) {
	if c.BufferSize <= 0 {
		c.BufferSize = DefaultAsyncBufferSize
	} else if c.BufferSize > MaxAsyncBufferSize {
		return AsyncConfig{}, &ConfigError{
			Field: "BufferSize",
			Msg:   fmt.Sprintf("buffer size %d exceeds maximum %d", c.BufferSize, MaxAsyncBufferSize),
		}
	}
	if c.ErrorTimeout <= 0 {
		c.ErrorTimeout = DefaultErrorTimeout
	}
	return c, nil
}

// --- SamplingConfig ---

// SamplingConfig 持有日志采样的配置。
type SamplingConfig struct {
	Enabled    bool          // 启用采样。
	Initial    int           // 每窗口前 N 条始终记录。0 → 100。
	Thereafter int           // 初始之后每 N 条记 1 条。0 → 10。
	Window     time.Duration // 采样窗口时长。0 → 1s。
}

// Validate 检查必填字段并返回应用默认值后的规范化副本。
func (c SamplingConfig) Validate() (SamplingConfig, error) {
	if !c.Enabled {
		return c, nil
	}
	if c.Initial <= 0 {
		c.Initial = DefaultSamplingInitial
	}
	if c.Thereafter <= 0 {
		c.Thereafter = DefaultSamplingThereafter
	}
	if c.Window <= 0 {
		c.Window = DefaultSamplingWindow
	}
	return c, nil
}
