// Package syslog 通过 RFC3164/RFC5424 syslog（TCP/UDP，
// 可选 TLS）外发日志记录。
//
// # 维护模式（0.1.0-7 起）
//
// syslog 属二线支持：包保持可用且有测试，
// 但不再新增功能。一线网络输出为 OTLP
// （mebsuta/otlp + mebsuta/telemetry）、database handler
// （含事务双写）与 mbta 通道；本地输出（stdout、
// file+filerotate）不受此分级影响。新集成应优先
// 选择 OTLP，除非遗留 syslog collector 是硬性
// 要求。
package syslog

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/iuboy/mebsuta"
)

// DefaultFacility 是 Config.Facility 为零时使用的 syslog facility。
// Go 的 int 零值为 0（LOG_KERN），但用户态应用默认应使用
// LOG_USER（1）。若确需 LOG_KERN，请显式将 Facility 设为
// syslog.LOG_KERN（0）——Validate 会保留它，因为从用户视角
// 该字段已经是“非零”赋值。
const DefaultFacility = 1

// MaxRetryDelay 限制 Config.RetryDelay 上限。每次失败的写尝试都会
// 等待 RetryDelay；误配成数分钟的延迟会成倍放大
// writeWithRetry 与 Close 排空的最坏阻塞时间。
const MaxRetryDelay = 30 * time.Second

// Config 保存 syslog 输出的配置。
type Config struct {
	Network  string       // "tcp"、"udp"、"unix"。默认 "tcp"。
	Address  string       // 必填：syslog 服务地址（如 "localhost:514"）。
	Level    slog.Leveler // 日志级别过滤。默认 slog.LevelInfo。
	Tag      string       // syslog tag。默认 "mebsuta"。
	Facility int          // syslog facility（0-23）。0 → DefaultFacility（1=user）。
	// 关于 0 为何重映射为 1（user）而非保留为 0（kernel）——即 int 的
	// Go 零值——见 DefaultFacility。
	Reconnect     *bool         // 断连后自动重连。nil → true。
	RetryDelay    time.Duration // 重连尝试间隔。0 → 500ms。
	TLSSkipVerify bool          // 跳过 TLS 证书校验。
	StaticHost    string        // 覆盖系统主机名。
	Secure        bool          // 启用 TLS。
	// RFC3164 使用 RFC3164 格式而非 RFC5424。默认 false = RFC5424
	//（0.1.0-25 起反转：此前默认 RFC3164 是历史遗留——RFC3164 没有
	// structured-data 字段，全部属性与审计契约字段被静默丢弃）。
	RFC3164       bool          // 使用 RFC3164 格式而非 RFC5424。
	BufferSize    int           // 内部消息缓冲大小。0 → 1000。
	TimeZone      string        // 时间戳时区。默认 "UTC"。
	JSONInMessage bool          // 在 message 字段中包含 JSON 结构。
	ErrorTimeout  time.Duration // 缓冲满时 Error+ 日志的最大等待。0 → 1s。
}

// Validate 检查必填字段，并返回应用默认值后的规范化副本。
func (c Config) Validate() (Config, error) {
	if c.Network == "" {
		c.Network = "tcp"
	}
	if c.Address == "" {
		return Config{}, &mebsuta.ConfigError{Field: "Address", Msg: "syslog address is required"}
	}
	if c.Level == nil {
		c.Level = slog.LevelInfo
	}
	if c.Tag == "" {
		c.Tag = "mebsuta"
	}
	if len(c.Tag) > 48 {
		return Config{}, &mebsuta.ConfigError{Field: "Tag", Msg: fmt.Sprintf("syslog tag too long: %d chars (max 48)", len(c.Tag))}
	}
	for _, r := range c.Tag {
		if r < 33 || r > 126 {
			return Config{}, &mebsuta.ConfigError{Field: "Tag", Msg: fmt.Sprintf("syslog tag contains non-printable character: %q", r)}
		}
	}
	if c.Facility < 0 || c.Facility > 23 {
		return Config{}, &mebsuta.ConfigError{Field: "Facility", Msg: fmt.Sprintf("invalid syslog facility: %d, must be 0-23", c.Facility)}
	}
	// 0 既是 Go 零值也是合法的 syslog facility（LOG_KERN）。
	// 应用默认应用 LOG_USER（1），故将 0 重映射为 1。
	// 真正需要 LOG_KERN 的用户必须使用其他机制。
	if c.Facility == 0 {
		c.Facility = DefaultFacility
	}
	if c.Reconnect == nil {
		c.Reconnect = mebsuta.Ptr(true)
	}
	if c.RetryDelay <= 0 {
		c.RetryDelay = 500 * time.Millisecond
	}
	if c.RetryDelay > MaxRetryDelay {
		return Config{}, &mebsuta.ConfigError{Field: "RetryDelay", Msg: fmt.Sprintf("retry delay %v exceeds maximum %v", c.RetryDelay, MaxRetryDelay)}
	}
	if c.BufferSize > 10000 {
		return Config{}, &mebsuta.ConfigError{Field: "BufferSize", Msg: fmt.Sprintf("buffer size %d exceeds maximum 10000", c.BufferSize)}
	}
	if c.BufferSize <= 0 {
		c.BufferSize = 1000
	}
	if c.ErrorTimeout <= 0 {
		c.ErrorTimeout = 1 * time.Second
	}
	if c.TimeZone != "" {
		if _, err := time.LoadLocation(c.TimeZone); err != nil {
			return Config{}, &mebsuta.ConfigError{Field: "TimeZone", Msg: fmt.Sprintf("invalid timezone: %s", c.TimeZone)}
		}
	}
	return c, nil
}
