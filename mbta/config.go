package mbta

import (
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/iuboy/mebsuta"
)

// 重试/延迟上限：运行期与 Close 排空期间，每个失败批次都要付出
// MaxRetries ×（发送 deadline + RetryDelay）的代价，无界取值会让
// 关闭也无界。与 syslog.MaxRetryDelay 保持一致。
const (
	// MaxRetryDelay 限制 Config.RetryDelay 上限。
	MaxRetryDelay = 30 * time.Second
	// MaxRetriesLimit 限制 Config.MaxRetries 上限。
	MaxRetriesLimit = 10
	// maxBatchSize 限制 Config.BatchSize 上限。processQueue 会按该容量
	// 预分配批次切片，误配的巨大 BatchSize 相当于一笔巨大的
	// 预先分配（OOM 隐患）。与 database.maxBatchSize 保持一致。
	maxBatchSize = 10000
)

// maskedToken 是 String/GoString/Sanitize 渲染 Config.Token 时使用的内容。
const maskedToken = "***"

// ResultHandler 接收服务端针对某个批次的终态 RESULT 通知
// （accepted / durable / rejected / released），与
// mbtago.ResultHandler 对应。seq 与 SendBatch 分配的值一致；level 是
// corepb.ResultLevel 的枚举名（如 "RESULT_LEVEL_REJECTED"），或在
// 终态未按时到达时客户端合成的 "timeout"。
type ResultHandler func(seq uint64, level string, code uint32, correlation string)

// Config 保存 MBTA 日志外发 handler 的配置。
type Config struct {
	// 连接设置
	Server   string // 必填：forwarder 地址（如 "localhost:7400"）
	AgentID  string // 必填：agent 标识
	Hostname string // 可选：默认取系统主机名
	Token    string // 可选：认证 token

	// TLS 设置
	CAFile             string
	CertFile           string
	KeyFile            string
	ServerName         string
	InsecureSkipVerify bool

	// 行为
	Level        slog.Leveler  // 日志级别过滤。默认 slog.LevelInfo。
	BufferSize   int           // 内部批次缓冲。0 -> 1000。
	FlushPeriod  time.Duration // 缓冲记录的刷新周期。0 -> 5s。
	BatchSize    int           // 每批最大记录数。0 -> 100。
	MaxRetries   int           // 最大发送重试次数。0 -> 3。
	RetryDelay   time.Duration // 基础重试延迟。0 -> 1s。
	ErrorTimeout time.Duration // 缓冲满时 Error+ 日志的最大等待。0 -> 1s。
	CloseTimeout time.Duration // 客户端优雅关闭/排空的最大等待。0 -> 5s。
	// Reconnect 在发送重试间、会话不再 READY 时重新拨号 forwarder。
	// nil -> true。没有它（或重连持续失败）时，
	// 批次在 MaxRetries 次尝试后被丢弃。
	Reconnect *bool // 断连后自动重连。nil -> true。

	// OnResult 可选地为每个批次接收服务端的终态 RESULT 通知
	//（见 ResultHandler）。
	//
	// 必须在此提供，而不是通过 mbta-go 客户端的
	// SetResultHandler：该回调是单槽位，handler 在构造时
	// 已在其中注册了自己的内部包装（把 rejected/released 批次计入
	// Dropped 并做限频上报）。底层客户端刻意不导出，观察
	// RESULT 的唯一途径就是该字段；将来任何对客户端的直接
	// 访问都会静默覆盖内部记账。
	//
	// SendBatch 在批次写上线后立即返回——nil 错误
	// 并不代表服务端接受了该批次。OnResult（加上
	// handler 内置的丢弃计数）是唯一的拒绝可见性。
	OnResult ResultHandler

	// 元数据
	Tag    string // SignalBatch 的 Tag。默认 "mebsuta"。
	Source string // Source 标识。默认为主机名。
}

// Validate 检查必填字段，并返回应用默认值后的规范化副本。
func (c Config) Validate() (Config, error) {
	if c.Server == "" {
		return Config{}, &mebsuta.ConfigError{Field: "Server", Msg: "mbta server address is required"}
	}
	if c.AgentID == "" {
		return Config{}, &mebsuta.ConfigError{Field: "AgentID", Msg: "mbta agent ID is required"}
	}
	if c.Level == nil {
		c.Level = slog.LevelInfo
	}
	if c.BufferSize > maxBufferSize {
		return Config{}, &mebsuta.ConfigError{Field: "BufferSize", Msg: fmt.Sprintf("buffer size %d exceeds maximum %d", c.BufferSize, maxBufferSize)}
	}
	if c.BufferSize <= 0 {
		c.BufferSize = defaultBufferSize
	}
	if c.FlushPeriod <= 0 {
		c.FlushPeriod = defaultFlushPeriod
	}
	if c.BatchSize <= 0 {
		c.BatchSize = defaultBatchSize
	} else if c.BatchSize > maxBatchSize {
		// 钳制而非报错：processQueue 会按 BatchSize 容量预分配
		// 批次切片，误配的巨大值是一颗预先分配炸弹，
		// 拨号时报错并无帮助。
		c.BatchSize = maxBatchSize
	}
	if c.MaxRetries <= 0 {
		c.MaxRetries = defaultMaxRetries
	}
	if c.RetryDelay <= 0 {
		c.RetryDelay = defaultRetryDelay
	}
	// 上限让 Close 的排空有界：最终刷新最多花费
	// MaxRetries ×（SendBatch deadline + RetryDelay），无界取值
	// 会让“有界关闭”成为空话。
	if c.RetryDelay > MaxRetryDelay {
		c.RetryDelay = MaxRetryDelay
	}
	if c.MaxRetries > MaxRetriesLimit {
		c.MaxRetries = MaxRetriesLimit
	}
	if c.ErrorTimeout <= 0 {
		c.ErrorTimeout = time.Second
	}
	if c.CloseTimeout <= 0 {
		c.CloseTimeout = defaultCloseTimeout
	}
	if c.Tag == "" {
		c.Tag = "mebsuta"
	}
	if c.Source == "" {
		hostname, err := resolveHostname(c.Hostname)
		if err != nil {
			c.Source = "localhost"
		} else {
			c.Source = hostname
		}
	}
	if c.Reconnect == nil {
		c.Reconnect = mebsuta.Ptr(true)
	}
	return c, nil
}

// rawConfig 是去掉方法的 Config，fmt 渲染结构体时
// 不会重入 String/GoString（那会无限递归）。
type rawConfig Config

// Sanitize 返回将 Token 替换为 "***" 的 Config 副本。将
// Config 交给不受信任的 sink（日志、错误报告、转储）前请先调用。
func (c Config) Sanitize() Config {
	c.Token = maskedToken
	return c
}

// String 渲染配置时屏蔽 Token，意外打印 Config
// 值（"%v" / "%+v"）时也不会泄漏凭据。
func (c Config) String() string {
	return fmt.Sprintf("%+v", rawConfig(c.Sanitize()))
}

// GoString 是 String 的 "%#v" 对应版本，同样屏蔽 Token。
func (c Config) GoString() string {
	return fmt.Sprintf("%#v", rawConfig(c.Sanitize()))
}

func resolveHostname(static string) (string, error) {
	if static != "" {
		return static, nil
	}
	hostname, err := os.Hostname()
	if err != nil {
		return "", fmt.Errorf("get hostname: %w", err)
	}
	return hostname, nil
}
