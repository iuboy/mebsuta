// Package telemetry 提供一步到位的 OpenTelemetry 引导，覆盖三个信号
// （traces、metrics、logs），走 OTLP/HTTP。
//
// 它存在的意义是让每个服务以完全一致的方式接入 OpenTelemetry：资源
// 属性、头部采样、批处理、W3C 传播与优雅关停。各项目用本包替换自己
// 手搓的 internal/telemetry 包。
//
// 用法：
//
//	tel, err := telemetry.Start(ctx, telemetry.Config{
//		ServiceName: "castor",
//		Endpoint:    "http://mebsuta-forwarder:4318",
//	})
//	if err != nil {
//		return err
//	}
//	defer tel.Shutdown(context.Background())
//
// Endpoint 语义：
//
//   - ""（零值）：no-op 模式。Start 永不报错，Shutdown 是 no-op，
//     provider 访问器返回 no-op 实现。本地开发与测试零开销，
//     全局状态保持原样。
//   - 完整 URL（"http://host:4318" 或 "https://host"）：由 scheme 决定
//     是否 TLS。URL 的 path 被忽略——每个 exporter 使用其规范默认的
//     /v1/traces|metrics|logs 路径。
//   - 裸 "host:port"：按明文 HTTP 处理，即典型的局域网
//     mebsuta-forwarder 部署形态。
//
// 只使用 OTLP/HTTP exporter——故意不让 gRPC 进入编译期依赖图（对齐
// mebsuta-forwarder 的 no-grpc 立场：forwarder 的 OTLP 来源只在 :4318
// 上监听 HTTP）。
package telemetry

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/iuboy/mebsuta"
)

// Signals 是选择启动哪些 OTel 信号的位掩码。
type Signals uint8

const (
	// Traces 选择 trace 信号（TracerProvider + 批量 span 处理器）。
	Traces Signals = 1 << iota
	// Metrics 选择 metric 信号（MeterProvider + 周期读取器）。
	Metrics
	// Logs 选择 log 信号（LoggerProvider + 批量记录处理器）。
	Logs

	// None 不启动任何信号。与零值等价；见 Config.Signals。
	None Signals = 0
	// All 是全部信号的并集。
	All = Traces | Metrics | Logs
)

// String 将信号集合渲染为 "traces|metrics|logs"，用于诊断输出。
func (s Signals) String() string {
	if s == None {
		return "none"
	}
	var parts []string
	if s&Traces != 0 {
		parts = append(parts, "traces")
	}
	if s&Metrics != 0 {
		parts = append(parts, "metrics")
	}
	if s&Logs != 0 {
		parts = append(parts, "logs")
	}
	return strings.Join(parts, "|")
}

// 默认配置值。
const (
	// DefaultShutdownTimeout 在 Config.ShutdownTimeout 未设置时约束
	// Shutdown 的冲刷窗口。
	DefaultShutdownTimeout = 5 * time.Second
)

// Config 承载 telemetry 引导配置。
type Config struct {
	// ServiceName 设置资源 service.name 属性。设置了 Endpoint 时必填：
	// 无名资源在下游无法查询，因此 Start 选择 fail-fast，而不是输出
	// 无人能归因的记录。no-op 模式下忽略。
	ServiceName string
	// ServiceVersion 设置资源 service.version 属性。可选。
	ServiceVersion string
	// Environment 设置资源 deployment.environment 属性
	// （如 "production"、"staging"）。可选。
	Environment string
	// Endpoint 是 OTLP/HTTP 目标。"" → no-op 模式（除非设置了 Database）；
	// 可接受的形态见包文档。
	Endpoint string
	// Database 为 traces 与 metrics 选择数据库后端（部署模式 B）。
	// 与 Endpoint 同时设置即双写。nil → 仅 OTLP。见 DatabaseConfig。
	Database *DatabaseConfig
	// TLSCAFile 是用于校验 OTLP collector 的 PEM CA 文件（私有 CA 的
	// https 部署——wasat 的单二进制自签形态）。"" → 系统信任池。
	// 对齐 mbta 的凭据面。
	TLSCAFile string
	// TLSCertFile / TLSKeyFile 提供客户端身份（mTLS——在接收方校验
	// 客户端证书时生效；两者必须同时设置，不能只设其一）。
	TLSCertFile string
	TLSKeyFile  string
	// TLSServerName 在端点主机名与证书 SAN 不一致时，覆盖证书校验
	// 所用的服务器名称。
	TLSServerName string
	// Signals 选择启动哪些 provider。0 → All（零值 Config 打开全部
	// 信号；要完全 no-op 请将 Endpoint 置为等价于 None 的 ""）。
	Signals Signals
	// SamplingRate 是 trace 头部采样比例。0 → 1.0（全采样——零值
	// Config 保留每条 trace，符合本地开发预期）；-1 → NeverSample
	//（完全关闭采样，供接入方表达三态采样器的 never 档）；其余取值
	// 须落在 [-1, 1]。
	SamplingRate float64
	// Headers 附加到每个 OTLP 导出请求（例如给接收方 forwarder 的
	// 认证令牌）。可选。
	Headers map[string]string
	// Attributes 是额外资源属性，在服务属性之后合并。可选。
	Attributes map[string]string
	// OTelErrorHandler 接收 SDK 内部的导出失败（batcher 重试耗尽、
	// exporter 错误），否则这些会落到 otel 的全局默认处理（stderr）。
	// nil → mebsuta.DefaultErrorHandler()。仅在启用 SetGlobal 时接线——
	// otel.SetErrorHandler 是全局的，SetGlobal=false 的部署自行管理
	// 其 otel 全局状态。
	OTelErrorHandler mebsuta.ErrorHandler
	// SetGlobal 把已启动的 provider 与 W3C propagator 注册到 otel
	// 全局，使 otel.Tracer/Meter/Logger 及读取全局的插桩（otelgin、
	// otelhttp、……）能拿到它们。nil → true。无论此设置如何，
	// no-op 模式从不触碰全局。
	SetGlobal *bool
	// ShutdownTimeout 约束 Shutdown 的冲刷窗口。0 → 5s。
	ShutdownTimeout time.Duration
	// MetricExportInterval 是周期性 metric 读取器的间隔。
	// 0 → SDK 默认（60s）。
	MetricExportInterval time.Duration
	// BatchLogQueueSize 限制 log batcher 在丢记录前的内存队列长度
	// （wasat 缺口 ④；0 → SDK 默认 2048）。
	BatchLogQueueSize int
	// BatchLogInterval 是 log batcher 的冲刷节奏（wasat 缺口 ④；
	// 0 → SDK 默认）。
	BatchLogInterval time.Duration
}

// Validate 填充默认值并拒绝会静默劣化的取值，返回规范化副本（不修改
// 调用方）——对齐全仓 Config 校验约定：fail-fast、错误信息含合法域。
// no-op 模式（Endpoint 与 Database 均空）跳过信号校验。
// 校验错误统一为 *mebsuta.ConfigError，消费方可 errors.As 做字段级判断。
func (c Config) Validate() (Config, error) {
	if c.Endpoint == "" && c.Database == nil {
		return c, nil
	}
	if c.ServiceName == "" {
		return Config{}, &mebsuta.ConfigError{Field: "ServiceName", Msg: "配置了后端时必填（无名资源下游不可查询）"}
	}
	if c.Database != nil {
		if err := c.Database.validate(); err != nil {
			return Config{}, err
		}
	}
	if _, _, err := canonicalEndpoint(c.Endpoint); err != nil {
		return Config{}, &mebsuta.ConfigError{Field: "Endpoint", Msg: err.Error()}
	}
	if err := c.validateTLS(); err != nil {
		return Config{}, err
	}
	// 仅 -1 表示 NeverSample；(0, 1] 为比例；(-1, 0) 开区间无语义，拒绝。
	if (c.SamplingRate < -1) || (c.SamplingRate > 1) || (c.SamplingRate < 0 && c.SamplingRate > -1) {
		return Config{}, &mebsuta.ConfigError{Field: "SamplingRate", Msg: fmt.Sprintf("%v 超出合法域 {-1} ∪ [0, 1]（-1 = NeverSample）", c.SamplingRate)}
	}
	if c.SamplingRate == 0 {
		c.SamplingRate = 1
	}
	if c.Signals == None {
		c.Signals = All
	}
	if c.BatchLogQueueSize < 0 {
		return Config{}, &mebsuta.ConfigError{Field: "BatchLogQueueSize", Msg: fmt.Sprintf("%d 超出合法域 (>= 0，0 = SDK 缺省)", c.BatchLogQueueSize)}
	}
	if c.BatchLogInterval < 0 {
		return Config{}, &mebsuta.ConfigError{Field: "BatchLogInterval", Msg: fmt.Sprintf("%v 超出合法域 (>= 0，0 = SDK 缺省)", c.BatchLogInterval)}
	}
	return c, nil
}

// tlsActive 报告是否设置了任意 TLS 凭据字段。
func (c Config) tlsActive() bool {
	return c.TLSCAFile != "" || c.TLSCertFile != "" || c.TLSKeyFile != "" || c.TLSServerName != ""
}

// validateTLS 校验 TLS 字段交叉规则：显式 http:// 端点与 TLS 凭据自相
// 矛盾；客户端身份必须证书/私钥成对。
func (c Config) validateTLS() error {
	if !c.tlsActive() {
		return nil
	}
	if lower := strings.ToLower(c.Endpoint); strings.HasPrefix(lower, "http://") {
		return &mebsuta.ConfigError{Field: "Endpoint", Msg: fmt.Sprintf("%q 显式 http:// 但配置了 TLS 凭据（去掉 TLS 字段或改用 https://）", c.Endpoint)}
	}
	if (c.TLSCertFile == "") != (c.TLSKeyFile == "") {
		return &mebsuta.ConfigError{Field: "TLSCertFile", Msg: "TLSCertFile 与 TLSKeyFile 必须成对设置"}
	}
	return nil
}

// buildTLS 把凭据文件加载为供 OTLP exporter 使用的 *tls.Config。
// 未设置任何 TLS 字段时返回 nil。MinVersion 钉在 TLS 1.2，
// 与 syslog handler 的下限一致。
func (c Config) buildTLS() (*tls.Config, error) {
	if !c.tlsActive() {
		return nil, nil
	}
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: c.TLSServerName,
	}
	if c.TLSCAFile != "" {
		pem, err := os.ReadFile(c.TLSCAFile)
		if err != nil {
			return nil, fmt.Errorf("telemetry: read TLSCAFile: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("telemetry: TLSCAFile %s contains no valid PEM certificate", c.TLSCAFile)
		}
		cfg.RootCAs = pool
	}
	if c.TLSCertFile != "" {
		pair, err := tls.LoadX509KeyPair(c.TLSCertFile, c.TLSKeyFile)
		if err != nil {
			return nil, fmt.Errorf("telemetry: load client keypair: %w", err)
		}
		cfg.Certificates = []tls.Certificate{pair}
	}
	return cfg, nil
}

// canonicalEndpoint 把 Config.Endpoint 规范化为 OTLP/HTTP exporter 所期望
// 的 (host, insecure) 二元组：
//
//   - 裸 "host:port" 按明文 HTTP 处理（文档所述的局域网默认），
//     原样返回且 insecure=true；
//   - 显式 scheme 必须是 http 或 https，且 host 必须存在；
//   - path、query 与 fragment 被丢弃——exporter 总是 POST 到其规范默认的
//     /v1/<signal> 路径。
func canonicalEndpoint(raw string) (host string, insecure bool, err error) {
	if !strings.Contains(raw, "://") {
		return raw, true, nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", false, fmt.Errorf("telemetry: parse Endpoint %q: %w", raw, err)
	}
	if u.Host == "" {
		return "", false, fmt.Errorf("telemetry: Endpoint %q: missing host", raw)
	}
	switch u.Scheme {
	case "http":
		return u.Host, true, nil
	case "https":
		return u.Host, false, nil
	default:
		return "", false, fmt.Errorf("telemetry: Endpoint %q: unsupported scheme %q (want http or https)", raw, u.Scheme)
	}
}
