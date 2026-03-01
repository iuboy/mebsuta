package config

import (
	"fmt"
	"time"
)

// LoggerConfigBuilder 提供流式API构建LoggerConfig
// 使用Builder模式可以更清晰地创建复杂的日志配置
type LoggerConfigBuilder struct {
	cfg *LoggerConfig
	err error
}

// NewLoggerConfigBuilder 创建一个新的LoggerConfigBuilder
func NewLoggerConfigBuilder(serviceName string) *LoggerConfigBuilder {
	return &LoggerConfigBuilder{
		cfg: &LoggerConfig{
			ServiceName: serviceName,
			Outputs:     []OutputConfig{},
			Encoder: EncoderConfig{
				MessageKey:       "msg",
				LevelKey:         "level",
				TimeKey:          "time",
				TimeFormat:       DefaultTimeFormat,
				TimeZone:         "UTC",
				EnableCaller:     false,
				EnableStacktrace: false,
			},
			Sampling: SamplingConfig{
				Enabled: false,
			},
		},
	}
}

// WithEncoder 设置编码器配置
func (b *LoggerConfigBuilder) WithEncoder(encoder EncoderConfig) *LoggerConfigBuilder {
	b.cfg.Encoder = encoder
	return b
}

// WithEncoderKeys 自定义编码器键名
func (b *LoggerConfigBuilder) WithEncoderKeys(messageKey, levelKey, timeKey string) *LoggerConfigBuilder {
	b.cfg.Encoder.MessageKey = messageKey
	b.cfg.Encoder.LevelKey = levelKey
	b.cfg.Encoder.TimeKey = timeKey
	return b
}

// WithTimeFormat 设置时间格式和时区
func (b *LoggerConfigBuilder) WithTimeFormat(format string, timezone string) *LoggerConfigBuilder {
	b.cfg.Encoder.TimeFormat = format
	b.cfg.Encoder.TimeZone = timezone
	return b
}

// WithCaller 启用调用者信息
func (b *LoggerConfigBuilder) WithCaller(enable bool) *LoggerConfigBuilder {
	b.cfg.Encoder.EnableCaller = enable
	return b
}

// WithStacktrace 启用堆栈跟踪
func (b *LoggerConfigBuilder) WithStacktrace(enable bool) *LoggerConfigBuilder {
	b.cfg.Encoder.EnableStacktrace = enable
	return b
}

// AddStdoutOutput 添加标准输出
func (b *LoggerConfigBuilder) AddStdoutOutput(level LogLevel, encoding EncodingType) *LoggerConfigBuilder {
	b.cfg.Outputs = append(b.cfg.Outputs, OutputConfig{
		Type:     Stdout,
		Level:    level,
		Encoding: encoding,
		Enabled:  true,
	})
	return b
}

// AddFileOutput 添加文件输出
func (b *LoggerConfigBuilder) AddFileOutput(level LogLevel, encoding EncodingType, path string, opts ...FileOption) *LoggerConfigBuilder {
	fileCfg := &FileConfig{
		Path:       path,
		MaxSizeMB:  DefaultFileMaxSizeMB,
		MaxBackups: DefaultMaxBackups,
		MaxAgeDays: DefaultMaxAgeDays,
		Compress:   false,
		LocalTime:  false,
	}
	for _, opt := range opts {
		opt(fileCfg)
	}

	b.cfg.Outputs = append(b.cfg.Outputs, OutputConfig{
		Type:     File,
		Level:    level,
		Encoding: encoding,
		Enabled:  true,
		File:     fileCfg,
	})
	return b
}

// AddDatabaseOutput 添加数据库输出
func (b *LoggerConfigBuilder) AddDatabaseOutput(level LogLevel, driver string, dsn string, tableName string, opts ...DatabaseOption) *LoggerConfigBuilder {
	dbCfg := &DatabaseConfig{
		DriverName:      driver,
		DataSourceName:  dsn,
		TableName:       tableName,
		BatchSize:       DefaultBatchSize,
		BatchInterval:   DefaultBatchInterval,
		MaxOpenConns:    DefaultMaxOpenConns,
		MaxIdleConns:    DefaultMaxIdleConns,
		MaxConnLifetime: 0,
		RetryDelay:      DefaultRetryDelay,
	}
	for _, opt := range opts {
		opt(dbCfg)
	}

	b.cfg.Outputs = append(b.cfg.Outputs, OutputConfig{
		Type:     DB,
		Level:    level,
		Encoding: JSON,
		Enabled:  true,
		Database: dbCfg,
	})
	return b
}

// AddSyslogOutput 添加Syslog输出
func (b *LoggerConfigBuilder) AddSyslogOutput(level LogLevel, network, address, tag string, opts ...SyslogOption) *LoggerConfigBuilder {
	syslogCfg := &SyslogConfig{
		Network:       network,
		Address:       address,
		Tag:           tag,
		Facility:      1, // user-level
		RetryDelay:    DefaultRetryDelay,
		JSONInMessage: false,
	}
	for _, opt := range opts {
		opt(syslogCfg)
	}

	b.cfg.Outputs = append(b.cfg.Outputs, OutputConfig{
		Type:     Syslog,
		Level:    level,
		Encoding: JSON,
		Enabled:  true,
		Syslog:   syslogCfg,
	})
	return b
}

// WithSampling 启用日志采样
func (b *LoggerConfigBuilder) WithSampling(initial, thereafter int, window time.Duration) *LoggerConfigBuilder {
	b.cfg.Sampling = SamplingConfig{
		Enabled:    true,
		Initial:    initial,
		Thereafter: thereafter,
		Window:     window,
	}
	return b
}

// WithDebugMode 启用调试模式
func (b *LoggerConfigBuilder) WithDebugMode(debug bool) *LoggerConfigBuilder {
	b.cfg.DebugMode = debug
	return b
}

// Build 构建最终的LoggerConfig
func (b *LoggerConfigBuilder) Build() (*LoggerConfig, error) {
	if b.err != nil {
		return nil, b.err
	}

	// 验证配置
	if err := b.cfg.Validate(); err != nil {
		return nil, fmt.Errorf("配置验证失败: %w", err)
	}

	return b.cfg, nil
}

// MustBuild 构建配置，失败时panic（仅用于测试）
func (b *LoggerConfigBuilder) MustBuild() *LoggerConfig {
	cfg, err := b.Build()
	if err != nil {
		panic(err)
	}
	return cfg
}

// FileOption 文件配置选项函数类型
type FileOption func(*FileConfig)

// WithFileRotation 设置文件轮转参数
func WithFileRotation(maxSizeMB, maxBackups, maxAgeDays int) FileOption {
	return func(fc *FileConfig) {
		fc.MaxSizeMB = maxSizeMB
		fc.MaxBackups = maxBackups
		fc.MaxAgeDays = maxAgeDays
	}
}

// WithFileCompression 启用文件压缩
func WithFileCompression(enable bool) FileOption {
	return func(fc *FileConfig) {
		fc.Compress = enable
	}
}

// WithFileLocalTime 使用本地时间
func WithFileLocalTime(enable bool) FileOption {
	return func(fc *FileConfig) {
		fc.LocalTime = enable
	}
}

// DatabaseOption 数据库配置选项函数类型
type DatabaseOption func(*DatabaseConfig)

// WithBatchSize 设置批量大小
func WithBatchSize(size int) DatabaseOption {
	return func(dc *DatabaseConfig) {
		dc.BatchSize = size
	}
}

// WithBatchInterval 设置批量间隔
func WithBatchInterval(interval time.Duration) DatabaseOption {
	return func(dc *DatabaseConfig) {
		dc.BatchInterval = interval
	}
}

// WithConnectionPool 设置连接池参数
func WithConnectionPool(maxOpen, maxIdle int, maxLifetime time.Duration) DatabaseOption {
	return func(dc *DatabaseConfig) {
		dc.MaxOpenConns = maxOpen
		dc.MaxIdleConns = maxIdle
		dc.MaxConnLifetime = maxLifetime
	}
}

// WithTimeSeries 配置InfluxDB时序数据库
func WithTimeSeries(url, org, bucket, token string) DatabaseOption {
	return func(dc *DatabaseConfig) {
		dc.TimeSeries = &TimeSeriesConfig{
			URL:    url,
			Org:    org,
			Bucket: bucket,
			Token:  token,
		}
	}
}

// SyslogOption Syslog配置选项函数类型
type SyslogOption func(*SyslogConfig)

// WithSyslogFacility 设置Syslog设施值
func WithSyslogFacility(facility int) SyslogOption {
	return func(sc *SyslogConfig) {
		sc.Facility = facility
	}
}

// WithSyslogFormat 使用JSON格式
func WithSyslogFormat(useJSON bool) SyslogOption {
	return func(sc *SyslogConfig) {
		sc.JSONInMessage = useJSON
	}
}

// WithSyslogRetryDelay 设置重试延迟
func WithSyslogRetryDelay(delay time.Duration) SyslogOption {
	return func(sc *SyslogConfig) {
		sc.RetryDelay = delay
	}
}

// WithSyslogTimeZone 设置时区
func WithSyslogTimeZone(tz string) SyslogOption {
	return func(sc *SyslogConfig) {
		sc.TimeZone = tz
	}
}
