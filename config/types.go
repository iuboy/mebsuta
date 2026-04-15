package config

import "time"

const (
	DefaultRetryDelay     = 500 * time.Millisecond
	DefaultBatchSize      = 100
	DefaultBatchInterval  = 5 * time.Second
	DefaultMaxOpenConns   = 10
	DefaultMaxIdleConns   = 5
	DefaultFileMaxSizeMB  = 100
	DefaultMaxBackups     = 5
	DefaultMaxAgeDays     = 30
	DefaultTimeFormat     = time.RFC3339Nano
	DefaultSyslogNetwork  = "tcp"
	DefaultSyslogTag      = "mebsuta"
	TimeSeriesDriver      = "influxdb"
)

// LogLevel 定义支持的日志级别
type LogLevel string

const (
	DebugLevel  LogLevel = "debug"
	InfoLevel   LogLevel = "info"
	WarnLevel   LogLevel = "warn"
	ErrorLevel  LogLevel = "error"
	DPanicLevel LogLevel = "dpanic"
	FatalLevel  LogLevel = "fatal"
	PanicLevel  LogLevel = "panic"
)

// FileConfig 定义文件日志配置
type FileConfig struct {
	Path            string        `json:"path" validate:"required"` // 文件路径
	MaxSizeMB       int           `json:"maxSizeMB"`                // 最大文件大小(MB)
	MaxBackups      int           `json:"maxBackups"`               // 最大备份数
	MaxAgeDays      int           `json:"maxAgeDays"`               // 最大保存天数
	Compress        bool          `json:"compress"`                 // 是否压缩
	RotateOnStartup bool          `json:"rotateOnStartup"`          // 启动时轮转
	LocalTime       bool          `json:"localTime"`                // 是否使用本地时间
	Format          string        `json:"format"`                   // 输出编码格式："json" 或 "console"
	RotateInterval  time.Duration `json:"rotateInterval"`           // 固定间隔轮转（如每小时/每天）
}

// DatabaseConfig 定义数据库日志配置
type DatabaseConfig struct {
	DriverName      string            `json:"driver" validate:"required"`      // 驱动名称
	DataSourceName  string            `json:"dsn"`                             // 连接字符串
	TableName       string            `json:"tableName"`                       // 表名
	BatchSize       int               `json:"batchSize"`                       // 批量大小
	BatchInterval   time.Duration     `json:"batchInterval"`                   // 批量间隔
	MaxConnLifetime time.Duration     `json:"maxConnLifeTime"`                 // 连接生命周期
	MaxOpenConns    int               `json:"maxOpenConns"`                    // 最大打开连接数
	MaxIdleConns    int               `json:"maxIdleConns"`                    // 最大空闲连接数
	RetryDelay      time.Duration     `json:"retryDelay"`                      // 重试间隔
	TimeSeries      *TimeSeriesConfig `json:"timeSeries" validate:"omitempty"` // 时序数据库配置
}

// TimeSeriesConfig 定义时序数据库配置
type TimeSeriesConfig struct {
	Org    string `json:"org" validate:"required"`
	Bucket string `json:"bucket" validate:"required"`
	Token  string `json:"token" validate:"required"`
	URL    string `json:"url" validate:"required,url"`
}

// SyslogConfig 定义Syslog配置
type SyslogConfig struct {
	Network       string        `json:"network" validate:"oneof=tcp udp"` // 网络协议
	Address       string        `json:"address" validate:"required"`      // 服务器地址
	Tag           string        `json:"tag" validate:"required"`          // 应用标识
	Facility      int           `json:"facility" validate:"min=0,max=23"` // 系统设施
	Reconnect     bool          `json:"reconnect"`                        // 是否自动重连
	RetryDelay    time.Duration `json:"retryDelay"`                       // 重试延迟
	TLSSkipVerify bool          `json:"tlsSkipVerify"`                    // 跳过TLS验证
	StaticHost    string        `json:"staticHost"`                       // 静态主机名
	Secure        bool          `json:"secure"`                           // 使用TLS
	RFC5424       bool          `json:"rfc5424"`                          // 使用RFC5424格式
	Structured    string        `json:"structuredData"`                   // 结构化数据
	BufferSize    int           `json:"bufferSize"`                       // 缓冲区大小
	TimeZone      string        `json:"timeZone"`                         // 时区
	JSONInMessage bool          `json:"jsonInMessage"`                    // JSON数据嵌入消息中
}

// EncoderConfig 定义日志编码器配置
type EncoderConfig struct {
	TimeFormat    string `json:"timeFormat"`                     // 时间格式
	TimeZone      string `json:"timeZone"`                       // 时区
	MessageKey    string `json:"messageKey" validate:"required"` // 消息键
	LevelKey      string `json:"levelKey" validate:"required"`   // 级别键
	TimeKey       string `json:"timeKey" validate:"required"`    // 时间键
	CallerKey     string `json:"callerKey" validate:"required"`  // 调用者键
	StacktraceKey string `json:"stacktraceKey" validate:"required"` // 堆栈跟踪键
	EnableCaller  bool   `json:"enableCaller"`                   // 启用调用者信息
}

// SamplingConfig 定义日志采样配置
type SamplingConfig struct {
	Enabled    bool          `json:"enabled"`
	Initial    int           `json:"initial" validate:"min=1"`
	Thereafter int           `json:"thereafter" validate:"min=1"`
	Window     time.Duration `json:"window" validate:"min=1000000"`
}
