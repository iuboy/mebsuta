package config

import "time"

const (
	DefaultRetryDelay    = 500 * time.Millisecond
	DefaultBatchSize     = 100
	DefaultBatchInterval = 5 * time.Second
	DefaultMaxOpenConns  = 10
	DefaultMaxIdleConns  = 5
	DefaultFileMaxSizeMB = 100
	DefaultMaxBackups    = 5
	DefaultMaxAgeDays    = 30
	DefaultSyslogNetwork = "tcp"
	DefaultSyslogTag     = "mebsuta"
)

// FileConfig 定义文件日志配置
type FileConfig struct {
	Path           string        `json:"path"`
	MaxSizeMB      int           `json:"maxSizeMB"`
	MaxBackups     int           `json:"maxBackups"`
	MaxAgeDays     int           `json:"maxAgeDays"`
	Compress       bool          `json:"compress"`
	Format         string        `json:"format"`
	RotateInterval time.Duration `json:"rotateInterval"`
}

// DatabaseConfig 定义数据库日志配置
type DatabaseConfig struct {
	DriverName      string        `json:"driver"`
	DataSourceName  string        `json:"dsn"`
	TableName       string        `json:"tableName"`
	BatchSize       int           `json:"batchSize"`
	BatchInterval   time.Duration `json:"batchInterval"`
	MaxConnLifetime time.Duration `json:"maxConnLifeTime"`
	MaxOpenConns    int           `json:"maxOpenConns"`
	MaxIdleConns    int           `json:"maxIdleConns"`
	RetryDelay      time.Duration `json:"retryDelay"`
}

// SyslogConfig 定义Syslog配置
type SyslogConfig struct {
	Network       string        `json:"network"`
	Address       string        `json:"address"`
	Tag           string        `json:"tag"`
	Facility      int           `json:"facility"`
	Reconnect     bool          `json:"reconnect"`
	RetryDelay    time.Duration `json:"retryDelay"`
	TLSSkipVerify bool          `json:"tlsSkipVerify"`
	StaticHost    string        `json:"staticHost"`
	Secure        bool          `json:"secure"`
	RFC5424       bool          `json:"rfc5424"`
	BufferSize    int           `json:"bufferSize"`
	TimeZone      string        `json:"timeZone"`
	JSONInMessage bool          `json:"jsonInMessage"`
}

// SamplingConfig 定义日志采样配置
type SamplingConfig struct {
	Enabled    bool          `json:"enabled"`
	Initial    int           `json:"initial"`
	Thereafter int           `json:"thereafter"`
	Window     time.Duration `json:"window"`
}
