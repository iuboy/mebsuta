package config

import (
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"go.uber.org/zap/zapcore"
)

func (l LogLevel) Valid() bool {
	for _, level := range []LogLevel{DebugLevel, InfoLevel, WarnLevel, ErrorLevel, DPanicLevel, FatalLevel, PanicLevel} {
		if l == level {
			return true
		}
	}
	return false
}

func (l LogLevel) ZapLevel() zapcore.Level {
	switch l {
	case DebugLevel:
		return zapcore.DebugLevel
	case InfoLevel:
		return zapcore.InfoLevel
	case WarnLevel:
		return zapcore.WarnLevel
	case ErrorLevel:
		return zapcore.ErrorLevel
	case FatalLevel:
		return zapcore.FatalLevel
	case PanicLevel:
		return zapcore.PanicLevel
	default:
		return zapcore.InfoLevel
	}
}

func (t OutputType) Valid() bool {
	switch t {
	case Stdout, File, DB, Syslog:
		return true
	default:
		return false
	}
}

// Validate 验证输出配置
func (oc *OutputConfig) Validate() error {
	if !oc.Type.Valid() {
		return fmt.Errorf("invalid output type: %s", oc.Type)
	}
	if !oc.Level.Valid() {
		return fmt.Errorf("invalid log level: %s", oc.Level)
	}

	switch oc.Type {
	case File:
		if oc.File == nil {
			return errors.New("file output requires file configuration")
		}
		return oc.File.Validate()
	case DB:
		if oc.Database == nil {
			return errors.New("database output requires database configuration")
		}
		return oc.Database.Validate()
	case Syslog:
		if oc.Syslog == nil {
			return errors.New("syslog output requires syslog configuration")
		}
		return oc.Syslog.Validate()
	}
	return nil
}

// Validate 验证文件配置
func (fc *FileConfig) Validate() error {
	if fc.Path == "" {
		return errors.New("file path is required")
	}
	if !filepath.IsAbs(fc.Path) {
		return fmt.Errorf("file path must be an absolute path: %s", fc.Path)
	}
	if fc.MaxSizeMB == 0 {
		fc.MaxSizeMB = DefaultFileMaxSizeMB
	}
	if fc.MaxBackups == 0 {
		fc.MaxBackups = DefaultMaxBackups
	}
	if fc.MaxAgeDays == 0 {
		fc.MaxAgeDays = DefaultMaxAgeDays
	}
	if !fc.Compress && !fc.LocalTime {
		fc.LocalTime = false
	}

	return nil
}

// Validate 验证数据库配置
func (dc *DatabaseConfig) Validate() error {
	if dc.BatchSize == 0 {
		dc.BatchSize = DefaultBatchSize
	}
	if dc.BatchInterval == 0 {
		dc.BatchInterval = DefaultBatchInterval
	}
	if dc.MaxOpenConns == 0 {
		dc.MaxOpenConns = DefaultMaxOpenConns
	}
	if dc.MaxIdleConns == 0 {
		dc.MaxIdleConns = DefaultMaxIdleConns
	}
	if dc.RetryDelay == 0 {
		dc.RetryDelay = DefaultRetryDelay
	}

	switch dc.DriverName {
	case "mysql", "postgres":
		if dc.DataSourceName == "" {
			return errors.New("data source name is required for SQL databases")
		}
		if dc.TableName == "" {
			return errors.New("table name is required for SQL databases")
		}
	case TimeSeriesDriver:
		if dc.TimeSeries == nil {
			return fmt.Errorf("time series configuration required for driver: %s", TimeSeriesDriver)
		}
		if err := dc.TimeSeries.Validate(); err != nil {
			return fmt.Errorf("time series config validation failed: %w", err)
		}
	default:
		return fmt.Errorf("unsupported driver: %s", dc.DriverName)
	}
	return nil
}

// Validate 验证时序配置
func (ts *TimeSeriesConfig) Validate() error {
	if ts.URL == "" {
		return errors.New("URL is required for time series database")
	}
	if ts.Bucket == "" {
		return errors.New("bucket is required for time series database")
	}
	if ts.Token == "" {
		return errors.New("token is required for time series database")
	}
	return nil
}

// Validate 验证Syslog配置
func (sc *SyslogConfig) Validate() error {
	if sc.Network == "" {
		sc.Network = "tcp"
	}
	if sc.Address == "" {
		return errors.New("syslog address is required")
	}
	if sc.Tag == "" {
		return errors.New("syslog tag is required")
	}
	if sc.RetryDelay == 0 {
		sc.RetryDelay = DefaultRetryDelay
	}
	if sc.Facility < 0 || sc.Facility > 23 {
		return fmt.Errorf("invalid syslog facility: %d, must be 0-23", sc.Facility)
	}
	if sc.TimeZone == "" {
		if _, err := time.LoadLocation(sc.TimeZone); err != nil {
			return fmt.Errorf("invalid time zone: %s", sc.TimeZone)
		}
	}
	if !sc.JSONInMessage {
		sc.JSONInMessage = false
	}
	return nil
}

// ApplyDefaults 设置编码器默认值
func (ec *EncoderConfig) ApplyDefaults() *EncoderConfig {
	if ec.TimeFormat == "" {
		ec.TimeFormat = DefaultTimeFormat
	}
	if ec.TimeZone == "" {
		ec.TimeZone = "UTC"
	}
	if ec.MessageKey == "" {
		ec.MessageKey = "msg"
	}
	if ec.LevelKey == "" {
		ec.LevelKey = "level"
	}
	if ec.TimeKey == "" {
		ec.TimeKey = "time"
	}
	if ec.CallerKey == "" {
		ec.CallerKey = "caller"
	}
	if ec.StacktraceKey == "" {
		ec.StacktraceKey = "stacktrace"
	}
	return ec
}

// Validate 验证采样配置
func (sc *SamplingConfig) Validate() error {
	if !sc.Enabled {
		return nil
	}
	if sc.Initial <= 0 || sc.Thereafter <= 0 || sc.Window <= 0 {
		return errors.New("sampling requires positive initial, thereafter and window values")
	}
	return nil
}

// Validate 验证日志配置
func (lc *LoggerConfig) Validate() error {
	for i, output := range lc.Outputs {
		if err := output.Validate(); err != nil {
			return fmt.Errorf("output %d validation failed: %w", i, err)
		}
	}
	if err := lc.Sampling.Validate(); err != nil {
		return fmt.Errorf("sampling config validation failed: %w", err)
	}
	return nil
}
