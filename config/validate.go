package config

import (
	"fmt"
	"path/filepath"
	"regexp"
	"time"

	meberrors "github.com/iuboy/mebsuta/errors"
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
	// 跳过对已禁用输出的验证
	if !oc.Enabled {
		return nil
	}
	if !oc.Type.Valid() {
		return meberrors.ErrUnsupportedType(fmt.Sprintf("无效的输出类型: %s", oc.Type))
	}
	if !oc.Level.Valid() {
		return meberrors.ErrValidateFailed(fmt.Sprintf("无效的日志级别: %s", oc.Level))
	}

	switch oc.Type {
	case File:
		if oc.File == nil {
			return meberrors.ErrMissingConfig("文件输出需要文件配置")
		}
		return oc.File.Validate()
	case DB:
		if oc.Database == nil {
			return meberrors.ErrMissingConfig("数据库输出需要数据库配置")
		}
		return oc.Database.Validate()
	case Syslog:
		if oc.Syslog == nil {
			return meberrors.ErrMissingConfig("Syslog输出需要Syslog配置")
		}
		return oc.Syslog.Validate()
	}
	return nil
}

// Validate 验证文件配置
func (fc *FileConfig) Validate() error {
	if fc.Path == "" {
		return meberrors.ErrInvalidConfig("文件路径不能为空")
	}
	if !filepath.IsAbs(fc.Path) {
		return meberrors.ErrInvalidPath(fmt.Sprintf("文件路径必须是绝对路径: %s", fc.Path))
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
			return meberrors.ErrMissingConfig("SQL数据库需要数据源名称")
		}
		if dc.TableName == "" {
			return meberrors.ErrMissingConfig("SQL数据库需要表名")
		}
		// 验证表名格式，防止SQL注入：只允许字母、数字和下划线
		if !regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`).MatchString(dc.TableName) {
			return meberrors.ErrInvalidConfig(fmt.Sprintf("表名格式无效: %s，只允许字母、数字和下划线，且必须以字母或下划线开头", dc.TableName))
		}
	case TimeSeriesDriver:
		if dc.TimeSeries == nil {
			return meberrors.ErrMissingConfig(fmt.Sprintf("驱动 %s 需要时序数据库配置", TimeSeriesDriver))
		}
		if err := dc.TimeSeries.Validate(); err != nil {
			return meberrors.Wrap(err, meberrors.ErrCodeValidateFailed, "时序数据库配置验证失败")
		}
	default:
		return meberrors.ErrUnsupportedType(fmt.Sprintf("不支持的数据库驱动: %s", dc.DriverName))
	}
	return nil
}

// Validate 验证时序配置
func (ts *TimeSeriesConfig) Validate() error {
	if ts.URL == "" {
		return meberrors.ErrMissingConfig("时序数据库需要URL")
	}
	if ts.Bucket == "" {
		return meberrors.ErrMissingConfig("时序数据库需要bucket")
	}
	if ts.Token == "" {
		return meberrors.ErrMissingConfig("时序数据库需要token")
	}
	return nil
}

// Validate 验证Syslog配置
func (sc *SyslogConfig) Validate() error {
	if sc.Network == "" {
		sc.Network = "tcp"
	}
	if sc.Address == "" {
		return meberrors.ErrMissingConfig("Syslog地址不能为空")
	}
	if sc.Tag == "" {
		return meberrors.ErrMissingConfig("Syslog标签不能为空")
	}
	if sc.RetryDelay == 0 {
		sc.RetryDelay = DefaultRetryDelay
	}
	if sc.Facility < 0 || sc.Facility > 23 {
		return meberrors.ErrValidateFailed(fmt.Sprintf("无效的Syslog设施值: %d，必须在0-23之间", sc.Facility))
	}
	if sc.TimeZone != "" {
		if _, err := time.LoadLocation(sc.TimeZone); err != nil {
			return meberrors.ErrInvalidConfig(fmt.Sprintf("无效的时区: %s", sc.TimeZone))
		}
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
	} else {
		// 验证时区，无效时重置为UTC
		if _, err := time.LoadLocation(ec.TimeZone); err != nil {
			ec.TimeZone = "UTC"
		}
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
		return meberrors.ErrValidateFailed("采样配置要求initial、thereafter和window值必须为正数")
	}
	return nil
}

// Validate 验证日志配置
func (lc *LoggerConfig) Validate() error {
	if lc.ServiceName == "" {
		return meberrors.ErrInvalidConfig("服务名称不能为空")
	}
	if len(lc.Outputs) == 0 {
		return meberrors.ErrInvalidConfig("至少需要配置一个输出")
	}
	for i, output := range lc.Outputs {
		if err := output.Validate(); err != nil {
			return meberrors.Wrap(err, meberrors.ErrCodeValidateFailed, fmt.Sprintf("输出配置 %d 验证失败", i))
		}
	}
	if err := lc.Sampling.Validate(); err != nil {
		return meberrors.Wrap(err, meberrors.ErrCodeValidateFailed, "采样配置验证失败")
	}
	return nil
}
