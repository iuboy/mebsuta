package config

import (
	"fmt"
	"path/filepath"
	"regexp"
	"time"
)

// validTableNameRe 预编译表名验证正则，避免每次 Validate 调用重新编译。
var validTableNameRe = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

// Validate 验证文件配置
func (fc *FileConfig) Validate() error {
	if fc.Path == "" {
		return fmt.Errorf("file path is required")
	}
	if !filepath.IsAbs(fc.Path) {
		return fmt.Errorf("file path must be absolute: %s", fc.Path)
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
	if dc.BatchSize <= 0 {
		dc.BatchSize = DefaultBatchSize
	}
	if dc.BatchInterval <= 0 {
		dc.BatchInterval = DefaultBatchInterval
	}
	if dc.MaxOpenConns <= 0 {
		dc.MaxOpenConns = DefaultMaxOpenConns
	}
	if dc.MaxIdleConns <= 0 {
		dc.MaxIdleConns = DefaultMaxIdleConns
	}
	if dc.RetryDelay <= 0 {
		dc.RetryDelay = DefaultRetryDelay
	}

	switch dc.DriverName {
	case "mysql", "postgres":
		if dc.DataSourceName == "" {
			return fmt.Errorf("SQL database requires data source name")
		}
		if dc.TableName == "" {
			dc.TableName = "logs"
		}
		if !validTableNameRe.MatchString(dc.TableName) {
			return fmt.Errorf("invalid table name: %s, only letters, digits and underscores allowed, must start with letter or underscore", dc.TableName)
		}
	default:
		return fmt.Errorf("unsupported database driver: %s", dc.DriverName)
	}
	return nil
}

// Validate 验证Syslog配置
func (sc *SyslogConfig) Validate() error {
	if sc.Network == "" {
		sc.Network = DefaultSyslogNetwork
	}
	if sc.Address == "" {
		return fmt.Errorf("syslog address is required")
	}
	if sc.Tag == "" {
		sc.Tag = DefaultSyslogTag
	}
	if sc.RetryDelay <= 0 {
		sc.RetryDelay = DefaultRetryDelay
	}
	if sc.Facility < 0 || sc.Facility > 23 {
		return fmt.Errorf("invalid syslog facility: %d, must be 0-23", sc.Facility)
	}
	if sc.TimeZone != "" {
		if _, err := time.LoadLocation(sc.TimeZone); err != nil {
			return fmt.Errorf("invalid timezone: %s", sc.TimeZone)
		}
	}
	return nil
}

// Validate 验证采样配置
func (sc *SamplingConfig) Validate() error {
	if !sc.Enabled {
		return nil
	}
	if sc.Initial <= 0 || sc.Thereafter <= 0 || sc.Window <= 0 {
		return fmt.Errorf("sampling config requires positive initial, thereafter and window values")
	}
	return nil
}
