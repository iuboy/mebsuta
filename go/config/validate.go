package config

import (
	"fmt"
	"path/filepath"
	"regexp"
	"time"
)

// validTableNameRe 预编译表名验证正则，避免每次 Validate 调用重新编译。
var validTableNameRe = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

// Validate validates the FileConfig and applies defaults for zero fields.
func (fc *FileConfig) Validate() error {
	if fc.path == "" {
		return fmt.Errorf("file path is required")
	}
	if !filepath.IsAbs(fc.path) {
		return fmt.Errorf("file path must be absolute: %s", fc.path)
	}
	if fc.maxSizeMB == 0 {
		fc.maxSizeMB = DefaultFileMaxSizeMB
	}
	if fc.maxBackups == 0 {
		fc.maxBackups = DefaultMaxBackups
	}
	if fc.maxAgeDays == 0 {
		fc.maxAgeDays = DefaultMaxAgeDays
	}
	return nil
}

// Validate validates the DatabaseConfig and applies defaults for zero fields.
func (dc *DatabaseConfig) Validate() error {
	if dc.batchSize <= 0 {
		dc.batchSize = DefaultBatchSize
	}
	if dc.batchInterval <= 0 {
		dc.batchInterval = DefaultBatchInterval
	}
	if dc.maxOpenConns <= 0 {
		dc.maxOpenConns = DefaultMaxOpenConns
	}
	if dc.maxIdleConns <= 0 {
		dc.maxIdleConns = DefaultMaxIdleConns
	}
	if dc.maxIdleConns > dc.maxOpenConns {
		dc.maxIdleConns = dc.maxOpenConns
	}
	if dc.retryDelay <= 0 {
		dc.retryDelay = DefaultRetryDelay
	}

	switch dc.driverName {
	case "mysql", "postgres":
		if dc.dataSourceName == "" {
			return fmt.Errorf("SQL database requires data source name")
		}
		if dc.tableName == "" {
			dc.tableName = "logs"
		}
		if !validTableNameRe.MatchString(dc.tableName) {
			return fmt.Errorf("invalid table name: %s, only letters, digits and underscores allowed, must start with letter or underscore", dc.tableName)
		}
		if len(dc.tableName) > 64 {
			return fmt.Errorf("table name too long: %d chars (max 64)", len(dc.tableName))
		}
	default:
		return fmt.Errorf("unsupported database driver: %s", dc.driverName)
	}
	return nil
}

// Validate validates the SyslogConfig and applies defaults for zero fields.
func (sc *SyslogConfig) Validate() error {
	if sc.network == "" {
		sc.network = DefaultSyslogNetwork
	}
	if sc.address == "" {
		return fmt.Errorf("syslog address is required")
	}
	if sc.tag == "" {
		sc.tag = DefaultSyslogTag
	}
	if len(sc.tag) > 48 {
		return fmt.Errorf("syslog tag too long: %d chars (max 48)", len(sc.tag))
	}
	for _, r := range sc.tag {
		if r < 33 || r > 126 {
			return fmt.Errorf("syslog tag contains non-printable character: %q", r)
		}
	}
	if sc.retryDelay <= 0 {
		sc.retryDelay = DefaultRetryDelay
	}
	if sc.bufferSize <= 0 {
		sc.bufferSize = 1000
	}
	if sc.facility < 0 || sc.facility > 23 {
		return fmt.Errorf("invalid syslog facility: %d, must be 0-23", sc.facility)
	}
	if sc.timeZone != "" {
		if _, err := time.LoadLocation(sc.timeZone); err != nil {
			return fmt.Errorf("invalid timezone: %s", sc.timeZone)
		}
	}
	return nil
}

// Validate validates the SamplingConfig when sampling is enabled.
func (sc *SamplingConfig) Validate() error {
	if !sc.enabled {
		return nil
	}
	if sc.initial <= 0 || sc.thereafter <= 0 || sc.window <= 0 {
		return fmt.Errorf("sampling config requires positive initial, thereafter and window values")
	}
	return nil
}
