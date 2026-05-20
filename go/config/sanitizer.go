package config

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// Sanitize returns a sanitized string representation of DatabaseConfig with sensitive fields masked.
func (dc *DatabaseConfig) Sanitize() string {
	if dc == nil {
		return ""
	}

	parts := []string{}
	parts = append(parts, "DriverName="+dc.DriverName)

	if dc.DataSourceName != "" {
		parts = append(parts, "DataSourceName="+maskPasswordInDSN(dc.DataSourceName))
	}

	if dc.TableName != "" {
		parts = append(parts, "TableName="+dc.TableName)
	}

	parts = append(parts, "BatchSize="+fmt.Sprint(dc.BatchSize))
	parts = append(parts, "MaxOpenConns="+fmt.Sprint(dc.MaxOpenConns))

	return "{ " + strings.Join(parts, ", ") + " }"
}

// Sanitize returns a sanitized string representation of FileConfig.
func (fc *FileConfig) Sanitize() string {
	if fc == nil {
		return ""
	}

	return "{ " +
		"Path=" + fc.Path + ", " +
		"MaxSizeMB=" + fmt.Sprint(fc.MaxSizeMB) + ", " +
		"MaxBackups=" + fmt.Sprint(fc.MaxBackups) +
		" }"
}

// Sanitize returns a sanitized string representation of SyslogConfig.
func (sc *SyslogConfig) Sanitize() string {
	if sc == nil {
		return ""
	}

	return "{ " +
		"Network=" + sc.Network + ", " +
		"Address=" + sc.Address + ", " +
		"Tag=" + sc.Tag +
		" }"
}

// 预编译正则表达式，避免每次调用 maskPasswordInDSN 时重复编译。
var (
	reMySQLDSN   = regexp.MustCompile(`^([^:]+):([^@]+)@`)
	reURIDSN     = regexp.MustCompile(`://([^:]+):([^@]+)@`)
	rePasswordKV = regexp.MustCompile(`password=[^&]+`)
)

// maskPasswordInDSN 隐藏数据源连接字符串中的密码
// 支持 MySQL、PostgreSQL、SQL Server 等常见格式
func maskPasswordInDSN(dsn string) string {
	// 格式 1: user:password@tcp(host:port)/db
	// 格式 2: postgres://user:password@host:port/db
	// 格式 3: sqlserver://user:password@host:port?database=db

	// MySQL 格式: user:password@tcp(host:port)/db
	if reMySQLDSN.MatchString(dsn) {
		return reMySQLDSN.ReplaceAllString(dsn, "$1:****@")
	}

	// PostgreSQL 格式: postgres://user:password@host:port/db
	if reURIDSN.MatchString(dsn) {
		return reURIDSN.ReplaceAllString(dsn, "://$1:****@")
	}

	// URL 参数格式中的密码: password=xxx
	if rePasswordKV.MatchString(dsn) {
		return rePasswordKV.ReplaceAllString(dsn, "password=****")
	}

	// 检查是否是 URL 格式
	if u, err := url.Parse(dsn); err == nil {
		if u.User != nil {
			// 保留用户名，隐藏密码
			user := u.User.Username()
			return strings.Replace(dsn, u.User.String()+"@", user+":****@", 1)
		}
	}

	// 如果无法识别格式，返回完全脱敏版本（不泄露任何原始内容）
	return "(redacted)"
}

// SanitizeForLog returns a sanitized string for any supported config type.
func SanitizeForLog(cfg any) string {
	if cfg == nil {
		return "(nil)"
	}

	switch c := cfg.(type) {
	case *DatabaseConfig:
		return c.Sanitize()
	case *FileConfig:
		return c.Sanitize()
	case *SyslogConfig:
		return c.Sanitize()
	default:
		// 对于未知类型，返回类型名称
		return "Config(" + getTypeName(cfg) + ")"
	}
}

func getTypeName(v any) string {
	return fmt.Sprintf("%T", v)
}
