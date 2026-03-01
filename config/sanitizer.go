package config

import (
	"fmt"
	"net/url"
	"reflect"
	"regexp"
	"strings"
)

// Sanitize 返回配置的脱敏字符串表示（用于日志输出）
// 此方法会隐藏敏感信息如密码、token 等
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

	if dc.TimeSeries != nil {
		parts = append(parts, "TimeSeries.URL="+dc.TimeSeries.URL)
		parts = append(parts, "TimeSeries.Token="+maskToken(dc.TimeSeries.Token))
		parts = append(parts, "TimeSeries.Org="+dc.TimeSeries.Org)
		parts = append(parts, "TimeSeries.Bucket="+dc.TimeSeries.Bucket)
	}

	parts = append(parts, "BatchSize="+fmt.Sprint(dc.BatchSize))
	parts = append(parts, "MaxOpenConns="+fmt.Sprint(dc.MaxOpenConns))

	return "{ " + strings.Join(parts, ", ") + " }"
}

// Sanitize 返回文件配置的脱敏字符串表示
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

// Sanitize 返回输出配置的脱敏字符串表示
func (oc *OutputConfig) Sanitize() string {
	if oc == nil {
		return ""
	}

	parts := []string{}
	parts = append(parts, "Type="+string(oc.Type))
	parts = append(parts, "Level="+string(oc.Level))
	parts = append(parts, "Enabled="+fmt.Sprintf("%v", oc.Enabled))

	if oc.Database != nil {
		parts = append(parts, "Database="+oc.Database.Sanitize())
	}

	if oc.File != nil {
		parts = append(parts, "File="+oc.File.Sanitize())
	}

	if oc.Syslog != nil {
		parts = append(parts, "Syslog="+oc.Syslog.Sanitize())
	}

	return "{ " + strings.Join(parts, ", ") + " }"
}

// Sanitize 返回 Syslog 配置的脱敏字符串表示
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

// maskPasswordInDSN 隐藏数据源连接字符串中的密码
// 支持 MySQL、PostgreSQL、SQL Server 等常见格式
func maskPasswordInDSN(dsn string) string {
	// 格式 1: user:password@tcp(host:port)/db
	// 格式 2: postgres://user:password@host:port/db
	// 格式 3: sqlserver://user:password@host:port?database=db

	// MySQL 格式: user:password@tcp(host:port)/db
	re1 := regexp.MustCompile(`^([^:]+):([^@]+)@`)
	if re1.MatchString(dsn) {
		return re1.ReplaceAllString(dsn, "$1:****@")
	}

	// PostgreSQL 格式: postgres://user:password@host:port/db
	re2 := regexp.MustCompile(`://([^:]+):([^@]+)@`)
	if re2.MatchString(dsn) {
		return re2.ReplaceAllString(dsn, "://$1:****@")
	}

	// URL 参数格式中的密码: password=xxx
	re3 := regexp.MustCompile(`password=[^&]+`)
	if re3.MatchString(dsn) {
		return re3.ReplaceAllString(dsn, "password=****")
	}

	// 检查是否是 URL 格式
	if u, err := url.Parse(dsn); err == nil {
		if u.User != nil {
			// 保留用户名，隐藏密码
			user := u.User.Username()
			return strings.Replace(dsn, u.User.String()+"@", user+":****@", 1)
		}
	}

	// 如果无法识别格式，返回完全脱敏版本
	if len(dsn) > 20 {
		return dsn[:20] + "...(hidden)"
	}
	return "(hidden)"
}

// maskToken 隐藏 token 的大部分字符
func maskToken(token string) string {
	if token == "" {
		return ""
	}

	if len(token) <= 8 {
		return "****"
	}

	// 保留前 4 位和后 4 位
	return token[:4] + "..." + token[len(token)-4:]
}

// SanitizeForLog 对任意配置进行脱敏（通用方法）
func SanitizeForLog(cfg interface{}) string {
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
	case *OutputConfig:
		return c.Sanitize()
	case LoggerConfig:
		parts := []string{}
		parts = append(parts, "ServiceName="+c.ServiceName)
		parts = append(parts, "DebugMode="+fmt.Sprint(c.DebugMode))
		for i, output := range c.Outputs {
			parts = append(parts, "Output["+fmt.Sprint(i)+"]="+output.Sanitize())
		}
		return "{ " + strings.Join(parts, ", ") + " }"
	default:
		// 对于未知类型，返回类型名称
		return "Config(" + getTypeName(cfg) + ")"
	}
}

func getTypeName(v interface{}) string {
	if t := reflect.TypeOf(v); t.Kind() == reflect.Ptr {
		return t.Elem().Name()
	} else {
		return t.Name()
	}
}
