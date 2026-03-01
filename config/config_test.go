package config

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zapcore"
)

// TestLogLevel_Valid 测试日志级别验证
func TestLogLevel_Valid(t *testing.T) {
	tests := []struct {
		name  string
		level LogLevel
		want  bool
	}{
		{"DebugLevel", DebugLevel, true},
		{"InfoLevel", InfoLevel, true},
		{"WarnLevel", WarnLevel, true},
		{"ErrorLevel", ErrorLevel, true},
		{"FatalLevel", FatalLevel, true},
		{"PanicLevel", PanicLevel, true},
		{"DPanicLevel", DPanicLevel, true},
		{"InvalidLevel", LogLevel("invalid"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.level.Valid())
		})
	}
}

// TestLogLevel_ZapLevel 测试日志级别转换
func TestLogLevel_ZapLevel(t *testing.T) {
	tests := []struct {
		name  string
		level LogLevel
		want  zapcore.Level
	}{
		{"DebugLevel", DebugLevel, zapcore.DebugLevel},
		{"InfoLevel", InfoLevel, zapcore.InfoLevel},
		{"WarnLevel", WarnLevel, zapcore.WarnLevel},
		{"ErrorLevel", ErrorLevel, zapcore.ErrorLevel},
		{"FatalLevel", FatalLevel, zapcore.FatalLevel},
		{"PanicLevel", PanicLevel, zapcore.PanicLevel},
		{"InvalidLevel", LogLevel("invalid"), zapcore.InfoLevel}, // 默认返回 Info
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.level.ZapLevel())
		})
	}
}

// TestOutputType_Valid 测试输出类型验证
func TestOutputType_Valid(t *testing.T) {
	tests := []struct {
		name  string
		otype OutputType
		want  bool
	}{
		{"Stdout", Stdout, true},
		{"File", File, true},
		{"DB", DB, true},
		{"Syslog", Syslog, true},
		{"InvalidType", OutputType("invalid"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.otype.Valid())
		})
	}
}

// TestEncoderConfig_ApplyDefaults 测试编码器配置默认值
func TestEncoderConfig_ApplyDefaults(t *testing.T) {
	ec := &EncoderConfig{}
	applied := ec.ApplyDefaults()

	assert.Equal(t, DefaultTimeFormat, applied.TimeFormat)
	assert.Equal(t, "UTC", applied.TimeZone)
	assert.Equal(t, "msg", applied.MessageKey)
	assert.Equal(t, "level", applied.LevelKey)
	assert.Equal(t, "time", applied.TimeKey)
	assert.Equal(t, "caller", applied.CallerKey)
	assert.Equal(t, "stacktrace", applied.StacktraceKey)
}

// TestOutputConfig_Validate 测试输出配置验证
func TestOutputConfig_Validate(t *testing.T) {
	t.Run("有效输出配置", func(t *testing.T) {
		oc := OutputConfig{
			Type:     Stdout,
			Level:    InfoLevel,
			Encoding: JSON,
			Enabled:  true,
		}
		err := oc.Validate()
		assert.NoError(t, err)
	})

	t.Run("无效输出类型", func(t *testing.T) {
		oc := OutputConfig{
			Type:     OutputType("invalid"),
			Level:    InfoLevel,
			Encoding: JSON,
			Enabled:  true,
		}
		err := oc.Validate()
		assert.Error(t, err)
	})

	t.Run("无效日志级别", func(t *testing.T) {
		oc := OutputConfig{
			Type:     Stdout,
			Level:    LogLevel("invalid"),
			Encoding: JSON,
			Enabled:  true,
		}
		err := oc.Validate()
		assert.Error(t, err)
	})
}

// TestFileConfig_Validate 测试文件配置验证
func TestFileConfig_Validate(t *testing.T) {
	t.Run("有效文件配置", func(t *testing.T) {
		fc := &FileConfig{
			Path:       "/var/log/test.log",
			MaxSizeMB:  100,
			MaxBackups: 5,
			MaxAgeDays: 30,
		}
		err := fc.Validate()
		assert.NoError(t, err)
	})

	t.Run("空路径", func(t *testing.T) {
		fc := &FileConfig{
			Path: "",
		}
		err := fc.Validate()
		assert.Error(t, err)
	})

	t.Run("相对路径", func(t *testing.T) {
		fc := &FileConfig{
			Path: "test.log",
		}
		err := fc.Validate()
		assert.Error(t, err)
	})

	t.Run("应用默认值", func(t *testing.T) {
		fc := &FileConfig{
			Path: "/var/log/test.log",
		}
		err := fc.Validate()
		require.NoError(t, err)
		assert.Equal(t, DefaultFileMaxSizeMB, fc.MaxSizeMB)
		assert.Equal(t, DefaultMaxBackups, fc.MaxBackups)
		assert.Equal(t, DefaultMaxAgeDays, fc.MaxAgeDays)
	})
}

// TestDatabaseConfig_Validate 测试数据库配置验证
func TestDatabaseConfig_Validate(t *testing.T) {
	t.Run("有效MySQL配置", func(t *testing.T) {
		dc := &DatabaseConfig{
			DriverName:     "mysql",
			DataSourceName: "root:password@tcp(localhost:3306)/logs",
			TableName:      "logs",
			BatchSize:      100,
			BatchInterval:  5 * time.Second,
		}
		err := dc.Validate()
		assert.NoError(t, err)
	})

	t.Run("有效Postgres配置", func(t *testing.T) {
		dc := &DatabaseConfig{
			DriverName:     "postgres",
			DataSourceName: "postgres://user:password@localhost:5432/logs",
			TableName:      "logs",
		}
		err := dc.Validate()
		assert.NoError(t, err)
	})

	t.Run("缺少数据源", func(t *testing.T) {
		dc := &DatabaseConfig{
			DriverName: "mysql",
			TableName:  "logs",
		}
		err := dc.Validate()
		assert.Error(t, err)
	})

	t.Run("缺少表名", func(t *testing.T) {
		dc := &DatabaseConfig{
			DriverName:     "mysql",
			DataSourceName: "root:password@tcp(localhost:3306)/logs",
		}
		err := dc.Validate()
		assert.Error(t, err)
	})

	t.Run("应用默认值", func(t *testing.T) {
		dc := &DatabaseConfig{
			DriverName:     "mysql",
			DataSourceName: "root:password@tcp(localhost:3306)/logs",
			TableName:      "logs",
		}
		err := dc.Validate()
		require.NoError(t, err)
		assert.Equal(t, DefaultBatchSize, dc.BatchSize)
		assert.Equal(t, DefaultBatchInterval, dc.BatchInterval)
		assert.Equal(t, DefaultMaxOpenConns, dc.MaxOpenConns)
		assert.Equal(t, DefaultMaxIdleConns, dc.MaxIdleConns)
	})

	t.Run("无效表名-包含特殊字符", func(t *testing.T) {
		dc := &DatabaseConfig{
			DriverName:     "mysql",
			DataSourceName: "root:password@tcp(localhost:3306)/logs",
			TableName:      "log-table; DROP TABLE logs--",
		}
		err := dc.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "表名格式无效")
	})

	t.Run("无效表名-以数字开头", func(t *testing.T) {
		dc := &DatabaseConfig{
			DriverName:     "mysql",
			DataSourceName: "root:password@tcp(localhost:3306)/logs",
			TableName:      "123logs",
		}
		err := dc.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "表名格式无效")
	})

	t.Run("有效表名-下划线开头", func(t *testing.T) {
		dc := &DatabaseConfig{
			DriverName:     "mysql",
			DataSourceName: "root:password@tcp(localhost:3306)/logs",
			TableName:      "_logs",
		}
		err := dc.Validate()
		assert.NoError(t, err)
	})

	t.Run("有效表名-包含数字", func(t *testing.T) {
		dc := &DatabaseConfig{
			DriverName:     "mysql",
			DataSourceName: "root:password@tcp(localhost:3306)/logs",
			TableName:      "logs2024",
		}
		err := dc.Validate()
		assert.NoError(t, err)
	})
}

// TestTimeSeriesConfig_Validate 测试时序数据库配置验证
func TestTimeSeriesConfig_Validate(t *testing.T) {
	t.Run("有效InfluxDB配置", func(t *testing.T) {
		ts := &TimeSeriesConfig{
			URL:    "http://localhost:8086",
			Org:    "test-org",
			Bucket: "test-bucket",
			Token:  "test-token",
		}
		err := ts.Validate()
		assert.NoError(t, err)
	})

	t.Run("缺少URL", func(t *testing.T) {
		ts := &TimeSeriesConfig{
			Org:    "test-org",
			Bucket: "test-bucket",
			Token:  "test-token",
		}
		err := ts.Validate()
		assert.Error(t, err)
	})

	t.Run("缺少Bucket", func(t *testing.T) {
		ts := &TimeSeriesConfig{
			URL:   "http://localhost:8086",
			Org:   "test-org",
			Token: "test-token",
		}
		err := ts.Validate()
		assert.Error(t, err)
	})
}

// TestSyslogConfig_Validate 测试Syslog配置验证
func TestSyslogConfig_Validate(t *testing.T) {
	t.Run("有效Syslog配置", func(t *testing.T) {
		sc := &SyslogConfig{
			Network:  "tcp",
			Address:  "localhost:514",
			Tag:      "test-app",
			Facility: 16,
		}
		err := sc.Validate()
		assert.NoError(t, err)
	})

	t.Run("空地址", func(t *testing.T) {
		sc := &SyslogConfig{
			Network: "tcp",
			Address: "",
			Tag:     "test-app",
		}
		err := sc.Validate()
		assert.Error(t, err)
	})

	t.Run("空标签", func(t *testing.T) {
		sc := &SyslogConfig{
			Network: "tcp",
			Address: "localhost:514",
			Tag:     "",
		}
		err := sc.Validate()
		assert.Error(t, err)
	})

	t.Run("无效设施值", func(t *testing.T) {
		sc := &SyslogConfig{
			Network:  "tcp",
			Address:  "localhost:514",
			Tag:      "test-app",
			Facility: 24, // 超过23
		}
		err := sc.Validate()
		assert.Error(t, err)
	})

	t.Run("无效时区", func(t *testing.T) {
		sc := &SyslogConfig{
			Network:  "tcp",
			Address:  "localhost:514",
			Tag:      "test-app",
			Facility: 16,
			TimeZone: "Invalid/Timezone",
		}
		err := sc.Validate()
		assert.Error(t, err)
	})

	t.Run("应用默认值", func(t *testing.T) {
		sc := &SyslogConfig{
			Network: "",
			Address: "localhost:514",
			Tag:     "test-app",
		}
		err := sc.Validate()
		require.NoError(t, err)
		assert.Equal(t, "tcp", sc.Network)
		assert.Equal(t, DefaultRetryDelay, sc.RetryDelay)
	})
}

// TestSamplingConfig_Validate 测试采样配置验证
func TestSamplingConfig_Validate(t *testing.T) {
	t.Run("禁用采样", func(t *testing.T) {
		sc := SamplingConfig{
			Enabled: false,
		}
		err := sc.Validate()
		assert.NoError(t, err)
	})

	t.Run("有效采样配置", func(t *testing.T) {
		sc := SamplingConfig{
			Enabled:    true,
			Initial:    10,
			Thereafter: 5,
			Window:     time.Second,
		}
		err := sc.Validate()
		assert.NoError(t, err)
	})

	t.Run("负数Initial", func(t *testing.T) {
		sc := SamplingConfig{
			Enabled:    true,
			Initial:    -1,
			Thereafter: 5,
			Window:     time.Second,
		}
		err := sc.Validate()
		assert.Error(t, err)
	})

	t.Run("负数Thereafter", func(t *testing.T) {
		sc := SamplingConfig{
			Enabled:    true,
			Initial:    10,
			Thereafter: -1,
			Window:     time.Second,
		}
		err := sc.Validate()
		assert.Error(t, err)
	})

	t.Run("零窗口", func(t *testing.T) {
		sc := SamplingConfig{
			Enabled:    true,
			Initial:    10,
			Thereafter: 5,
			Window:     0,
		}
		err := sc.Validate()
		assert.Error(t, err)
	})
}

// TestLoggerConfig_Validate 测试日志配置验证
func TestLoggerConfig_Validate(t *testing.T) {
	t.Run("完整有效配置", func(t *testing.T) {
		lc := LoggerConfig{
			ServiceName: "test-service",
			Outputs: []OutputConfig{
				{
					Type:     Stdout,
					Level:    InfoLevel,
					Encoding: JSON,
					Enabled:  true,
				},
			},
			Encoder: EncoderConfig{
				MessageKey: "msg",
				LevelKey:   "level",
				TimeKey:    "time",
			},
		}
		err := lc.Validate()
		assert.NoError(t, err)
	})

	t.Run("无效输出配置", func(t *testing.T) {
		lc := LoggerConfig{
			ServiceName: "test-service",
			Outputs: []OutputConfig{
				{
					Type:     OutputType("invalid"),
					Level:    InfoLevel,
					Encoding: JSON,
					Enabled:  true,
				},
			},
		}
		err := lc.Validate()
		assert.Error(t, err)
	})

	t.Run("无效采样配置", func(t *testing.T) {
		lc := LoggerConfig{
			ServiceName: "test-service",
			Outputs: []OutputConfig{
				{
					Type:     Stdout,
					Level:    InfoLevel,
					Encoding: JSON,
					Enabled:  true,
				},
			},
			Sampling: SamplingConfig{
				Enabled:    true,
				Initial:    -1,
				Thereafter: 5,
				Window:     time.Second,
			},
		}
		err := lc.Validate()
		assert.Error(t, err)
	})
}

// TestEncoderConfig_EdgeCases 测试编码器配置边界情况
func TestEncoderConfig_EdgeCases(t *testing.T) {
	t.Run("空键名", func(t *testing.T) {
		ec := &EncoderConfig{
			MessageKey: "",
			LevelKey:   "",
			TimeKey:    "",
		}
		applied := ec.ApplyDefaults()
		// 默认值应该被应用
		assert.Equal(t, "msg", applied.MessageKey)
		assert.Equal(t, "level", applied.LevelKey)
		assert.Equal(t, "time", applied.TimeKey)
	})

	t.Run("自定义时间格式", func(t *testing.T) {
		ec := &EncoderConfig{
			TimeFormat: "2006-01-02 15:04:05",
		}
		applied := ec.ApplyDefaults()
		assert.Equal(t, "2006-01-02 15:04:05", applied.TimeFormat)
	})

	t.Run("无效时区", func(t *testing.T) {
		ec := &EncoderConfig{
			TimeZone: "Invalid/Timezone",
		}
		applied := ec.ApplyDefaults()
		// 应用默认时区
		assert.Equal(t, "UTC", applied.TimeZone)
	})
}

// TestOutputConfig_EdgeCases 测试输出配置边界情况
func TestOutputConfig_EdgeCases(t *testing.T) {
	t.Run("禁用的输出", func(t *testing.T) {
		oc := OutputConfig{
			Type:    Stdout,
			Level:   InfoLevel,
			Enabled: false,
		}
		err := oc.Validate()
		// 禁用的输出应该跳过验证
		assert.NoError(t, err)
	})

	t.Run("所有日志级别", func(t *testing.T) {
		levels := []LogLevel{DebugLevel, InfoLevel, WarnLevel, ErrorLevel, FatalLevel, PanicLevel}
		for _, level := range levels {
			oc := OutputConfig{
				Type:     Stdout,
				Level:    level,
				Encoding: JSON,
				Enabled:  true,
			}
			err := oc.Validate()
			assert.NoError(t, err, "级别 %s 应该有效", level)
		}
	})
}

// TestDatabaseConfig_EdgeCases 测试数据库配置边界情况
func TestDatabaseConfig_EdgeCases(t *testing.T) {
	t.Run("最小批量大小", func(t *testing.T) {
		dc := &DatabaseConfig{
			DriverName:     "mysql",
			DataSourceName: "root:password@tcp(localhost:3306)/logs",
			TableName:      "logs",
			BatchSize:      1,
			BatchInterval:  time.Millisecond,
		}
		err := dc.Validate()
		assert.NoError(t, err)
	})

	t.Run("最大批量大小", func(t *testing.T) {
		dc := &DatabaseConfig{
			DriverName:     "mysql",
			DataSourceName: "root:password@tcp(localhost:3306)/logs",
			TableName:      "logs",
			BatchSize:      10000,
		}
		err := dc.Validate()
		assert.NoError(t, err)
	})

	t.Run("零批量间隔", func(t *testing.T) {
		dc := &DatabaseConfig{
			DriverName:     "mysql",
			DataSourceName: "root:password@tcp(localhost:3306)/logs",
			TableName:      "logs",
			BatchInterval:  0,
		}
		err := dc.Validate()
		assert.NoError(t, err)
	})
}

// TestTimeSeriesConfig_EdgeCases 测试时序数据库配置边界情况
func TestTimeSeriesConfig_EdgeCases(t *testing.T) {
	t.Run("带HTTPS的URL", func(t *testing.T) {
		ts := &TimeSeriesConfig{
			URL:    "https://localhost:8086",
			Org:    "test-org",
			Bucket: "test-bucket",
			Token:  "test-token",
		}
		err := ts.Validate()
		assert.NoError(t, err)
	})

	t.Run("长Token", func(t *testing.T) {
		longToken := strings.Repeat("a", 1000)
		ts := &TimeSeriesConfig{
			URL:    "http://localhost:8086",
			Org:    "test-org",
			Bucket: "test-bucket",
			Token:  longToken,
		}
		err := ts.Validate()
		assert.NoError(t, err)
	})
}

// TestSyslogConfig_EdgeCases 测试Syslog配置边界情况
func TestSyslogConfig_EdgeCases(t *testing.T) {
	t.Run("UDP网络", func(t *testing.T) {
		sc := &SyslogConfig{
			Network:  "udp",
			Address:  "localhost:514",
			Tag:      "test-app",
			Facility: 16,
		}
		err := sc.Validate()
		assert.NoError(t, err)
	})

	t.Run("RFC3164格式", func(t *testing.T) {
		sc := &SyslogConfig{
			Network:  "tcp",
			Address:  "localhost:514",
			Tag:      "test-app",
			Facility: 16,
			RFC5424:  false,
		}
		err := sc.Validate()
		assert.NoError(t, err)
	})

	t.Run("所有设施值", func(t *testing.T) {
		for facility := 0; facility <= 23; facility++ {
			sc := &SyslogConfig{
				Network:  "tcp",
				Address:  "localhost:514",
				Tag:      "test-app",
				Facility: facility,
			}
			err := sc.Validate()
			assert.NoError(t, err, "设施值 %d 应该有效", facility)
		}
	})
}

// TestSamplingConfig_EdgeCases 测试采样配置边界情况
func TestSamplingConfig_EdgeCases(t *testing.T) {
	t.Run("最大采样率", func(t *testing.T) {
		sc := SamplingConfig{
			Enabled:    true,
			Initial:    1000000,
			Thereafter: 500000,
			Window:     time.Hour,
		}
		err := sc.Validate()
		assert.NoError(t, err)
	})

	t.Run("最小窗口", func(t *testing.T) {
		sc := SamplingConfig{
			Enabled:    true,
			Initial:    10,
			Thereafter: 5,
			Window:     time.Nanosecond,
		}
		err := sc.Validate()
		assert.NoError(t, err)
	})

	t.Run("所有记录", func(t *testing.T) {
		sc := SamplingConfig{
			Enabled:    true,
			Initial:    1,
			Thereafter: 1,
			Window:     time.Second,
		}
		err := sc.Validate()
		assert.NoError(t, err)
	})
}

// TestComplexConfiguration 测试复杂配置场景
func TestComplexConfiguration(t *testing.T) {
	t.Run("多输出配置", func(t *testing.T) {
		lc := LoggerConfig{
			ServiceName: "test-service",
			Outputs: []OutputConfig{
				{
					Type:     Stdout,
					Level:    DebugLevel,
					Encoding: JSON,
					Enabled:  true,
				},
				{
					Type:     File,
					Level:    InfoLevel,
					Encoding: Console,
					Enabled:  true,
					File: &FileConfig{
						Path:       "/var/log/test.log",
						MaxSizeMB:  100,
						MaxBackups: 10,
						MaxAgeDays: 30,
					},
				},
				{
					Type:     DB,
					Level:    ErrorLevel,
					Encoding: JSON,
					Enabled:  true,
					Database: &DatabaseConfig{
						DriverName:     "mysql",
						DataSourceName: "root:password@tcp(localhost:3306)/logs",
						TableName:      "logs",
						BatchSize:      100,
						BatchInterval:  5 * time.Second,
						MaxOpenConns:   10,
						MaxIdleConns:   5,
					},
				},
				{
					Type:     Syslog,
					Level:    WarnLevel,
					Encoding: JSON,
					Enabled:  true,
					Syslog: &SyslogConfig{
						Network:  "tcp",
						Address:  "localhost:514",
						Tag:      "test-app",
						Facility: 16,
						RFC5424:  true,
					},
				},
			},
			Sampling: SamplingConfig{
				Enabled:    true,
				Initial:    100,
				Thereafter: 10,
				Window:     time.Minute,
			},
			Encoder: EncoderConfig{
				MessageKey:    "msg",
				LevelKey:      "level",
				TimeKey:       "time",
				TimeFormat:    time.RFC3339Nano,
				TimeZone:      "Asia/Shanghai",
				CallerKey:     "caller",
				StacktraceKey: "stacktrace",
				EnableCaller:  true,
				CustomFields: map[string]string{
					"env":     "production",
					"version": "1.0.0",
				},
			},
		}
		err := lc.Validate()
		assert.NoError(t, err)
	})

	t.Run("混合启用和禁用的输出", func(t *testing.T) {
		lc := LoggerConfig{
			ServiceName: "test-service",
			Outputs: []OutputConfig{
				{
					Type:     Stdout,
					Level:    InfoLevel,
					Encoding: JSON,
					Enabled:  true,
				},
				{
					Type:    File,
					Level:   DebugLevel,
					Enabled: false, // 禁用
				},
				{
					Type:    DB,
					Level:   ErrorLevel,
					Enabled: false, // 禁用
				},
			},
		}
		err := lc.Validate()
		assert.NoError(t, err)
	})
}

// TestConfigurationDefaults 测试配置默认值
func TestConfigurationDefaults(t *testing.T) {
	t.Run("编码器默认值", func(t *testing.T) {
		ec := EncoderConfig{}
		applied := ec.ApplyDefaults()

		assert.Equal(t, DefaultTimeFormat, applied.TimeFormat)
		assert.Equal(t, "UTC", applied.TimeZone)
		assert.Equal(t, "msg", applied.MessageKey)
		assert.Equal(t, "level", applied.LevelKey)
		assert.Equal(t, "time", applied.TimeKey)
		assert.Equal(t, "caller", applied.CallerKey)
		assert.Equal(t, "stacktrace", applied.StacktraceKey)
		assert.False(t, applied.EnableCaller)
		assert.False(t, applied.EnableStacktrace)
	})

	t.Run("文件默认值", func(t *testing.T) {
		fc := FileConfig{Path: "/var/log/test.log"}
		err := fc.Validate()
		require.NoError(t, err)

		assert.Equal(t, DefaultFileMaxSizeMB, fc.MaxSizeMB)
		assert.Equal(t, DefaultMaxBackups, fc.MaxBackups)
		assert.Equal(t, DefaultMaxAgeDays, fc.MaxAgeDays)
		assert.False(t, fc.Compress)
		assert.False(t, fc.RotateOnStartup)
		assert.False(t, fc.LocalTime)
	})

	t.Run("数据库默认值", func(t *testing.T) {
		dc := DatabaseConfig{
			DriverName:     "mysql",
			DataSourceName: "root:password@tcp(localhost:3306)/logs",
			TableName:      "logs",
		}
		err := dc.Validate()
		require.NoError(t, err)

		assert.Equal(t, DefaultBatchSize, dc.BatchSize)
		assert.Equal(t, DefaultBatchInterval, dc.BatchInterval)
		assert.Equal(t, DefaultMaxOpenConns, dc.MaxOpenConns)
		assert.Equal(t, DefaultMaxIdleConns, dc.MaxIdleConns)
	})
}

// TestSpecialConfigurations 测试特殊配置场景
func TestSpecialConfigurations(t *testing.T) {
	t.Run("包含自定义字段的编码器", func(t *testing.T) {
		ec := EncoderConfig{
			CustomFields: map[string]string{
				"service":  "my-service",
				"instance": "prod-1",
				"region":   "us-west-2",
			},
		}
		applied := ec.ApplyDefaults()
		assert.Len(t, applied.CustomFields, 3)
	})

	t.Run("超长服务名", func(t *testing.T) {
		longName := strings.Repeat("a", 1000)
		lc := LoggerConfig{
			ServiceName: longName,
			Outputs: []OutputConfig{
				{
					Type:     Stdout,
					Level:    InfoLevel,
					Encoding: JSON,
					Enabled:  true,
				},
			},
		}
		err := lc.Validate()
		assert.NoError(t, err)
	})

	t.Run("包含特殊字符的服务名", func(t *testing.T) {
		specialNames := []string{
			"test_service",
			"test-service",
			"test.service",
			"测试服务",
		}
		for _, name := range specialNames {
			lc := LoggerConfig{
				ServiceName: name,
				Outputs: []OutputConfig{
					{
						Type:     Stdout,
						Level:    InfoLevel,
						Encoding: JSON,
						Enabled:  true,
					},
				},
			}
			err := lc.Validate()
			assert.NoError(t, err, "服务名 '%s' 应该有效", name)
		}
	})
}
