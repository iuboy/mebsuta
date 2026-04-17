package config

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
		require.NoError(t, err)
		assert.Equal(t, "logs", dc.TableName)
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
		assert.Contains(t, err.Error(), "invalid table name")
	})

	t.Run("无效表名-以数字开头", func(t *testing.T) {
		dc := &DatabaseConfig{
			DriverName:     "mysql",
			DataSourceName: "root:password@tcp(localhost:3306)/logs",
			TableName:      "123logs",
		}
		err := dc.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid table name")
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
		require.NoError(t, err)
		assert.Equal(t, "mebsuta", sc.Tag)
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

// TestConfigurationDefaults 测试配置默认值
func TestConfigurationDefaults(t *testing.T) {
	t.Run("文件默认值", func(t *testing.T) {
		fc := FileConfig{Path: "/var/log/test.log"}
		err := fc.Validate()
		require.NoError(t, err)

		assert.Equal(t, DefaultFileMaxSizeMB, fc.MaxSizeMB)
		assert.Equal(t, DefaultMaxBackups, fc.MaxBackups)
		assert.Equal(t, DefaultMaxAgeDays, fc.MaxAgeDays)
		assert.False(t, fc.Compress)
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
