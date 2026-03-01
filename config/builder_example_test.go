package config_test

import (
	"testing"
	"time"

	"github.com/iuboy/mebsuta/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ExampleLoggerConfigBuilder_basic 演示基本的Builder用法
func ExampleLoggerConfigBuilder_basic() {
	// 使用Builder创建配置
	cfg, err := config.NewLoggerConfigBuilder("my-service").
		AddStdoutOutput(config.InfoLevel, config.Console).
		Build()

	if err != nil {
		panic(err)
	}

	_ = cfg
	// Output:
}

// ExampleLoggerConfigBuilder_fileOutput 演示添加文件输出
func ExampleLoggerConfigBuilder_fileOutput() {
	cfg, err := config.NewLoggerConfigBuilder("my-service").
		AddStdoutOutput(config.InfoLevel, config.Console).
		AddFileOutput(
			config.DebugLevel,
			config.JSON,
			"/var/log/my-service/app.log",
			config.WithFileRotation(100, 5, 30),
			config.WithFileCompression(true),
		).
		Build()

	if err != nil {
		panic(err)
	}

	_ = cfg
}

// ExampleLoggerConfigBuilder_databaseOutput 演示添加数据库输出
func ExampleLoggerConfigBuilder_databaseOutput() {
	cfg, err := config.NewLoggerConfigBuilder("my-service").
		AddStdoutOutput(config.InfoLevel, config.Console).
		AddDatabaseOutput(
			config.InfoLevel,
			"mysql",
			"root:password@tcp(localhost:3306)/logs",
			"app_logs",
			config.WithBatchSize(100),
			config.WithBatchInterval(5*time.Second),
			config.WithConnectionPool(10, 5, time.Hour),
		).
		Build()

	if err != nil {
		panic(err)
	}

	_ = cfg
}

// ExampleLoggerConfigBuilder_sampling 演示配置日志采样
func ExampleLoggerConfigBuilder_sampling() {
	cfg, err := config.NewLoggerConfigBuilder("my-service").
		AddStdoutOutput(config.InfoLevel, config.Console).
		WithSampling(100, 10, 60*time.Second).
		Build()

	if err != nil {
		panic(err)
	}

	_ = cfg
}

// ExampleLoggerConfigBuilder_customEncoder 演示自定义编码器配置
func ExampleLoggerConfigBuilder_customEncoder() {
	cfg, err := config.NewLoggerConfigBuilder("my-service").
		AddStdoutOutput(config.InfoLevel, config.JSON).
		WithEncoderKeys("message", "severity", "timestamp").
		WithTimeFormat(time.RFC3339Nano, "Asia/Shanghai").
		WithCaller(true).
		WithStacktrace(true).
		Build()

	if err != nil {
		panic(err)
	}

	_ = cfg
}

// ExampleLoggerConfigBuilder_multipleOutputs 演示多输出配置
func ExampleLoggerConfigBuilder_multipleOutputs() {
	cfg, err := config.NewLoggerConfigBuilder("my-service").
		AddStdoutOutput(config.InfoLevel, config.Console).
		AddFileOutput(
			config.DebugLevel,
			config.JSON,
			"/var/log/my-service/app.log",
		).
		AddDatabaseOutput(
			config.InfoLevel,
			"influxdb",
			"",
			"",
			config.WithTimeSeries(
				"http://localhost:8086",
				"my-org",
				"my-bucket",
				"my-token",
			),
		).
		WithSampling(100, 10, 60*time.Second).
		Build()

	if err != nil {
		panic(err)
	}

	_ = cfg
}

func TestLoggerConfigBuilder_Basic(t *testing.T) {
	cfg, err := config.NewLoggerConfigBuilder("test-service").
		AddStdoutOutput(config.InfoLevel, config.Console).
		Build()

	require.NoError(t, err)
	assert.Equal(t, "test-service", cfg.ServiceName)
	assert.Len(t, cfg.Outputs, 1)
	assert.Equal(t, config.Stdout, cfg.Outputs[0].Type)
	assert.Equal(t, config.InfoLevel, cfg.Outputs[0].Level)
}

func TestLoggerConfigBuilder_FileOutput(t *testing.T) {
	cfg, err := config.NewLoggerConfigBuilder("test-service").
		AddFileOutput(
			config.DebugLevel,
			config.JSON,
			"/var/log/app.log",
			config.WithFileRotation(100, 5, 30),
			config.WithFileCompression(true),
		).
		Build()

	require.NoError(t, err)
	assert.Len(t, cfg.Outputs, 1)
	assert.Equal(t, config.File, cfg.Outputs[0].Type)
	assert.NotNil(t, cfg.Outputs[0].File)
	assert.Equal(t, "/var/log/app.log", cfg.Outputs[0].File.Path)
	assert.Equal(t, 100, cfg.Outputs[0].File.MaxSizeMB)
	assert.Equal(t, 5, cfg.Outputs[0].File.MaxBackups)
	assert.Equal(t, 30, cfg.Outputs[0].File.MaxAgeDays)
	assert.True(t, cfg.Outputs[0].File.Compress)
}

func TestLoggerConfigBuilder_DatabaseOutput(t *testing.T) {
	cfg, err := config.NewLoggerConfigBuilder("test-service").
		AddDatabaseOutput(
			config.InfoLevel,
			"mysql",
			"root:password@tcp(localhost:3306)/logs",
			"app_logs",
			config.WithBatchSize(200),
			config.WithBatchInterval(10*time.Second),
			config.WithConnectionPool(20, 10, 2*time.Hour),
		).
		Build()

	require.NoError(t, err)
	assert.Len(t, cfg.Outputs, 1)
	assert.Equal(t, config.DB, cfg.Outputs[0].Type)
	assert.NotNil(t, cfg.Outputs[0].Database)
	assert.Equal(t, "mysql", cfg.Outputs[0].Database.DriverName)
	assert.Equal(t, 200, cfg.Outputs[0].Database.BatchSize)
	assert.Equal(t, 10*time.Second, cfg.Outputs[0].Database.BatchInterval)
	assert.Equal(t, 20, cfg.Outputs[0].Database.MaxOpenConns)
}

func TestLoggerConfigBuilder_Sampling(t *testing.T) {
	cfg, err := config.NewLoggerConfigBuilder("test-service").
		AddStdoutOutput(config.InfoLevel, config.Console).
		WithSampling(50, 5, 30*time.Second).
		Build()

	require.NoError(t, err)
	assert.True(t, cfg.Sampling.Enabled)
	assert.Equal(t, 50, cfg.Sampling.Initial)
	assert.Equal(t, 5, cfg.Sampling.Thereafter)
	assert.Equal(t, 30*time.Second, cfg.Sampling.Window)
}

func TestLoggerConfigBuilder_CustomEncoder(t *testing.T) {
	cfg, err := config.NewLoggerConfigBuilder("test-service").
		AddStdoutOutput(config.InfoLevel, config.JSON).
		WithEncoderKeys("message", "severity", "timestamp").
		WithTimeFormat(time.RFC3339, "UTC").
		WithCaller(true).
		WithStacktrace(true).
		Build()

	require.NoError(t, err)
	assert.Equal(t, "message", cfg.Encoder.MessageKey)
	assert.Equal(t, "severity", cfg.Encoder.LevelKey)
	assert.Equal(t, "timestamp", cfg.Encoder.TimeKey)
	assert.Equal(t, time.RFC3339, cfg.Encoder.TimeFormat)
	assert.Equal(t, "UTC", cfg.Encoder.TimeZone)
	assert.True(t, cfg.Encoder.EnableCaller)
	assert.True(t, cfg.Encoder.EnableStacktrace)
}

func TestLoggerConfigBuilder_MultipleOutputs(t *testing.T) {
	cfg, err := config.NewLoggerConfigBuilder("test-service").
		AddStdoutOutput(config.InfoLevel, config.Console).
		AddFileOutput(config.DebugLevel, config.JSON, "/var/log/app.log").
		WithSampling(100, 10, 60*time.Second).
		Build()

	require.NoError(t, err)
	assert.Len(t, cfg.Outputs, 2)
	assert.Equal(t, config.Stdout, cfg.Outputs[0].Type)
	assert.Equal(t, config.File, cfg.Outputs[1].Type)
	assert.True(t, cfg.Sampling.Enabled)
}

func TestLoggerConfigBuilder_Validation(t *testing.T) {
	// 空服务名应该失败
	_, err := config.NewLoggerConfigBuilder("").
		AddStdoutOutput(config.InfoLevel, config.Console).
		Build()

	assert.Error(t, err)
}

func TestLoggerConfigBuilder_MustBuild(t *testing.T) {
	// 成功构建
	cfg := config.NewLoggerConfigBuilder("test-service").
		AddStdoutOutput(config.InfoLevel, config.Console).
		MustBuild()

	assert.NotNil(t, cfg)

	// 失败构建应该panic
	assert.Panics(t, func() {
		config.NewLoggerConfigBuilder("").
			AddStdoutOutput(config.InfoLevel, config.Console).
			MustBuild()
	})
}
