package mebsuta_test

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/iuboy/mebsuta"
	"github.com/iuboy/mebsuta/config"
	"go.uber.org/zap"
)

func ExampleLoggerConfig_basic() {
	// 初始化日志系统
	cfg := config.LoggerConfig{
		ServiceName: "my-service",
		Outputs: []config.OutputConfig{
			{
				Type:     config.Stdout,
				Level:    config.InfoLevel,
				Encoding: config.JSON,
				Enabled:  true,
			},
		},
		Encoder: config.EncoderConfig{
			MessageKey: "msg",
			LevelKey:   "level",
			TimeKey:    "time",
		},
	}

	if err := mebsuta.Init(cfg); err != nil {
		log.Fatal(err)
	}
	defer mebsuta.Sync()

	// 记录日志
	mebsuta.Info("服务启动成功")
}

func ExampleLoggerConfig_withFile() {
	cfg := config.LoggerConfig{
		ServiceName: "my-service",
		Outputs: []config.OutputConfig{
			{
				Type:     config.File,
				Level:    config.DebugLevel,
				Encoding: config.JSON,
				Enabled:  true,
				File: &config.FileConfig{
					Path:       "/var/log/my-service/app.log",
					MaxSizeMB:  100,
					MaxBackups: 5,
					MaxAgeDays: 30,
					Compress:   true,
				},
			},
		},
		Encoder: config.EncoderConfig{
			MessageKey:       "msg",
			LevelKey:         "level",
			TimeKey:          "time",
			TimeFormat:       "2006-01-02T15:04:05.000Z07:00",
			TimeZone:         "Asia/Shanghai",
			EnableCaller:     true,
			EnableStacktrace: true,
		},
	}

	if err := mebsuta.Init(cfg); err != nil {
		log.Fatal(err)
	}
	defer mebsuta.Sync()

	mebsuta.Debug("调试信息", mebsuta.Int("port", 8080))
	mebsuta.Info("服务启动")
}

func ExampleLoggerConfig_withSampling() {
	cfg := config.LoggerConfig{
		ServiceName: "my-service",
		Outputs: []config.OutputConfig{
			{
				Type:     config.Stdout,
				Level:    config.InfoLevel,
				Encoding: config.Console,
				Enabled:  true,
			},
		},
		Sampling: config.SamplingConfig{
			Enabled:    true,
			Initial:    100, // 初始记录100条
			Thereafter: 10,  // 之后每10条记录1条
			Window:     60 * time.Second,
		},
		Encoder: config.EncoderConfig{
			MessageKey: "msg",
			LevelKey:   "level",
			TimeKey:    "time",
		},
	}

	if err := mebsuta.Init(cfg); err != nil {
		log.Fatal(err)
	}
	defer mebsuta.Sync()

	// 高频日志会自动采样
	for i := 0; i < 1000; i++ {
		mebsuta.Info("处理请求", mebsuta.Int("request_id", i))
	}
}

func ExampleLoggerConfig_withContext() {
	// 设置上下文提取器
	mebsuta.SetContextExtractor(func(ctx context.Context) []zap.Field {
		var fields []zap.Field
		if requestID, ok := ctx.Value("request_id").(string); ok {
			fields = append(fields, zap.String("request_id", requestID))
		}
		if userID, ok := ctx.Value("user_id").(string); ok {
			fields = append(fields, zap.String("user_id", userID))
		}
		return fields
	})

	cfg := config.LoggerConfig{
		ServiceName: "my-service",
		Outputs: []config.OutputConfig{
			{
				Type:     config.Stdout,
				Level:    config.InfoLevel,
				Encoding: config.JSON,
				Enabled:  true,
			},
		},
		Encoder: config.EncoderConfig{
			MessageKey: "msg",
			LevelKey:   "level",
			TimeKey:    "time",
		},
	}

	if err := mebsuta.Init(cfg); err != nil {
		log.Fatal(err)
	}
	defer mebsuta.Sync()

	// 使用上下文记录日志
	ctx := context.WithValue(context.Background(), mebsuta.RequestContextKey, "req-123")
	ctx = context.WithValue(ctx, mebsuta.UserContextKey, "user-456")

	logger := mebsuta.WithContext(ctx)
	logger.Info("处理用户请求")
}

func ExampleLoggerConfig_standardLevels() {
	cfg := config.LoggerConfig{
		ServiceName: "my-service",
		Outputs: []config.OutputConfig{
			{
				Type:     config.Stdout,
				Level:    config.DebugLevel,
				Encoding: config.Console,
				Enabled:  true,
			},
		},
		Encoder: config.EncoderConfig{
			MessageKey: "msg",
			LevelKey:   "level",
			TimeKey:    "time",
		},
	}

	if err := mebsuta.Init(cfg); err != nil {
		log.Fatal(err)
	}
	defer mebsuta.Sync()

	// 使用不同的日志级别
	mebsuta.Debug("调试信息")
	mebsuta.Info("普通信息")
	mebsuta.Warn("警告信息")
	mebsuta.Error("错误信息")
}

func ExampleLoggerConfig_formatted() {
	cfg := config.LoggerConfig{
		ServiceName: "my-service",
		Outputs: []config.OutputConfig{
			{
				Type:     config.Stdout,
				Level:    config.InfoLevel,
				Encoding: config.JSON,
				Enabled:  true,
			},
		},
		Encoder: config.EncoderConfig{
			MessageKey: "msg",
			LevelKey:   "level",
			TimeKey:    "time",
		},
	}

	if err := mebsuta.Init(cfg); err != nil {
		log.Fatal(err)
	}
	defer mebsuta.Sync()

	// 使用格式化API
	mebsuta.Debugf("用户 %s 登录成功", "张三")
	mebsuta.Infof("处理了 %d 个请求", 100)
	mebsuta.Warnf("内存使用率达到 %.2f%%", 85.5)
	mebsuta.Errorf("无法连接到数据库 %s", "localhost:3306")
}

func ExampleLoggerConfig_withFields() {
	cfg := config.LoggerConfig{
		ServiceName: "my-service",
		Outputs: []config.OutputConfig{
			{
				Type:     config.Stdout,
				Level:    config.InfoLevel,
				Encoding: config.JSON,
				Enabled:  true,
			},
		},
		Encoder: config.EncoderConfig{
			MessageKey: "msg",
			LevelKey:   "level",
			TimeKey:    "time",
		},
	}

	if err := mebsuta.Init(cfg); err != nil {
		log.Fatal(err)
	}
	defer mebsuta.Sync()

	// 使用结构化字段
	mebsuta.Info("用户登录",
		mebsuta.String("user_id", "user-123"),
		mebsuta.String("username", "zhangsan"),
		mebsuta.String("ip", "192.168.1.100"),
		mebsuta.Int("port", 12345),
		mebsuta.Bool("success", true),
	)
}

func ExampleLoggerConfig_errorHandling() {
	cfg := config.LoggerConfig{
		ServiceName: "my-service",
		Outputs: []config.OutputConfig{
			{
				Type:     config.Stdout,
				Level:    config.InfoLevel,
				Encoding: config.JSON,
				Enabled:  true,
			},
		},
		Encoder: config.EncoderConfig{
			MessageKey: "msg",
			LevelKey:   "level",
			TimeKey:    "time",
		},
	}

	if err := mebsuta.Init(cfg); err != nil {
		log.Fatal(err)
	}
	defer mebsuta.Sync()

	// 记录错误
	err := fmt.Errorf("数据库连接失败: %s", "timeout")
	if err != nil {
		mebsuta.Error("操作失败",
			mebsuta.ErrorField(err),
			mebsuta.String("operation", "query_user"),
		)
	}
}

func ExampleLoggerConfig_retry() {
	cfg := config.LoggerConfig{
		ServiceName: "my-service",
		Outputs: []config.OutputConfig{
			{
				Type:     config.Stdout,
				Level:    config.InfoLevel,
				Encoding: config.JSON,
				Enabled:  true,
			},
		},
		Encoder: config.EncoderConfig{
			MessageKey: "msg",
			LevelKey:   "level",
			TimeKey:    "time",
		},
	}

	if err := mebsuta.Init(cfg); err != nil {
		log.Fatal(err)
	}
	defer mebsuta.Sync()

	// 使用重试机制
	attempts := 0
	err := mebsuta.RetryWithBackoff(
		context.Background(),
		3,                    // 最大尝试次数
		100*time.Millisecond, // 初始延迟
		func() error {
			attempts++
			if attempts < 3 {
				return fmt.Errorf("暂时失败")
			}
			mebsuta.Info("操作成功", mebsuta.Int("attempts", attempts))
			return nil
		},
	)

	if err != nil {
		mebsuta.Error("重试失败", mebsuta.ErrorField(err))
	}
}

func ExampleLoggerConfig_try() {
	cfg := config.LoggerConfig{
		ServiceName: "my-service",
		Outputs: []config.OutputConfig{
			{
				Type:     config.Stdout,
				Level:    config.InfoLevel,
				Encoding: config.JSON,
				Enabled:  true,
			},
		},
		Encoder: config.EncoderConfig{
			MessageKey: "msg",
			LevelKey:   "level",
			TimeKey:    "time",
		},
	}

	if err := mebsuta.Init(cfg); err != nil {
		log.Fatal(err)
	}
	defer mebsuta.Sync()

	// 使用Try包装可能panic的操作
	err := mebsuta.Try(context.Background(), func() error {
		// 这里可能发生panic的代码
		mebsuta.Info("执行危险操作")
		return nil
	})

	if err != nil {
		mebsuta.Error("操作失败", mebsuta.ErrorField(err))
	}
}

// Example_multiOutput 演示多输出配置
func Example_multiOutput() {
	cfg := config.LoggerConfig{
		ServiceName: "my-service",
		Outputs: []config.OutputConfig{
			// 控制台输出
			{
				Type:     config.Stdout,
				Level:    config.InfoLevel,
				Encoding: config.Console,
				Enabled:  true,
			},
			// 文件输出
			{
				Type:     config.File,
				Level:    config.DebugLevel,
				Encoding: config.JSON,
				Enabled:  true,
				File: &config.FileConfig{
					Path:       "/var/log/my-service/app.log",
					MaxSizeMB:  100,
					MaxBackups: 5,
					MaxAgeDays: 30,
				},
			},
		},
		Encoder: config.EncoderConfig{
			MessageKey: "msg",
			LevelKey:   "level",
			TimeKey:    "time",
		},
	}

	if err := mebsuta.Init(cfg); err != nil {
		log.Fatal(err)
	}
	defer mebsuta.Sync()

	mebsuta.Info("日志同时输出到控制台和文件")
}

// Example_customFieldTypes 演示各种字段类型
func Example_customFieldTypes() {
	cfg := config.LoggerConfig{
		ServiceName: "my-service",
		Outputs: []config.OutputConfig{
			{
				Type:     config.Stdout,
				Level:    config.InfoLevel,
				Encoding: config.JSON,
				Enabled:  true,
			},
		},
		Encoder: config.EncoderConfig{
			MessageKey: "msg",
			LevelKey:   "level",
			TimeKey:    "time",
		},
	}

	if err := mebsuta.Init(cfg); err != nil {
		log.Fatal(err)
	}
	defer mebsuta.Sync()

	mebsuta.Info("结构化日志示例",
		mebsuta.String("string", "字符串值"),
		mebsuta.Int("int", 42),
		mebsuta.Int64("int64", 9223372036854775807),
		mebsuta.Float64("float64", 3.14159),
		mebsuta.Bool("bool", true),
		mebsuta.Duration("duration", 1000000000), // 1秒
		mebsuta.Any("any", map[string]string{"key": "value"}),
	)
}
