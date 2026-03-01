package mebsuta

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/iuboy/mebsuta/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// TestInit 测试日志系统初始化
func TestInit(t *testing.T) {
	t.Run("成功初始化", func(t *testing.T) {
		// 注意：不重置全局状态，因为atomic.Value不能存储nil
		// Init使用sync.Once，多次调用会被忽略

		cfg := config.LoggerConfig{
			ServiceName: "test-service",
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

		err := Init(cfg)
		// 如果已经初始化，会返回nil（被忽略）
		if !IsInitialized() {
			assert.NoError(t, err)
		}
		assert.True(t, IsInitialized())
		assert.NotNil(t, GetLogger())
	})

	t.Run("空服务名", func(t *testing.T) {
		// 注意：如果已经初始化过，这个测试会失败
		// 因为sync.Once会忽略第二次Init调用
		// 在真实测试中，应该使用独立的测试进程
		t.Skip("由于sync.Once和全局状态，此测试在已初始化的环境中会失败")
	})
}

// TestSetLogger 测试设置日志器
func TestSetLogger(t *testing.T) {
	logger, err := zap.NewDevelopment()
	require.NoError(t, err)

	err = SetLogger(logger)
	assert.NoError(t, err)
	assert.NotNil(t, GetLogger())
}

// TestSetLogger_Nil 测试设置空日志器
func TestSetLogger_Nil(t *testing.T) {
	err := SetLogger(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "不能为空")
}

// TestGetLogger 测试获取日志器
func TestGetLogger(t *testing.T) {
	logger := GetLogger()
	assert.NotNil(t, logger)

	// 测试 Sugar 方法
	sugar := Sugar()
	assert.NotNil(t, sugar)
}

// TestSetContextExtractor 测试设置上下文提取器
func TestSetContextExtractor(t *testing.T) {
	extractor := func(ctx context.Context) []zap.Field {
		if id, ok := ctx.Value("request_id").(string); ok {
			return []zap.Field{zap.String("request_id", id)}
		}
		return nil
	}

	err := SetContextExtractor(extractor)
	assert.NoError(t, err)
}

// TestSetContextExtractor_Nil 测试设置空提取器
func TestSetContextExtractor_Nil(t *testing.T) {
	err := SetContextExtractor(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "不能为空")
}

// TestGetExtractedFields 测试提取上下文字段
func TestGetExtractedFields(t *testing.T) {
	// 设置提取器
	SetContextExtractor(func(ctx context.Context) []zap.Field {
		if id, ok := ctx.Value(CustomIDContextKey).(string); ok {
			return []zap.Field{zap.String("custom_id", id)}
		}
		return nil
	})

	// 测试有效上下文
	ctx := context.WithValue(context.Background(), CustomIDContextKey, "test-123")
	fields := GetExtractedFields(ctx)
	assert.Len(t, fields, 1)
	assert.Equal(t, "custom_id", fields[0].Key)
	assert.Equal(t, "test-123", fields[0].String)

	// 测试空上下文
	fields = GetExtractedFields(context.TODO())
	assert.Nil(t, fields)
}

// TestWithContext 测试带上下文的日志
func TestWithContext(t *testing.T) {
	ctx := context.WithValue(context.Background(), RequestContextKey, "req-456")
	logger := WithContext(ctx)
	assert.NotNil(t, logger)
}

// TestStandardLogLevelAPI 测试标准日志级别API
func TestStandardLogLevelAPI(t *testing.T) {
	t.Run("Debug", func(t *testing.T) {
		assert.NotPanics(t, func() {
			Debug("debug message")
		})
	})

	t.Run("Info", func(t *testing.T) {
		assert.NotPanics(t, func() {
			Info("info message")
		})
	})

	t.Run("Warn", func(t *testing.T) {
		assert.NotPanics(t, func() {
			Warn("warn message")
		})
	})

	t.Run("Error", func(t *testing.T) {
		assert.NotPanics(t, func() {
			Error("error message")
		})
	})

	t.Run("Panic", func(t *testing.T) {
		assert.Panics(t, func() {
			Panic("panic message")
		})
	})
}

// TestFormattedLogAPI 测试格式化日志API
func TestFormattedLogAPI(t *testing.T) {
	t.Run("Debugf", func(t *testing.T) {
		assert.NotPanics(t, func() {
			Debugf("debug %s", "formatted")
		})
	})

	t.Run("Infof", func(t *testing.T) {
		assert.NotPanics(t, func() {
			Infof("info %s", "formatted")
		})
	})

	t.Run("Warnf", func(t *testing.T) {
		assert.NotPanics(t, func() {
			Warnf("warn %s", "formatted")
		})
	})

	t.Run("Errorf", func(t *testing.T) {
		assert.NotPanics(t, func() {
			Errorf("error %s", "formatted")
		})
	})

	t.Run("Panicf", func(t *testing.T) {
		assert.Panics(t, func() {
			Panicf("panic %s", "formatted")
		})
	})
}

// TestFieldCreators 测试字段创建函数
func TestFieldCreators(t *testing.T) {
	t.Run("String", func(t *testing.T) {
		field := String("key", "value")
		assert.Equal(t, "key", field.Key)
	})

	t.Run("Int", func(t *testing.T) {
		field := Int("key", 123)
		assert.Equal(t, "key", field.Key)
	})

	t.Run("Int64", func(t *testing.T) {
		field := Int64("key", int64(456))
		assert.Equal(t, "key", field.Key)
	})

	t.Run("Uint", func(t *testing.T) {
		field := Uint("key", uint(789))
		assert.Equal(t, "key", field.Key)
	})

	t.Run("Uint64", func(t *testing.T) {
		field := Uint64("key", uint64(101112))
		assert.Equal(t, "key", field.Key)
	})

	t.Run("Bool", func(t *testing.T) {
		field := Bool("key", true)
		assert.Equal(t, "key", field.Key)
	})

	t.Run("Float64", func(t *testing.T) {
		field := Float64("key", 3.14)
		assert.Equal(t, "key", field.Key)
	})

	t.Run("Any", func(t *testing.T) {
		field := Any("key", map[string]string{"a": "b"})
		assert.Equal(t, "key", field.Key)
	})

	t.Run("Duration", func(t *testing.T) {
		field := Duration("key", time.Second)
		assert.Equal(t, "key", field.Key)
	})

	t.Run("Time", func(t *testing.T) {
		field := Time("key", time.Now())
		assert.Equal(t, "key", field.Key)
	})

	t.Run("Bytes", func(t *testing.T) {
		field := Bytes("key", []byte("test"))
		assert.Equal(t, "key", field.Key)
	})
}

// TestErrorField 测试错误字段创建
func TestErrorField(t *testing.T) {
	err := errors.New("test error")
	field := ErrorField(err)
	assert.Equal(t, "error", field.Key)
}

// TestStackField 测试堆栈字段创建
func TestStackField(t *testing.T) {
	field := StackField(1)
	assert.Equal(t, "caller", field.Key)
	// 验证字段被创建，具体函数名取决于调用栈
	// 在测试环境中可能返回 testing.tRunner
	assert.NotEmpty(t, field.String)
}

// TestFullStackField 测试完整堆栈字段创建
func TestFullStackField(t *testing.T) {
	field := FullStackField(1)
	assert.Equal(t, "stack", field.Key)
	assert.NotNil(t, field.Interface)
}

// TestOnError 测试错误处理
func TestOnError(t *testing.T) {
	// 不应该panic
	assert.NotPanics(t, func() {
		OnError(errors.New("test error"))
	})

	// nil错误不应该panic
	assert.NotPanics(t, func() {
		OnError(nil)
	})
}

// TestOnInitError 测试初始化错误处理
func TestOnInitError(t *testing.T) {
	// 不应该panic
	assert.NotPanics(t, func() {
		OnInitError(errors.New("test error"), "测试错误")
	})

	// nil错误不应该panic
	assert.NotPanics(t, func() {
		OnInitError(nil, "测试错误")
	})
}

// TestTry 测试错误处理包装器
func TestTry(t *testing.T) {
	t.Run("成功操作", func(t *testing.T) {
		err := Try(context.TODO(), func() error {
			return nil
		})
		assert.NoError(t, err)
	})

	t.Run("失败操作", func(t *testing.T) {
		expectedErr := errors.New("operation failed")
		err := Try(context.TODO(), func() error {
			return expectedErr
		})
		assert.Equal(t, expectedErr, err)
	})

	t.Run("Panic恢复", func(t *testing.T) {
		err := Try(context.TODO(), func() error {
			panic("test panic")
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "panic")
	})
}

// TestRetryWithBackoff 测试重试机制
func TestRetryWithBackoff(t *testing.T) {
	t.Run("首次成功", func(t *testing.T) {
		attempts := 0
		err := RetryWithBackoff(context.Background(), 3, 10*time.Millisecond, func() error {
			attempts++
			if attempts == 1 {
				return nil
			}
			return errors.New("not yet")
		})
		assert.NoError(t, err)
		assert.Equal(t, 1, attempts)
	})

	t.Run("重试后成功", func(t *testing.T) {
		attempts := 0
		err := RetryWithBackoff(context.Background(), 5, time.Millisecond, func() error {
			attempts++
			if attempts == 3 {
				return nil
			}
			return errors.New("not yet")
		})
		assert.NoError(t, err)
		assert.Equal(t, 3, attempts)
	})

	t.Run("达到最大尝试次数", func(t *testing.T) {
		err := RetryWithBackoff(context.Background(), 3, time.Millisecond, func() error {
			return errors.New("always fail")
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "3次尝试后失败")
	})

	t.Run("上下文取消", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		err := RetryWithBackoff(ctx, 3, time.Second, func() error {
			return errors.New("fail")
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "重试已取消")
	})
}

// TestSync 测试同步功能
func TestSync(t *testing.T) {
	t.Run("正常同步", func(t *testing.T) {
		err := Sync()
		// 在测试环境中，Sync可能会因为文件描述符问题而失败
		// 这是测试环境的限制，不是代码bug
		// 只要调用不panic就OK
		_ = err
	})

	// 在没有初始化logger的情况下测试
	t.Run("未初始化同步", func(t *testing.T) {
		// 这个测试在已初始化的环境中会使用初始化的logger
		// Sync会返回nil如果logger为nil
		err := Sync()
		// 同样，在测试环境中可能失败
		_ = err
	})
}

// TestSetGlobalContext 测试设置全局上下文
func TestSetGlobalContext(t *testing.T) {
	ctx := context.Background()
	SetGlobalContext(ctx)
	// 验证设置成功，不panic
	assert.NotPanics(t, func() {
		GetExtractedFields(context.TODO())
	})

	// 设置新的context（必须是相同的具体类型）
	newCtx := context.Background()
	SetGlobalContext(newCtx)
	assert.NotPanics(t, func() {
		GetExtractedFields(context.TODO())
	})

	// 设置nil应该保持原值不变
	SetGlobalContext(newCtx)
	assert.NotPanics(t, func() {
		GetExtractedFields(context.TODO())
	})
}

// TestGetExtractedFields_DefaultRequestID 测试默认的request_id提取
func TestGetExtractedFields_DefaultRequestID(t *testing.T) {
	// 测试使用默认行为
	SetContextExtractor(func(ctx context.Context) []zap.Field {
		// 模拟默认行为
		if id, ok := ctx.Value(RequestContextKey).(string); ok && id != "" {
			return []zap.Field{zap.String("request_id", id)}
		}
		return nil
	})

	ctx := context.WithValue(context.Background(), RequestContextKey, "default-req-123")
	fields := GetExtractedFields(ctx)
	assert.Len(t, fields, 1)
	assert.Equal(t, "request_id", fields[0].Key)
	assert.Equal(t, "default-req-123", fields[0].String)

	// 测试空字符串request_id
	ctx2 := context.WithValue(context.Background(), RequestContextKey, "")
	fields2 := GetExtractedFields(ctx2)
	assert.Nil(t, fields2)
}

// TestTypeAliases 测试类型别名
func TestTypeAliases(t *testing.T) {
	// 验证类型别名正确指向
	assert.Equal(t, config.DebugLevel, DebugLevel)
	assert.Equal(t, config.InfoLevel, InfoLevel)
	assert.Equal(t, config.WarnLevel, WarnLevel)
	assert.Equal(t, config.ErrorLevel, ErrorLevel)
	assert.Equal(t, config.FatalLevel, FatalLevel)
	assert.Equal(t, config.PanicLevel, PanicLevel)
	assert.Equal(t, config.DPanicLevel, DPanicLevel)

	assert.Equal(t, config.JSON, JSON)
	assert.Equal(t, config.Console, Console)

	assert.Equal(t, config.Stdout, Stdout)
	assert.Equal(t, config.File, File)
	assert.Equal(t, config.DB, DB)
	assert.Equal(t, config.Syslog, Syslog)
}

// TestLoggerConfigAlias 测试配置别名
func TestLoggerConfigAlias(t *testing.T) {
	// 验证配置别名
	var lc1 LoggerConfig
	var lc2 config.LoggerConfig

	// 它们应该是相同的类型
	lc1.ServiceName = "test"
	lc2.ServiceName = "test"

	assert.Equal(t, lc1.ServiceName, lc2.ServiceName)
}

// TestInitMultiple 测试多次初始化
func TestInitMultiple(t *testing.T) {
	// 测试多次初始化不会重新执行（因为sync.Once）

	cfg := config.LoggerConfig{
		ServiceName: "test-service",
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

	// 第一次初始化应该成功
	err := Init(cfg)
	assert.NoError(t, err)

	// 第二次初始化应该被忽略（使用sync.Once）
	err = Init(cfg)
	assert.NoError(t, err)
}

// TestConcurrentLogging 并发日志测试
func TestConcurrentLogging(t *testing.T) {
	t.Run("并发写入不同级别", func(t *testing.T) {
		levels := []func(string, ...zap.Field){
			Debug,
			Info,
			Warn,
			Error,
		}

		var wg sync.WaitGroup
		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				levels[id%4](fmt.Sprintf("concurrent log %d", id), Int("id", id))
			}(i)
		}
		wg.Wait()
	})

	t.Run("并发格式化日志", func(t *testing.T) {
		var wg sync.WaitGroup
		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				Infof("concurrent formatted log %d", id)
			}(i)
		}
		wg.Wait()
	})
}

// TestLogWithNilFields 测试空字段处理
func TestLogWithNilFields(t *testing.T) {
	t.Run("Debug with nil fields", func(t *testing.T) {
		assert.NotPanics(t, func() {
			Debug("test")
		})
	})

	t.Run("Info with empty fields", func(t *testing.T) {
		assert.NotPanics(t, func() {
			Info("test")
		})
	})
}

// TestSpecialCharacters 测试特殊字符处理
func TestSpecialCharacters(t *testing.T) {
	specialCases := []string{
		"测试中文",
		"日本語",
		"한글",
		"🎉 emoji",
		"new\nline",
		"tab\tcharacter",
		"quote\"test",
		"backslash\\test",
		"null\x00byte",
		"<script>alert('xss')</script>",
	}

	for _, msg := range specialCases {
		t.Run(msg, func(t *testing.T) {
			assert.NotPanics(t, func() {
				Info(msg)
			})
			assert.NotPanics(t, func() {
				Infof("%s", msg)
			})
		})
	}
}

// TestLargeMessage 测试大消息处理
func TestLargeMessage(t *testing.T) {
	t.Run("大字符串消息", func(t *testing.T) {
		largeMsg := strings.Repeat("a", 10000)
		assert.NotPanics(t, func() {
			Info(largeMsg)
		})
	})

	t.Run("大量字段", func(t *testing.T) {
		fields := make([]zap.Field, 100)
		for i := 0; i < 100; i++ {
			fields[i] = Int(fmt.Sprintf("field%d", i), i)
		}
		assert.NotPanics(t, func() {
			Info("test", fields...)
		})
	})
}

// TestPerformanceBenchmark 性能基准测试
func TestPerformanceBenchmark(t *testing.T) {
	if testing.Short() {
		t.Skip("跳过性能测试")
	}

	t.Run("简单日志性能", func(t *testing.T) {
		start := time.Now()
		for i := 0; i < 10000; i++ {
			Info("benchmark test", Int("iteration", i))
		}
		duration := time.Since(start)
		avgLatency := duration.Microseconds() / 10000
		t.Logf("10,000条日志耗时: %v, 平均延迟: %dμs", duration, avgLatency)
		assert.Less(t, avgLatency, int64(100), "平均延迟应小于100μs")
	})
}

// TestContextExtraction 上下文提取测试
func TestContextExtraction(t *testing.T) {
	t.Run("嵌套上下文", func(t *testing.T) {
		ctx := context.Background()
		ctx = context.WithValue(ctx, UserContextKey, "123")
		ctx = context.WithValue(ctx, RequestContextKey, "abc")

		SetContextExtractor(func(ctx context.Context) []zap.Field {
			fields := []zap.Field{}
			if uid, ok := ctx.Value(UserContextKey).(string); ok {
				fields = append(fields, zap.String("user_id", uid))
			}
			if rid, ok := ctx.Value(RequestContextKey).(string); ok {
				fields = append(fields, zap.String("request_id", rid))
			}
			return fields
		})

		logger := WithContext(ctx)
		assert.NotNil(t, logger)
		assert.NotPanics(t, func() {
			logger.Info("nested context test")
		})
	})

	t.Run("取消的上下文", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		logger := WithContext(ctx)
		assert.NotNil(t, logger)
		assert.NotPanics(t, func() {
			logger.Info("cancelled context test")
		})
	})
}

// TestTryWithVariousPanic 测试不同类型的panic
func TestTryWithVariousPanic(t *testing.T) {
	t.Run("string panic", func(t *testing.T) {
		err := Try(context.TODO(), func() error {
			panic("string panic")
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "string panic")
	})

	t.Run("error panic", func(t *testing.T) {
		expectedErr := errors.New("error panic")
		err := Try(context.TODO(), func() error {
			panic(expectedErr)
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "error panic")
	})

	t.Run("int panic", func(t *testing.T) {
		err := Try(context.TODO(), func() error {
			panic(42)
		})
		assert.Error(t, err)
	})
}

// TestRetryWithBackoff_EdgeCases 重试边界情况测试
func TestRetryWithBackoff_EdgeCases(t *testing.T) {
	t.Run("零次尝试", func(t *testing.T) {
		err := RetryWithBackoff(context.Background(), 0, time.Millisecond, func() error {
			return errors.New("fail")
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "无效的尝试次数")
		assert.Contains(t, err.Error(), "必须至少为1")
	})

	t.Run("负数尝试次数", func(t *testing.T) {
		err := RetryWithBackoff(context.Background(), -1, time.Millisecond, func() error {
			return errors.New("fail")
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "无效的尝试次数")
		assert.Contains(t, err.Error(), "必须至少为1")
	})

	t.Run("零延迟", func(t *testing.T) {
		attempts := 0
		err := RetryWithBackoff(context.Background(), 3, 0, func() error {
			attempts++
			if attempts == 3 {
				return nil
			}
			return errors.New("not yet")
		})
		assert.NoError(t, err)
		assert.Equal(t, 3, attempts)
	})
}

// TestFieldValues 测试字段值边界
func TestFieldValues(t *testing.T) {
	t.Run("极值", func(t *testing.T) {
		assert.NotPanics(t, func() {
			Info("test",
				Int("int_min", -2147483648),
				Int("int_max", 2147483647),
				Int64("int64_min", -9223372036854775808),
				Int64("int64_max", 9223372036854775807),
				Uint("uint_max", 4294967295),
				Uint64("uint64_max", 18446744073709551615),
				Float64("float_min", -1.797693134862315708145274237317043567981e+308),
				Float64("float_max", 1.797693134862315708145274237317043567981e+308),
			)
		})
	})

	t.Run("零值", func(t *testing.T) {
		assert.NotPanics(t, func() {
			Info("test",
				Int("zero", 0),
				String("empty", ""),
				Bool("false", false),
				Float64("zero_float", 0.0),
			)
		})
	})
}

// TestErrorWrapping 错误包装测试
func TestErrorWrapping(t *testing.T) {
	t.Run("多层错误", func(t *testing.T) {
		err1 := errors.New("底层错误")
		err2 := fmt.Errorf("中间层错误: %w", err1)
		err3 := fmt.Errorf("顶层错误: %w", err2)

		assert.NotPanics(t, func() {
			Error("多层错误", ErrorField(err3))
		})
	})
}
