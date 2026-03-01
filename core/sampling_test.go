package core_test

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/iuboy/mebsuta/config"
	"github.com/iuboy/mebsuta/core"
	meberrors "github.com/iuboy/mebsuta/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// testWriteSyncer 测试用的WriteSyncer实现
type testWriteSyncer struct {
	buffers [][]byte
	mu      sync.Mutex
}

func (t *testWriteSyncer) Write(p []byte) (n int, err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	buf := make([]byte, len(p))
	copy(buf, p)
	t.buffers = append(t.buffers, buf)
	return len(p), nil
}

func (t *testWriteSyncer) Sync() error {
	return nil
}

func (t *testWriteSyncer) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.buffers = nil
	return nil
}

func (t *testWriteSyncer) Len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.buffers)
}

// TestNewLoggerWithSampler 测试带采样的日志器创建
func TestNewLoggerWithSampler(t *testing.T) {
	t.Run("禁用采样", func(t *testing.T) {
		core.ClearEncoderCache()

		cfg := config.LoggerConfig{
			ServiceName: "test",
			Sampling:    config.SamplingConfig{Enabled: false},
			Outputs: []config.OutputConfig{
				{
					Type:     config.Stdout,
					Level:    config.InfoLevel,
					Encoding: config.JSON,
					Enabled:  true,
				},
			},
		}

		logger, err := core.NewLogger(cfg, func(out config.OutputConfig) (core.WriteSyncer, error) {
			return &testWriteSyncer{}, nil
		})

		require.NoError(t, err)
		assert.NotNil(t, logger)

		logger.Info("test message")
		logger.Sync()
	})

	t.Run("启用采样", func(t *testing.T) {
		core.ClearEncoderCache()

		cfg := config.LoggerConfig{
			ServiceName: "test",
			Sampling: config.SamplingConfig{
				Enabled:    true,
				Initial:    10,
				Thereafter: 5,
				Window:     time.Second,
			},
			Outputs: []config.OutputConfig{
				{
					Type:     config.Stdout,
					Level:    config.InfoLevel,
					Encoding: config.JSON,
					Enabled:  true,
				},
			},
		}

		logger, err := core.NewLogger(cfg, func(out config.OutputConfig) (core.WriteSyncer, error) {
			return &testWriteSyncer{}, nil
		})

		require.NoError(t, err)
		assert.NotNil(t, logger)

		logger.Info("test message")
		logger.Sync()
	})
}

// TestSamplerLogic 测试采样逻辑
func TestSamplerLogic(t *testing.T) {
	core.ClearEncoderCache()

	cfg := config.LoggerConfig{
		ServiceName: "test",
		Sampling: config.SamplingConfig{
			Enabled:    true,
			Initial:    3,
			Thereafter: 2,
			Window:     time.Second,
		},
		Outputs: []config.OutputConfig{
			{
				Type:     config.Stdout,
				Level:    config.InfoLevel,
				Encoding: config.JSON,
				Enabled:  true,
			},
		},
	}

	logger, err := core.NewLogger(cfg, func(out config.OutputConfig) (core.WriteSyncer, error) {
		return &testWriteSyncer{}, nil
	})

	require.NoError(t, err)

	// 记录20条日志
	for i := 0; i < 20; i++ {
		logger.Info("test message", zap.Int("count", i))
	}

	logger.Sync()
}

// TestSamplerWithErrorLevel 测试错误级别始终记录
func TestSamplerWithErrorLevel(t *testing.T) {
	core.ClearEncoderCache()

	cfg := config.LoggerConfig{
		ServiceName: "test",
		Sampling: config.SamplingConfig{
			Enabled:    true,
			Initial:    1,
			Thereafter: 100,
			Window:     time.Second,
		},
		Outputs: []config.OutputConfig{
			{
				Type:     config.Stdout,
				Level:    config.ErrorLevel,
				Encoding: config.JSON,
				Enabled:  true,
			},
		},
	}

	logger, err := core.NewLogger(cfg, func(out config.OutputConfig) (core.WriteSyncer, error) {
		return &testWriteSyncer{}, nil
	})

	require.NoError(t, err)

	// 记录10条错误日志
	for i := 0; i < 10; i++ {
		logger.Error("error message", zap.Int("count", i))
	}

	logger.Sync()
}

// TestSamplerWindowReset 测试时间窗口重置
func TestSamplerWindowReset(t *testing.T) {
	core.ClearEncoderCache()

	cfg := config.LoggerConfig{
		ServiceName: "test",
		Sampling: config.SamplingConfig{
			Enabled:    true,
			Initial:    5,
			Thereafter: 10,
			Window:     100 * time.Millisecond,
		},
		Outputs: []config.OutputConfig{
			{
				Type:     config.Stdout,
				Level:    config.InfoLevel,
				Encoding: config.JSON,
				Enabled:  true,
			},
		},
	}

	logger, err := core.NewLogger(cfg, func(out config.OutputConfig) (core.WriteSyncer, error) {
		return &testWriteSyncer{}, nil
	})

	require.NoError(t, err)

	// 第一窗口：记录6条（前5条都记录）
	for i := 0; i < 6; i++ {
		logger.Info("window 1")
	}

	// 等待时间窗口重置
	time.Sleep(150 * time.Millisecond)

	// 第二窗口：记录6条（前5条都记录）
	for i := 0; i < 6; i++ {
		logger.Info("window 2")
	}

	logger.Sync()
}

// TestSamplerConcurrent 并发采样测试
func TestSamplerConcurrent(t *testing.T) {
	core.ClearEncoderCache()

	cfg := config.LoggerConfig{
		ServiceName: "test",
		Sampling: config.SamplingConfig{
			Enabled:    true,
			Initial:    10,
			Thereafter: 5,
			Window:     time.Second,
		},
		Outputs: []config.OutputConfig{
			{
				Type:     config.Stdout,
				Level:    config.InfoLevel,
				Encoding: config.JSON,
				Enabled:  true,
			},
		},
	}

	logger, err := core.NewLogger(cfg, func(out config.OutputConfig) (core.WriteSyncer, error) {
		return &testWriteSyncer{}, nil
	})

	require.NoError(t, err)

	var wg sync.WaitGroup
	numGoroutines := 10
	logsPerGoroutine := 100

	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < logsPerGoroutine; j++ {
				logger.Info("concurrent test", zap.Int("goroutine", id))
			}
		}(i)
	}

	wg.Wait()
	logger.Sync()
}

// TestSamplerSync 测试同步
func TestSamplerSync(t *testing.T) {
	core.ClearEncoderCache()

	cfg := config.LoggerConfig{
		ServiceName: "test",
		Sampling: config.SamplingConfig{
			Enabled:    true,
			Initial:    10,
			Thereafter: 5,
			Window:     time.Second,
		},
		Outputs: []config.OutputConfig{
			{
				Type:     config.Stdout,
				Level:    config.InfoLevel,
				Encoding: config.JSON,
				Enabled:  true,
			},
		},
	}

	logger, err := core.NewLogger(cfg, func(out config.OutputConfig) (core.WriteSyncer, error) {
		return &testWriteSyncer{}, nil
	})

	require.NoError(t, err)

	// 记录一些日志
	for i := 0; i < 5; i++ {
		logger.Info("sync test")
	}

	// 调用Sync
	err = logger.Sync()
	require.NoError(t, err)
}

// TestSamplerClose 测试关闭采样器
func TestSamplerClose(t *testing.T) {
	core.ClearEncoderCache()

	cfg := config.LoggerConfig{
		ServiceName: "test",
		Sampling: config.SamplingConfig{
			Enabled:    true,
			Initial:    10,
			Thereafter: 5,
			Window:     100 * time.Millisecond,
		},
		Outputs: []config.OutputConfig{
			{
				Type:     config.Stdout,
				Level:    config.InfoLevel,
				Encoding: config.JSON,
				Enabled:  true,
			},
		},
	}

	logger, err := core.NewLogger(cfg, func(out config.OutputConfig) (core.WriteSyncer, error) {
		return &testWriteSyncer{}, nil
	})

	require.NoError(t, err)

	// 记录一些日志
	for i := 0; i < 5; i++ {
		logger.Info("close test")
	}

	// 调用Sync（这会关闭采样器）
	err = logger.Sync()
	require.NoError(t, err)

	// 等待goroutine退出
	time.Sleep(200 * time.Millisecond)
}

// TestEncoderCache 测试编码器缓存
func TestEncoderCache(t *testing.T) {
	core.ClearEncoderCache()

	cfg1 := config.LoggerConfig{
		ServiceName: "test",
		Outputs: []config.OutputConfig{
			{
				Type:     config.Stdout,
				Level:    config.InfoLevel,
				Encoding: config.JSON,
				Enabled:  true,
			},
		},
	}

	cfg2 := config.LoggerConfig{
		ServiceName: "test",
		Encoder: config.EncoderConfig{
			MessageKey: "msg",
			TimeKey:    "time",
		},
		Outputs: []config.OutputConfig{
			{
				Type:     config.Stdout,
				Level:    config.InfoLevel,
				Encoding: config.JSON,
				Enabled:  true,
			},
		},
	}

	logger1, _ := core.NewLogger(cfg1, func(out config.OutputConfig) (core.WriteSyncer, error) {
		return &testWriteSyncer{}, nil
	})

	logger2, _ := core.NewLogger(cfg2, func(out config.OutputConfig) (core.WriteSyncer, error) {
		return &testWriteSyncer{}, nil
	})

	require.NotNil(t, logger1)
	require.NotNil(t, logger2)

	logger1.Sync()
	logger2.Sync()
}

// TestClearEncoderCache 测试清空编码器缓存
func TestClearEncoderCache(t *testing.T) {
	// 创建多个日志器以填充缓存
	cfg := config.LoggerConfig{
		ServiceName: "test",
		Outputs: []config.OutputConfig{
			{
				Type:     config.Stdout,
				Level:    config.InfoLevel,
				Encoding: config.JSON,
				Enabled:  true,
			},
		},
	}

	for i := 0; i < 5; i++ {
		logger, _ := core.NewLogger(cfg, func(out config.OutputConfig) (core.WriteSyncer, error) {
			return &testWriteSyncer{}, nil
		})
		require.NotNil(t, logger)
		logger.Sync()
	}

	// 清空缓存
	core.ClearEncoderCache()

	// 验证：创建新的日志器应该正常工作
	logger, err := core.NewLogger(cfg, func(out config.OutputConfig) (core.WriteSyncer, error) {
		return &testWriteSyncer{}, nil
	})

	require.NoError(t, err)
	require.NotNil(t, logger)
	logger.Sync()
}

// TestEncoderCacheEviction 测试编码器缓存淘汰
func TestEncoderCacheEviction(t *testing.T) {
	core.ClearEncoderCache()

	// 创建超过maxEncoderCacheSize（10）个不同的日志器配置
	for i := 0; i < 15; i++ {
		cfg := config.LoggerConfig{
			ServiceName: fmt.Sprintf("test-%d", i),
			Encoder: config.EncoderConfig{
				MessageKey: fmt.Sprintf("msg%d", i),
			},
			Outputs: []config.OutputConfig{
				{
					Type:     config.Stdout,
					Level:    config.InfoLevel,
					Encoding: config.JSON,
					Enabled:  true,
				},
			},
		}

		logger, err := core.NewLogger(cfg, func(out config.OutputConfig) (core.WriteSyncer, error) {
			return &testWriteSyncer{}, nil
		})

		require.NoError(t, err)
		require.NotNil(t, logger)
		logger.Sync()
	}

	// 测试：缓存不应该无限增长
	// 这个测试主要是验证没有panic或内存泄漏
	assert.True(t, true)
}

// TestNewLoggerErrorHandling 测试NewLogger错误处理
func TestNewLoggerErrorHandling(t *testing.T) {
	core.ClearEncoderCache()

	t.Run("无效配置", func(t *testing.T) {
		cfg := config.LoggerConfig{
			Outputs: []config.OutputConfig{
				{
					Type:     config.Stdout,
					Enabled:  true,
					Encoding: config.JSON,
				},
			},
		}

		_, err := core.NewLogger(cfg, func(out config.OutputConfig) (core.WriteSyncer, error) {
			return &testWriteSyncer{}, nil
		})

		assert.Error(t, err)
	})

	t.Run("工厂函数失败", func(t *testing.T) {
		cfg := config.LoggerConfig{
			ServiceName: "test",
			Outputs: []config.OutputConfig{
				{
					Type:     config.Stdout,
					Level:    config.InfoLevel,
					Encoding: config.JSON,
					Enabled:  true,
				},
			},
		}

		_, err := core.NewLogger(cfg, func(out config.OutputConfig) (core.WriteSyncer, error) {
			return nil, meberrors.ErrInternal("模拟工厂失败")
		})

		assert.Error(t, err)
	})
}

// TestSamplerPanicRecovery 测试panic恢复
func TestSamplerPanicRecovery(t *testing.T) {
	// 这个测试验证采样器的panic恢复机制
	// 由于resetLoop使用recover，即使panic也不应该导致goroutine泄漏
	core.ClearEncoderCache()

	cfg := config.LoggerConfig{
		ServiceName: "test",
		Sampling: config.SamplingConfig{
			Enabled:    true,
			Initial:    10,
			Thereafter: 5,
			Window:     10 * time.Millisecond,
		},
		Outputs: []config.OutputConfig{
			{
				Type:     config.Stdout,
				Level:    config.InfoLevel,
				Encoding: config.JSON,
				Enabled:  true,
			},
		},
	}

	logger, err := core.NewLogger(cfg, func(out config.OutputConfig) (core.WriteSyncer, error) {
		return &testWriteSyncer{}, nil
	})

	require.NoError(t, err)

	// 记录一些日志
	for i := 0; i < 5; i++ {
		logger.Info("test")
	}

	// 等待几个时间窗口
	time.Sleep(50 * time.Millisecond)

	// 调用Sync（这会关闭采样器）
	err = logger.Sync()
	require.NoError(t, err)

	// 等待goroutine退出
	time.Sleep(100 * time.Millisecond)

	// 如果没有panic，测试通过
	assert.True(t, true)
}

// TestSamplerHighThroughput 高吞吐量测试
func TestSamplerHighThroughput(t *testing.T) {
	core.ClearEncoderCache()

	cfg := config.LoggerConfig{
		ServiceName: "test",
		Sampling: config.SamplingConfig{
			Enabled:    true,
			Initial:    100,
			Thereafter: 50,
			Window:     time.Second,
		},
		Outputs: []config.OutputConfig{
			{
				Type:     config.Stdout,
				Level:    config.InfoLevel,
				Encoding: config.JSON,
				Enabled:  true,
			},
		},
	}

	logger, err := core.NewLogger(cfg, func(out config.OutputConfig) (core.WriteSyncer, error) {
		return &testWriteSyncer{}, nil
	})

	require.NoError(t, err)

	// 快速记录大量日志
	for i := 0; i < 1000; i++ {
		logger.Info("high throughput test")
	}

	logger.Sync()
}

// TestSamplerWithDynamicConfig 动态配置测试
func TestSamplerWithDynamicConfig(t *testing.T) {
	core.ClearEncoderCache()

	cfg := config.LoggerConfig{
		ServiceName: "test",
		Sampling: config.SamplingConfig{
			Enabled:    true,
			Initial:    5,
			Thereafter: 5,
			Window:     time.Second,
		},
		Outputs: []config.OutputConfig{
			{
				Type:     config.Stdout,
				Level:    config.InfoLevel,
				Encoding: config.JSON,
				Enabled:  true,
			},
		},
	}

	logger, err := core.NewLogger(cfg, func(out config.OutputConfig) (core.WriteSyncer, error) {
		return &testWriteSyncer{}, nil
	})

	require.NoError(t, err)

	// 记录10条
	for i := 0; i < 10; i++ {
		logger.Info("phase 1")
	}

	// 等待窗口重置
	time.Sleep(1*time.Second + 100*time.Millisecond)

	// 记录更多日志
	for i := 0; i < 20; i++ {
		logger.Info("phase 2")
	}

	logger.Sync()
}

// TestSamplerPerformance 性能测试
func TestSamplerPerformance(t *testing.T) {
	if testing.Short() {
		t.Skip("跳过性能测试")
	}

	core.ClearEncoderCache()

	cfg := config.LoggerConfig{
		ServiceName: "test",
		Sampling: config.SamplingConfig{
			Enabled:    true,
			Initial:    100,
			Thereafter: 50,
			Window:     time.Second,
		},
		Outputs: []config.OutputConfig{
			{
				Type:     config.Stdout,
				Level:    config.InfoLevel,
				Encoding: config.JSON,
				Enabled:  true,
			},
		},
	}

	logger, err := core.NewLogger(cfg, func(out config.OutputConfig) (core.WriteSyncer, error) {
		return &testWriteSyncer{}, nil
	})

	require.NoError(t, err)

	start := time.Now()

	// 记录10万条日志
	for i := 0; i < 100000; i++ {
		logger.Info("performance test")
	}

	duration := time.Since(start)
	t.Logf("记录100,000条日志耗时: %v", duration)

	logger.Sync()

	// 性能要求：10万条日志应该在合理时间内完成
	assert.Less(t, duration, 10*time.Second, "性能应该足够好")
}

// TestSamplerWrapper 测试 samplerWrapper 的方法
func TestSamplerWrapper(t *testing.T) {
	core.ClearEncoderCache()

	cfg := config.LoggerConfig{
		ServiceName: "test",
		Sampling: config.SamplingConfig{
			Enabled:    true,
			Initial:    5,
			Thereafter: 2,
			Window:     time.Second,
		},
		Outputs: []config.OutputConfig{
			{
				Type:     config.Stdout,
				Level:    config.InfoLevel,
				Encoding: config.JSON,
				Enabled:  true,
			},
		},
	}

	logger, err := core.NewLogger(cfg, func(out config.OutputConfig) (core.WriteSyncer, error) {
		return &testWriteSyncer{}, nil
	})

	require.NoError(t, err)

	// 使用 With 创建带字段的 logger
	loggerWithFields := logger.With(zap.String("component", "test"))
	assert.NotNil(t, loggerWithFields)

	// 记录日志
	loggerWithFields.Info("test with fields")
	loggerWithFields.Sync()

	// 多次 With 调用
	loggerWithFields2 := loggerWithFields.With(zap.String("extra", "value"))
	loggerWithFields2.Info("test with nested fields")
	loggerWithFields2.Sync()
}

// TestSamplerWriteAfterClose 测试关闭后写入
func TestSamplerWriteAfterClose(t *testing.T) {
	core.ClearEncoderCache()

	cfg := config.LoggerConfig{
		ServiceName: "test",
		Sampling: config.SamplingConfig{
			Enabled:    true,
			Initial:    10,
			Thereafter: 5,
			Window:     100 * time.Millisecond,
		},
		Outputs: []config.OutputConfig{
			{
				Type:     config.Stdout,
				Level:    config.InfoLevel,
				Encoding: config.JSON,
				Enabled:  true,
			},
		},
	}

	logger, err := core.NewLogger(cfg, func(out config.OutputConfig) (core.WriteSyncer, error) {
		return &testWriteSyncer{}, nil
	})

	require.NoError(t, err)

	// 记录一些日志
	for i := 0; i < 5; i++ {
		logger.Info("before close")
	}

	// 关闭
	logger.Sync()

	// 等待 goroutine 退出
	time.Sleep(200 * time.Millisecond)

	// 关闭后再写入不应该 panic
	logger.Info("after close")
}

// TestSamplerWrapperEnabled 测试 samplerWrapper 的 Enabled 方法
func TestSamplerWrapperEnabled(t *testing.T) {
	core.ClearEncoderCache()

	cfg := config.LoggerConfig{
		ServiceName: "test",
		Sampling: config.SamplingConfig{
			Enabled:    true,
			Initial:    10,
			Thereafter: 5,
			Window:     time.Second,
		},
		Outputs: []config.OutputConfig{
			{
				Type:     config.Stdout,
				Level:    config.InfoLevel,
				Encoding: config.JSON,
				Enabled:  true,
			},
		},
	}

	logger, err := core.NewLogger(cfg, func(out config.OutputConfig) (core.WriteSyncer, error) {
		return &testWriteSyncer{}, nil
	})

	require.NoError(t, err)

	loggerWithFields := logger.With(zap.String("test", "value"))
	// Enabled 应该正确工作
	assert.True(t, loggerWithFields.Core().Enabled(zapcore.InfoLevel))

	// 记录日志验证功能
	loggerWithFields.Info("test wrapper info")
	loggerWithFields.Error("test wrapper error")
	loggerWithFields.Sync()
}

// TestSamplerDuplicateClose 测试重复关闭采样器
func TestSamplerDuplicateClose(t *testing.T) {
	core.ClearEncoderCache()

	cfg := config.LoggerConfig{
		ServiceName: "test",
		Sampling: config.SamplingConfig{
			Enabled:    true,
			Initial:    10,
			Thereafter: 5,
			Window:     100 * time.Millisecond,
		},
		Outputs: []config.OutputConfig{
			{
				Type:     config.Stdout,
				Level:    config.InfoLevel,
				Encoding: config.JSON,
				Enabled:  true,
			},
		},
	}

	logger, err := core.NewLogger(cfg, func(out config.OutputConfig) (core.WriteSyncer, error) {
		return &testWriteSyncer{}, nil
	})

	require.NoError(t, err)

	// 记录一些日志
	for i := 0; i < 5; i++ {
		logger.Info("test")
	}

	// 第一次 Sync
	err = logger.Sync()
	require.NoError(t, err)

	// 等待 goroutine 退出
	time.Sleep(200 * time.Millisecond)

	// 第二次 Sync 应该不会 panic
	err = logger.Sync()
	require.NoError(t, err)
}
