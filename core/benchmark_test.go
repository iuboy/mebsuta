package core

import (
	"context"
	"testing"
	"time"

	"github.com/iuboy/mebsuta/config"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// BenchmarkLogger_NoSampling 基准测试：无采样的日志记录
func BenchmarkLogger_NoSampling(b *testing.B) {
	core := NewNopCore()
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		ent := zapcore.Entry{
			Time:    time.Now(),
			Message: "benchmark log message",
			Level:   zapcore.InfoLevel,
		}
		_ = core.Write(ent, []zap.Field{
			zap.Int("iteration", i),
			zap.String("data", "sample data for benchmarking"),
		})
	}
}

// BenchmarkLogger_WithSampling 基准测试：带采样的日志记录
func BenchmarkLogger_WithSampling(b *testing.B) {
	samplingCfg := config.SamplingConfig{
		Enabled:    true,
		Initial:    100,
		Thereafter: 10,
		Window:     time.Second,
	}

	core := NewNopCore()
	sampler, err := newSampler(core, samplingCfg)
	require.NoError(b, err)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		ent := zapcore.Entry{
			Time:    time.Now(),
			Message: "benchmark log message",
			Level:   zapcore.InfoLevel,
		}
		_ = sampler.Write(ent, []zap.Field{
			zap.Int("iteration", i),
		})
	}
}

// BenchmarkLogger_WithFields 基准测试：带多个字段的日志记录
func BenchmarkLogger_WithFields(b *testing.B) {
	core := NewNopCore()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		ent := zapcore.Entry{
			Time:    time.Now(),
			Message: "benchmark with fields",
			Level:   zapcore.InfoLevel,
		}
		_ = core.Write(ent, []zap.Field{
			zap.String("string_field", "value"),
			zap.Int("int_field", 42),
			zap.Int64("int64_field", 9223372036854775807),
			zap.Float64("float_field", 3.14159),
			zap.Bool("bool_field", true),
			zap.Duration("duration_field", time.Second),
			zap.Time("time_field", time.Now()),
			zap.Any("any_field", map[string]string{"key": "value"}),
		})
	}
}

// BenchmarkLogger_With 基准测试：With方法性能
func BenchmarkLogger_With(b *testing.B) {
	core := NewNopCore()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		fields := []zap.Field{
			zap.String("field1", "value1"),
			zap.String("field2", "value2"),
			zap.String("field3", "value3"),
		}
		core = core.With(fields)

		ent := zapcore.Entry{
			Time:    time.Now(),
			Message: "benchmark with",
			Level:   zapcore.InfoLevel,
		}
		_ = core.Write(ent, []zap.Field{})
	}
}

// BenchmarkLogger_Check 基准测试：Check方法性能
func BenchmarkLogger_Check(b *testing.B) {
	core := NewNopCore()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		ent := zapcore.Entry{
			Time:    time.Now(),
			Message: "benchmark check",
			Level:   zapcore.InfoLevel,
		}
		ce := core.Check(ent, nil)
		_ = ce
	}
}

// BenchmarkLogger_Sync 基准测试：Sync方法性能
func BenchmarkLogger_Sync(b *testing.B) {
	core := NewNopCore()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = core.Sync()
	}
}

// BenchmarkEncoder_JSON 基准测试：JSON编码性能
func BenchmarkEncoder_JSON(b *testing.B) {
	encoderConfig := zapcore.EncoderConfig{
		MessageKey: "msg",
		LevelKey:   "level",
		TimeKey:    "time",
		EncodeTime: zapcore.ISO8601TimeEncoder,
	}
	encoder := zapcore.NewJSONEncoder(encoderConfig)

	ent := zapcore.Entry{
		Time:    time.Now(),
		Message: "benchmark json encoding",
		Level:   zapcore.InfoLevel,
	}
	fields := []zap.Field{
		zap.String("string_field", "value"),
		zap.Int("int_field", 42),
		zap.Float64("float_field", 3.14159),
		zap.Bool("bool_field", true),
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		buf, _ := encoder.EncodeEntry(ent, fields)
		buf.Free()
	}
}

// BenchmarkEncoder_Console 基准测试：Console编码性能
func BenchmarkEncoder_Console(b *testing.B) {
	encoderConfig := zapcore.EncoderConfig{
		MessageKey: "msg",
		LevelKey:   "level",
		TimeKey:    "time",
		EncodeTime: zapcore.ISO8601TimeEncoder,
	}
	encoder := zapcore.NewConsoleEncoder(encoderConfig)

	ent := zapcore.Entry{
		Time:    time.Now(),
		Message: "benchmark console encoding",
		Level:   zapcore.InfoLevel,
	}
	fields := []zap.Field{
		zap.String("string_field", "value"),
		zap.Int("int_field", 42),
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		buf, _ := encoder.EncodeEntry(ent, fields)
		buf.Free()
	}
}

// BenchmarkSampling_Throughput 基准测试：不同采样率下的吞吐量
func BenchmarkSampling_Throughput(b *testing.B) {
	scenarios := []struct {
		name       string
		initial    int
		thereafter int
	}{
		{"NoSampling", 1, 1},
		{"LightSampling", 100, 10},
		{"MediumSampling", 100, 100},
		{"HeavySampling", 10, 100},
	}

	for _, scenario := range scenarios {
		b.Run(scenario.name, func(b *testing.B) {
			samplingCfg := config.SamplingConfig{
				Enabled:    scenario.initial != 1 || scenario.thereafter != 1,
				Initial:    scenario.initial,
				Thereafter: scenario.thereafter,
				Window:     time.Second,
			}

			core := NewNopCore()
			sampler, err := newSampler(core, samplingCfg)
			require.NoError(b, err)

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				ent := zapcore.Entry{
					Time:    time.Now(),
					Message: "benchmark sampling",
					Level:   zapcore.InfoLevel,
				}
				_ = sampler.Write(ent, []zap.Field{})
			}
		})
	}
}

// BenchmarkConcurrentLogging 基准测试：并发日志记录性能
func BenchmarkConcurrentLogging(b *testing.B) {
	core := NewNopCore()

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			ent := zapcore.Entry{
				Time:    time.Now(),
				Message: "concurrent benchmark",
				Level:   zapcore.InfoLevel,
			}
			_ = core.Write(ent, []zap.Field{
				zap.Int("goroutine", i),
			})
			i++
		}
	})
}

// BenchmarkFieldCreation 基准测试：字段创建性能
func BenchmarkFieldCreation(b *testing.B) {
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = []zap.Field{
			zap.String("key", "value"),
			zap.Int("int", 42),
			zap.Int64("int64", 9223372036854775807),
			zap.Float64("float64", 3.14159),
			zap.Bool("bool", true),
		}
	}
}

// BenchmarkLogLevelCheck 基准测试：日志级别检查性能
func BenchmarkLogLevelCheck(b *testing.B) {
	core := NewNopCore()

	levels := []zapcore.Level{
		zapcore.DebugLevel,
		zapcore.InfoLevel,
		zapcore.WarnLevel,
		zapcore.ErrorLevel,
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		ent := zapcore.Entry{
			Time:    time.Now(),
			Message: "benchmark level check",
			Level:   levels[i%len(levels)],
		}
		_ = core.Enabled(ent.Level)
	}
}

// BenchmarkContextExtraction 基准测试：上下文提取性能
func BenchmarkContextExtraction(b *testing.B) {
	extractor := func(ctx context.Context) []zap.Field {
		var fields []zap.Field
		if requestID, ok := ctx.Value("request_id").(string); ok {
			fields = append(fields, zap.String("request_id", requestID))
		}
		if userID, ok := ctx.Value("user_id").(string); ok {
			fields = append(fields, zap.String("user_id", userID))
		}
		return fields
	}

	ctx := context.Background()
	ctx = context.WithValue(ctx, "request_id", "req-12345")
	ctx = context.WithValue(ctx, "user_id", "user-67890")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = extractor(ctx)
	}
}

// NewNopCore 创建一个用于基准测试的空Core
func NewNopCore() zapcore.Core {
	return zapcore.NewNopCore()
}
