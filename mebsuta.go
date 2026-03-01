// Package mebsuta 提供一个高性能、结构化的日志库
// 专为微服务设计，支持多输出（文件、数据库、系统日志）和监控指标
//
// 特性：
//   - 支持多种输出目标：控制台、文件、SQL数据库、InfluxDB、Syslog
//   - 高性能异步批量写入
//   - 内置Prometheus指标监控
//   - 动态日志采样，避免日志爆炸
//   - 完整的错误处理和错误链追踪
//   - 支持上下文感知日志
//
// 使用示例：
//
//	cfg := config.LoggerConfig{
//	    ServiceName: "my-service",
//	    DebugMode:   false,
//	    Outputs: []config.OutputConfig{
//	        {
//	            Type:     config.Stdout,
//	            Level:    config.InfoLevel,
//	            Encoding: config.JSON,
//	            Enabled:  true,
//	        },
//	    },
//	    Encoder: config.EncoderConfig{
//	        MessageKey: "msg",
//	        LevelKey:   "level",
//	        TimeKey:    "time",
//	    },
//	}
//
//	if err := mebsuta.Init(cfg); err != nil {
//	    log.Fatal(err)
//	}
//
//	mebsuta.Info("服务启动成功")
package mebsuta

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/iuboy/mebsuta/config"
	"github.com/iuboy/mebsuta/core"
	"github.com/iuboy/mebsuta/internal/adapter"
	mebmetrics "github.com/iuboy/mebsuta/metrics"
	"go.uber.org/zap"
)

// =============================================================================
// 类型别名和常量定义
// =============================================================================

type LoggerConfig = config.LoggerConfig
type EncoderConfig = config.EncoderConfig
type SamplingConfig = config.SamplingConfig
type OutputConfig = config.OutputConfig
type FileConfig = config.FileConfig
type DatabaseConfig = config.DatabaseConfig
type SyslogConfig = config.SyslogConfig
type TimeSeriesConfig = config.TimeSeriesConfig

type LogLevel = config.LogLevel
type OutputType = config.OutputType
type EncodingType = config.EncodingType

const (
	DebugLevel  = config.DebugLevel
	InfoLevel   = config.InfoLevel
	WarnLevel   = config.WarnLevel
	ErrorLevel  = config.ErrorLevel
	PanicLevel  = config.PanicLevel
	FatalLevel  = config.FatalLevel
	DPanicLevel = config.DPanicLevel

	JSON    = config.JSON
	Console = config.Console
	Stdout  = config.Stdout
	File    = config.File
	DB      = config.DB
	Syslog  = config.Syslog
)

// =============================================================================
// Context Key 类型定义（避免使用 string 作为 key）
// =============================================================================

// contextKey 是自定义的 context key 类型，防止 key 冲突
type contextKey string

// 预定义的 context key 常量
const (
	// RequestContextKey 用于存储请求ID
	RequestContextKey contextKey = "request_id"
	// UserContextKey 用于存储用户ID
	UserContextKey contextKey = "user_id"
	// TraceIDContextKey 用于存储追踪ID
	TraceIDContextKey contextKey = "trace_id"
	// CustomIDContextKey 用于存储自定义ID
	CustomIDContextKey contextKey = "custom_id"
)

// =============================================================================
// 全局变量和状态管理
// =============================================================================

var (
	// 初始化保护
	initOnce     sync.Once
	fallbackOnce sync.Once

	// 全局 logger 实例（并发安全）
	globalLogger atomic.Value // *zap.Logger

	// 初始化状态
	isInitialized atomic.Bool

	// 缓存的 fallback logger
	fallbackLogger atomic.Value // *zap.Logger

	// 上下文字段提取器
	contextExtractor atomic.Value // ContextExtractor

	// 全局上下文（用于测试）
	globalCtx atomic.Value // context.Context
)

// 初始化全局上下文为默认值，确保 atomic.Value 类型一致
func init() {
	globalCtx.Store(context.Background())
}

// =============================================================================
// 上下文提取器类型定义
// =============================================================================

// ContextExtractor 用于从 context 中提取日志字段
type ContextExtractor func(ctx context.Context) []zap.Field

// =============================================================================
// 初始化函数
// =============================================================================

// InitWithDetails 初始化日志系统，带详细错误信息
func InitWithDetails(cfg config.LoggerConfig) error {
	var initErr error
	initOnce.Do(func() {
		// 验证配置
		if err := cfg.Validate(); err != nil {
			initErr = fmt.Errorf("配置验证失败: %w", err)
			return
		}

		// 注册metrics
		if err := mebmetrics.Register(); err != nil {
			initErr = fmt.Errorf("监控指标初始化失败: %w", err)
			return
		}

		// 创建工厂函数
		factory := func(out config.OutputConfig) (core.WriteSyncer, error) {
			syncer, err := adapter.CreateSyncer(out)
			if err != nil {
				return nil, fmt.Errorf("创建同步器失败 (类型: %s): %w", out.Type, err)
			}
			return syncer, nil
		}

		// 创建日志器
		logger, err := core.NewLogger(cfg, factory)
		if err != nil {
			initErr = fmt.Errorf("创建日志器失败: %w", err)
			return
		}

		// 设置全局状态
		SetLogger(logger)
		isInitialized.Store(true)

		// 记录初始化成功（注意：这里使用新创建的 logger）
		logger.Info("Mebsuta初始化成功",
			zap.String("service", cfg.ServiceName),
			zap.Int("outputs", len(cfg.Outputs)))
	})

	return initErr
}

// Init 初始化日志系统（简化版本）
func Init(cfg config.LoggerConfig) error {
	return InitWithDetails(cfg)
}

// CreateLogger 创建独立的日志器实例（用于测试或多实例场景）
// 不影响全局日志器状态
func CreateLogger(cfg config.LoggerConfig) (*zap.Logger, error) {
	// 验证配置
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("配置验证失败: %w", err)
	}

	// 创建工厂函数
	factory := func(out config.OutputConfig) (core.WriteSyncer, error) {
		syncer, err := adapter.CreateSyncer(out)
		if err != nil {
			return nil, fmt.Errorf("创建同步器失败 (类型: %s): %w", out.Type, err)
		}
		return syncer, nil
	}

	// 创建日志器
	logger, err := core.NewLogger(cfg, factory)
	if err != nil {
		return nil, fmt.Errorf("创建日志器失败: %w", err)
	}

	return logger, nil
}

// SetLogger 设置全局日志器
func SetLogger(logger *zap.Logger) error {
	if logger == nil {
		return fmt.Errorf("日志器不能为空")
	}

	globalLogger.Store(logger)
	zap.ReplaceGlobals(logger)
	return nil
}

// =============================================================================
// 全局日志器获取
// =============================================================================

// GetLogger 获取全局日志器实例
func GetLogger() *zap.Logger {
	if logger := getGlobalLogger(); logger != nil {
		return logger
	}
	return getFallbackLogger()
}

func getGlobalLogger() *zap.Logger {
	if val := globalLogger.Load(); val != nil {
		if l, ok := val.(*zap.Logger); ok {
			return l
		}
	}
	return nil
}

func getFallbackLogger() *zap.Logger {
	fallbackOnce.Do(func() {
		cfg := zap.NewDevelopmentConfig()
		l, err := cfg.Build()
		if err != nil {
			// 如果连 fallback 都失败，使用 noop logger 避免崩溃
			fmt.Fprintf(os.Stderr, "无法创建fallback logger: %v，使用noop logger\n", err)
			l = zap.NewNop()
		}
		fallbackLogger.Store(l)
	})
	if val := fallbackLogger.Load(); val != nil {
		if l, ok := val.(*zap.Logger); ok {
			return l
		}
	}
	return zap.NewNop() // 兜底
}

func SetContextExtractor(extractor ContextExtractor) error {
	if extractor == nil {
		return fmt.Errorf("上下文提取器不能为空")
	}
	contextExtractor.Store(extractor) // atomic.Value 本身就是并发安全的
	return nil
}

// GetExtractedFields 从上下文中提取字段
func GetExtractedFields(ctx context.Context) []zap.Field {
	if ctx == nil {
		// 只在 ctx 为 nil 时尝试 globalCtx
		if gctx := globalCtx.Load(); gctx != nil {
			if c, ok := gctx.(context.Context); ok {
				ctx = c
			}
		}
	}

	if ctx == nil {
		return nil
	}

	// 优先使用自定义提取器
	if extractor := contextExtractor.Load(); extractor != nil {
		if fn, ok := extractor.(ContextExtractor); ok {
			return safeCallExtractor(fn, ctx)
		}
	}

	// 默认行为
	if id, ok := ctx.Value("request_id").(string); ok && id != "" {
		return []zap.Field{zap.String("request_id", id)}
	}
	return nil
}

func safeCallExtractor(extractor ContextExtractor, ctx context.Context) []zap.Field {
	defer func() {
		if r := recover(); r != nil {
			stack := make([]byte, 4096)
			n := runtime.Stack(stack, false)
			// 尝试使用全局 logger 记录
			if logger := getGlobalLogger(); logger != nil {
				logger.Error("上下文提取器发生panic",
					zap.Any("panic", r),
					zap.ByteString("stack", stack[:n]))
			} else {
				// 最后的备用方案
				fmt.Fprintf(os.Stderr, "上下文提取器panic: %v\n堆栈: %s\n", r, stack[:n])
			}
		}
	}()

	return extractor(ctx)
}

// SetGlobalContext 设置全局上下文（测试用）
func SetGlobalContext(ctx context.Context) {
	if ctx == nil {
		// 不存储 nil，保持原值不变
		// atomic.Value 第一次存储的类型必须与后续存储的类型完全一致
		return
	}
	globalCtx.Store(ctx)
}

// =============================================================================
// 状态检查和生命周期
// =============================================================================

// IsInitialized 检查是否已初始化
func IsInitialized() bool {
	return isInitialized.Load()
}

// Sync 强制刷新所有日志输出缓冲
func Sync() error {
	logger := getGlobalLogger()
	if logger == nil {
		return nil
	}
	return logger.Sync()
}

// =============================================================================
// 上下文支持
// =============================================================================

// WithContext 返回带有上下文字段的日志器
func WithContext(ctx context.Context) *zap.Logger {
	logger := GetLogger()
	if logger == nil {
		return logger
	}

	fields := GetExtractedFields(ctx)
	if len(fields) == 0 {
		return logger
	}

	return logger.With(fields...)
}

// =============================================================================
// 标准日志 API（Level-based）
// =============================================================================

// Debug 记录调试级别日志
func Debug(msg string, fields ...zap.Field) { GetLogger().Debug(msg, fields...) }

// Info 记录信息级别日志
func Info(msg string, fields ...zap.Field) { GetLogger().Info(msg, fields...) }

// Warn 记录警告级别日志
func Warn(msg string, fields ...zap.Field) { GetLogger().Warn(msg, fields...) }

// Error 记录错误级别日志
func Error(msg string, fields ...zap.Field) { GetLogger().Error(msg, fields...) }

// Fatal 记录致命级别日志并退出
func Fatal(msg string, fields ...zap.Field) { GetLogger().Fatal(msg, fields...) }

// Panic 记录恐慌级别日志并 panic
func Panic(msg string, fields ...zap.Field) { GetLogger().Panic(msg, fields...) }

// DPanic 记录开发环境恐慌级别日志
// 在 DebugMode 为 true 时会 panic，否则作为 error 处理
// Zap 已内置此行为：开发环境 panic，生产环境降级为 error
func DPanic(msg string, fields ...zap.Field) { GetLogger().DPanic(msg, fields...) }

// =============================================================================
// 格式化日志 API
// =============================================================================

// Debugf 格式化调试日志
func Debugf(template string, args ...interface{}) { GetLogger().Sugar().Debugf(template, args...) }

// Infof 格式化信息日志
func Infof(template string, args ...interface{}) { GetLogger().Sugar().Infof(template, args...) }

// Warnf 格式化警告日志
func Warnf(template string, args ...interface{}) { GetLogger().Sugar().Warnf(template, args...) }

// Errorf 格式化错误日志
func Errorf(template string, args ...interface{}) { GetLogger().Sugar().Errorf(template, args...) }

// Fatalf 格式化致命日志
func Fatalf(template string, args ...interface{}) { GetLogger().Sugar().Fatalf(template, args...) }

// Panicf 格式化恐慌日志
func Panicf(template string, args ...interface{}) { GetLogger().Sugar().Panicf(template, args...) }

// DPanicf 格式化开发环境恐慌日志
func DPanicf(template string, args ...interface{}) {
	GetLogger().Sugar().DPanicf(template, args...)
}

// =============================================================================
// 辅助函数
// =============================================================================

// String 创建字符串字段
func String(key, val string) zap.Field { return zap.String(key, val) }

// StackField 创建调用栈字段（用于调试）
// 跳过当前函数和调用者，返回实际调用位置
func StackField(skip int) zap.Field {
	pc, _, _, ok := runtime.Caller(skip + 1) // +1 跳过 StackField 本身
	if !ok {
		return zap.String("caller", "未知")
	}
	fn := runtime.FuncForPC(pc)
	if fn == nil {
		return zap.String("caller", "未知")
	}
	return zap.String("caller", fn.Name())
}

// FullStackField 创建完整调用堆栈字段
func FullStackField(skip int) zap.Field {
	stack := make([]byte, 4096)
	n := runtime.Stack(stack, false)
	return zap.ByteString("stack", stack[:n])
}

// Int 创建整数字段
func Int(key string, val int) zap.Field { return zap.Int(key, val) }

// Bool 创建布尔字段
func Bool(key string, val bool) zap.Field { return zap.Bool(key, val) }

// Float64 创建浮点数字段
func Float64(key string, val float64) zap.Field { return zap.Float64(key, val) }

// ErrorField 创建错误字段
func ErrorField(err error) zap.Field { return zap.Error(err) }

// Any 创建任意类型字段
func Any(key string, val interface{}) zap.Field { return zap.Any(key, val) }

// Int64 创建 int64 字段
func Int64(key string, val int64) zap.Field { return zap.Int64(key, val) }

// Uint 创建 uint 字段
func Uint(key string, val uint) zap.Field { return zap.Uint(key, val) }

// Uint64 创建 uint64 字段
func Uint64(key string, val uint64) zap.Field { return zap.Uint64(key, val) }

// Duration 创建 Duration 字段
func Duration(key string, val time.Duration) zap.Field { return zap.Duration(key, val) }

// Time 创建 Time 字段
func Time(key string, val time.Time) zap.Field { return zap.Time(key, val) }

// Bytes 创建字节数组字段
func Bytes(key string, val []byte) zap.Field { return zap.Binary(key, val) }

// Sugar 获取底层的 SugaredLogger
func Sugar() *zap.SugaredLogger { return GetLogger().Sugar() }

// =============================================================================
// 错误处理函数
// =============================================================================

// OnError 处理错误（带调用栈）
func OnError(err error) {
	if err != nil {
		dlog := GetLogger()
		dlog.Error("操作失败", zap.Error(err), StackField(1))
		dlog.Debug("系统因错误即将终止", zap.Error(err), FullStackField(1))
	}
}

// OnInitError 初始化错误处理
func OnInitError(err error, msg string) {
	if err != nil {
		// 使用 fmt 直接输出，避免依赖日志系统
		fmt.Printf("错误: %s: %v\n", msg, err)
	}
}

// =============================================================================
// 高级功能函数
// =============================================================================

// Try 错误处理包装器
func Try(ctx context.Context, operation func() error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			stack := make([]byte, 4096)
			n := runtime.Stack(stack, false)
			// 处理 panic(nil) 的情况
			if r == nil {
				err = fmt.Errorf("操作过程中发生panic: nil\n堆栈: %s", stack[:n])
			} else {
				err = fmt.Errorf("操作过程中发生panic: %v\n堆栈: %s", r, stack[:n])
			}
			GetLogger().Error("操作发生panic",
				zap.Any("panic", r),
				zap.String("stack", string(stack[:n])))
		}
	}()
	return operation()
}

// RetryWithBackoff 条件重试机制
func RetryWithBackoff(ctx context.Context, maxAttempts int, delay time.Duration, operation func() error) error {
	// Validate parameters
	if maxAttempts < 1 {
		return fmt.Errorf("无效的尝试次数: %d，必须至少为1", maxAttempts)
	}

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		err := Try(ctx, operation)
		if err == nil {
			return nil
		}

		if attempt == maxAttempts {
			return fmt.Errorf("操作在%d次尝试后失败: %w", maxAttempts, err)
		}

		// 检查 context 是否取消
		select {
		case <-ctx.Done():
			return fmt.Errorf("重试已取消: %w", ctx.Err())
		case <-time.After(delay * time.Duration(attempt)):
			// 继续下一次重试
		}
	}
	return nil
}
