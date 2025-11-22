// Package Mebsuta 包是一个高性能、结构化日志库
// 专为具有多输出支持（文件、数据库、系统日志）的微服务而设计。
//
// 示例：
//
//	err := Mebsuta.Init(Mebsuta.LoggerConfig{
//	    ServiceName: "my-service",
//	    Outputs: []Mebsuta.OutputConfig{
//	        {Type: Mebsuta.Stdout, Level: Mebsuta.Info, Encoding: Mebsuta.JSON},
//	    },
//	})
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer Mebsuta.Sync()
//	Mebsuta.Info("Service started")
package mebsuta

import (
	"context"
	"mebsuta/config"
	"mebsuta/core"
	"mebsuta/internal/adapter"
	"sync"
	"sync/atomic"

	"go.uber.org/zap"
)

// LoggerConfig 是日志系统的主要配置结构
// 定义了服务名、输出目标、编码方式等核心参数
type LoggerConfig = config.LoggerConfig
type EncoderConfig = config.EncoderConfig
type SamplingConfig = config.SamplingConfig
type OutputConfig = config.OutputConfig
type FileConfig = config.FileConfig
type DatabaseConfig = config.DatabaseConfig
type SyslogConfig = config.SyslogConfig
type TimeSeriesConfig = config.TimeSeriesConfig

// === 常量也导出 ===
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

var (
	// 全局 logger 实例（并发安全）
	globalLogger atomic.Value // *zap.Logger
	// 可选的上下文字段提取器
	contextExtractor func(ctx context.Context) []zap.Field
	// 保护 contextExtractor 的并发读写
	extractorMu sync.RWMutex
)

// Init 初始化日志系统
func Init(cfg config.LoggerConfig) error {

	factory := func(out config.OutputConfig) (core.WriteSyncer, error) {
		return adapter.CreateSyncer(out)
	}

	logger, err := core.NewLogger(cfg, factory)
	if err != nil {
		return err
	}

	SetLogger(logger)
	return nil
}

func SetLogger(logger *zap.Logger) {
	globalLogger.Store(logger)
	zap.ReplaceGlobals(logger)
}

// Logger 获取日志器实例
func Logger() *zap.Logger {
	if logger := globalLogger.Load(); logger != nil {
		return logger.(*zap.Logger)
	}
	return fallbackLogger()
}

// ContextExtractor -------------------------------------------------
// 上下文支持（如 request_id）
// ------------------------------------------------------------------
// ContextExtractor 用于从 context 中提取日志字段
type ContextExtractor func(ctx context.Context) []zap.Field

// SetContextExtractor 设置上下文提取函数
//
//	示例：Mebsuta.SetContextExtractor(func(ctx context.Context) []zap.Field {
//	    if id := FromRequestID(ctx); id != "" {
//	        return []zap.Field{zap.String("request_id", id)}
//	    }
//	    return nil
//	})
func SetContextExtractor(extractor ContextExtractor) {
	extractorMu.Lock()
	defer extractorMu.Unlock()
	contextExtractor = extractor
}

// getExtractedFields 从当前上下文中提取字段
func getExtractedFields() []zap.Field {
	extractorMu.RLock()
	fn := contextExtractor
	extractorMu.RUnlock()
	if fn != nil {
		if ctx := extractContext(); ctx != nil {
			return fn(ctx)
		}
	}
	return nil
}

// 用于测试 mock 的 context
var globalCtx context.Context

// SetGlobalContext 为日志系统设置一个全局 context（测试用）
// 一般不需要调用
func SetGlobalContext(ctx context.Context) {
	globalCtx = ctx
}
func extractContext() context.Context {
	if globalCtx != nil {
		return globalCtx
	}
	// TODO: 可接入 OpenTelemetry 等 context 传播机制
	return nil
}

// WithContext 返回一个绑定了上下文字段的日志器
func WithContext(ctx context.Context) *zap.Logger {
	logger := Logger()

	var fields []zap.Field

	// 应用上下文提取器
	if extracted := getExtractedFields(); extracted != nil {
		fields = append(fields, extracted...)
	}

	const requestIDKey = "request_id" // 注意：这里可以是 string，与 test 一致
	if ctx != nil {
		if reqID, ok := ctx.Value(requestIDKey).(string); ok {
			fields = append(fields, zap.String("request_id", reqID))
		}
	}

	if len(fields) > 0 {
		logger = logger.With(fields...)
	}
	return logger
}

// ------------------------------------------------------------------
// 标准日志 API（Level-based）
// ------------------------------------------------------------------

func Debug(msg string, fields ...zap.Field) { Logger().Debug(msg, fields...) }
func Info(msg string, fields ...zap.Field)  { Logger().Info(msg, fields...) }
func Warn(msg string, fields ...zap.Field)  { Logger().Warn(msg, fields...) }
func Error(msg string, fields ...zap.Field) { Logger().Error(msg, fields...) }
func Fatal(msg string, fields ...zap.Field) { Logger().Fatal(msg, fields...) }
func Panic(msg string, fields ...zap.Field) { Logger().Panic(msg, fields...) }

// ------------------------------------------------------------------
// Sugared Logger API（格式化输出）
// ------------------------------------------------------------------

func Debugf(template string, args ...interface{}) { Logger().Sugar().Debugf(template, args...) }
func Infof(template string, args ...interface{})  { Logger().Sugar().Infof(template, args...) }
func Warnf(template string, args ...interface{})  { Logger().Sugar().Warnf(template, args...) }
func Errorf(template string, args ...interface{}) { Logger().Sugar().Errorf(template, args...) }
func Fatalf(template string, args ...interface{}) { Logger().Sugar().Fatalf(template, args...) }
func Panicf(template string, args ...interface{}) { Logger().Sugar().Panicf(template, args...) }

// ------------------------------------------------------------------
func String(key, val string) zap.Field { return zap.String(key, val) }
func ErrorField(err error) zap.Field   { return zap.Error(err) }

// Sugar 获取底层的 SugaredLogger
// 注意：频繁调用 Sugar() 会有性能损耗
func Sugar() *zap.SugaredLogger { return Logger().Sugar() }

// Sync ------------------------------------------------------------------
// 生命周期管理
// ------------------------------------------------------------------
// Sync 强制刷新所有日志输出缓冲
// 应在程序退出前调用
func Sync() error {
	if logger := globalLogger.Load(); logger != nil {
		return logger.(*zap.Logger).Sync()
	}
	return nil
}

// ------------------------------------------------------------------
// 内部：应急日志器（初始化失败时使用）
// ------------------------------------------------------------------

func fallbackLogger() *zap.Logger {
	cfg := zap.NewDevelopmentConfig()
	cfg.EncoderConfig.TimeKey = "ts"
	c, _ := cfg.Build()
	return c
}
