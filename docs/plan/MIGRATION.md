# Migration Guide: v0.1 → v0.2

v0.2 从 zap 封装全面转向 `log/slog` Handler 插件架构。

## 核心变化

- `mebsuta.New()` 返回 `*slog.Logger`（不再是自定义 Logger 类型）
- 输出通过 `slog.Handler` 插件实现
- 装饰器（采样、异步、指标）通过函数包装 Handler
- 移除了 `go.uber.org/zap` 依赖

## API 对照

### 创建 Logger

```go
// v0.1
cfg := config.LoggerConfig{...}
mebsuta.Init(cfg)

// v0.2
logger, err := mebsuta.New(
    mebsuta.WithHandler(mebsuta.NewStdoutHandler(slog.LevelInfo, mebsuta.JSON)),
)
slog.SetDefault(logger)
defer mebsuta.CloseAll(logger.Handler())
```

### 日志输出

```go
// v0.1
logger.Info("消息", zap.String("key", "value"))
logger.Zl().Sugar().Infof("格式化 %s", arg)

// v0.2 — 使用标准 slog 接口
slog.Info("消息", "key", "value")
slog.Info(fmt.Sprintf("格式化 %s", arg))
```

### 上下文提取

```go
// v0.1
mebsuta.SetContextExtractor(func(ctx context.Context) []zap.Field {
    return []zap.Field{zap.String("request_id", id)}
})

// v0.2 — 装饰器
h := mebsuta.WithContextExtractor(inner, func(ctx context.Context) []slog.Attr {
    return []slog.Attr{slog.String("request_id", id)}
})
```

### 采样

```go
// v0.1
mebsuta.WithSampling(100, 10, time.Minute)

// v0.2 — 装饰器
mebsuta.WithSampling(inner, mebsuta.SamplingConfig{
    Enabled: true, Initial: 100, Thereafter: 10, Window: time.Minute,
})
```

### 异步写入

```go
// v0.1
aw := mebsuta.NewAsyncWriter(underlyingWriter, 1024, true)
mebsuta.WithWriter(aw, config.InfoLevel)

// v0.2 — 装饰器
h := mebsuta.WithAsync(inner, mebsuta.AsyncConfig{BufferSize: 1024})
defer h.(*mebsuta.AsyncHandler).Close()
```

## 已移除

| 旧 API | 替代 |
|--------|------|
| `mebsuta.Init(cfg)` | `mebsuta.New(opts...)` |
| `mebsuta.CreateLogger(cfg)` | `mebsuta.New(opts...)` |
| `mebsuta.NewFromConfig(cfg)` | `mebsuta.New(opts...)` |
| `mebsuta.GetLogger()` | `slog.Default()` |
| `mebsuta.SetLogger(zl)` | `slog.SetDefault(logger)` |
| `mebsuta.IsInitialized()` | 检查 `slog.Default()` |
| `mebsuta.SetContextExtractor(fn)` | `WithContextExtractor` 装饰器 |
| `logger.Zl()` | 直接使用 `*slog.Logger` |
| `logger.Sugar()` | 使用 `fmt.Sprintf` |
| `logger.Sync()` | `mebsuta.CloseAll(handler)` |
| `logger.WithContext(ctx)` | `slog.InfoContext(ctx, ...)` |
| `logger.With(fields...)` | `logger.WithAttrs(attrs...)` |
| `zap.String/Int/...` | `slog.String/Int/...` |

## 已移除的包

| 包 | 原因 |
|----|------|
| `core/` | 被 slog Handler 替代 |
| `internal/adapter/` | 被 slog Handler 替代 |
| `errors/` | 使用标准 `fmt.Errorf` |
| `examples/categraf/` | 配置方式已变更 |

## 已移除的依赖

| 依赖 | 原因 |
|------|------|
| `go.uber.org/zap` | 转向 slog |
| `github.com/natefinch/lumberjack` | 自研文件轮转 |

## 包结构

```
mebsuta/
├── mebsuta.go              # New(), CloseAll, LogEntry, 包级日志函数
├── handler.go              # buildHandler, safeMultiHandler, CloseAll
├── types.go                # EncodingType (JSON, Console)
├── stdout_handler.go       # StdoutHandler
├── file_handler.go         # FileHandler (自研轮转)
├── syslog_handler.go       # SyslogHandler
├── database_handler.go     # DatabaseHandler
├── sampling_handler.go     # SamplingHandler 装饰器
├── async_handler.go        # AsyncHandler 装饰器, AsyncConfig
├── metrics_handler.go      # MetricsHandler 装饰器, HandlerMetrics 接口
├── context_extractor.go    # ContextExtractor 装饰器
├── config/                 # FileConfig, SyslogConfig, DatabaseConfig, SamplingConfig
└── metrics/                # Prometheus 指标 (*Metrics 实现 HandlerMetrics)
```
