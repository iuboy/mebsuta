# Migration Guide: v0.1 → v0.2

v0.2 从 zap 封装全面转向 `log/slog` Handler 插件架构。

## v0.3.x → 项目独立

项目从双语言 monorepo 拆分为独立 Go 仓库。Rust 版本移至独立仓库 `mebsuta-rust`。

### Import Path 变更

```go
// before (monorepo)
import "github.com/iuboy/mebsuta/go"
import "github.com/iuboy/mebsuta/go/config"
import "github.com/iuboy/mebsuta/go/metrics"

// after (独立仓库)
import "github.com/iuboy/mebsuta"
import "github.com/iuboy/mebsuta/metrics"
```

### Install 命令变更

```bash
# before (monorepo)
go get github.com/iuboy/mebsuta/go@go/v0.4.0

# after (独立仓库)
go get github.com/iuboy/mebsuta@v0.4.0
```

### Tag Scheme 变更

| Period | Tag Format | Example |
|--------|------------|---------|
| Before monorepo split | `vX.Y.Z` (root) | `v0.3.4` |
| During monorepo | `go/vX.Y.Z` | `go/v0.4.0` |
| After independent repo | `vX.Y.Z` | `v0.4.0` |

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
    mebsuta.UseFile(mebsuta.FileConfig{Path: "/var/log/app.log"}),
)
mebsuta.Init()
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
    Initial: 100, Thereafter: 10, Window: time.Minute,
})
```

### 异步写入

```go
// v0.1
aw := mebsuta.NewAsyncWriter(underlyingWriter, 1024, true)
mebsuta.WithWriter(aw, config.InfoLevel)

// v0.2 — 装饰器
h := mebsuta.WithAsync(inner, mebsuta.AsyncConfig{BufferSize: 1024})
defer mebsuta.CloseAll(h)
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
| `config/` | Config 类型提升到主包 |

## 已移除的依赖

| 依赖 | 原因 |
|------|------|
| `go.uber.org/zap` | 转向 slog |
| `github.com/natefinch/lumberjack` | 自研文件轮转 |

## 包结构

```
mebsuta/
├── mebsuta.go              # New(), Init(), Option
├── handler.go              # CloseAll, handlerUnwrapper
├── config.go               # FileConfig, StdoutConfig, SyslogConfig, AsyncConfig, SamplingConfig
├── types.go                # EncodingType, EventType, LevelAudit, HandlerError
├── stdout_handler.go       # StdoutHandler
├── file_handler.go         # FileHandler (自研轮转)
├── syslog_handler.go       # SyslogHandler
├── sampling_handler.go     # WithSampling 装饰器
├── async_handler.go        # WithAsync 装饰器, AsyncConfig
├── metrics_handler.go      # WithMetrics 装饰器, HandlerMetrics 接口
├── context_extractor.go    # WithContextExtractor 装饰器
├── contract_handler.go     # 合规 JSON encoder (GB/T 22239, GM/T 0054)
├── database/               # DatabaseHandler (gorm 隔离)
└── metrics/                # Prometheus 指标
```
