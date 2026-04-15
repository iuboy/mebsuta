# Mebsuta 文档

基于 `log/slog` 的结构化日志库。

## API 概览

```go
// 创建 logger
logger, err := mebsuta.New(
    mebsuta.WithHandler(mebsuta.NewStdoutHandler(slog.LevelInfo, mebsuta.JSON)),
)
slog.SetDefault(logger)
defer mebsuta.CloseAll(logger.Handler())

// 使用 slog 标准接口
slog.Info("消息", "key", "value")
slog.WarnContext(ctx, "带上下文")
```

## Handler 列表

| Handler | 构造函数 | 说明 |
|---------|----------|------|
| StdoutHandler | `NewStdoutHandler(level, format)` | 控制台输出 |
| FileHandler | `NewFileHandler(cfg)` | 文件输出，自研轮转 |
| SyslogHandler | `NewSyslogHandler(cfg)` | Syslog 输出 |
| DatabaseHandler | `NewDatabaseHandler(cfg)` | 数据库批量写入 |

## 装饰器列表

| 装饰器 | 构造函数 | 说明 |
|--------|----------|------|
| SamplingHandler | `WithSampling(inner, cfg)` | 时间窗口采样 |
| AsyncHandler | `WithAsync(inner, cfg)` | 异步缓冲写入 |
| MetricsHandler | `WithMetrics(inner, m, name)` | 指标收集 |
| ContextExtractor | `WithContextExtractor(inner, fn)` | 上下文字段提取 |

## 配置

### FileConfig

```go
config.FileConfig{
    Path:          "/var/log/app.log",
    MaxSizeMB:     100,
    MaxBackups:    5,
    MaxAgeDays:    30,
    Compress:      true,
    Format:        mebsuta.JSON,       // JSON 或 Console
    RotateInterval: 24 * time.Hour,   // 可选，时间轮转
}
```

### SamplingConfig

```go
config.SamplingConfig{
    Enabled:    true,
    Initial:    100,   // 初始全部记录
    Thereafter: 10,    // 之后每 N 条记录 1 条
    Window:     time.Minute,
}
```

### AsyncConfig

```go
mebsuta.AsyncConfig{
    BufferSize: 1024,  // channel 容量
}
```

## 装饰器组合

装饰器可以任意嵌套，顺序不影响功能：

```go
// Stdout -> Sampling -> Metrics
h := mebsuta.WithMetrics(
    mebsuta.WithSampling(
        mebsuta.NewStdoutHandler(slog.LevelInfo, mebsuta.JSON),
        config.SamplingConfig{Enabled: true, Initial: 100, Thereafter: 10, Window: time.Minute},
    ),
    myMetrics, "stdout",
)
```

注意：AsyncHandler 不应套在 SyslogHandler 或 DatabaseHandler 上，它们内部已有异步机制。

## 上下文提取

```go
h := mebsuta.WithContextExtractor(inner, func(ctx context.Context) []slog.Attr {
    if id, ok := ctx.Value(myKey).(string); ok {
        return []slog.Attr{slog.String("request_id", id)}
    }
    return nil
})

// 使用时传入 context
slog.InfoContext(ctx, "处理请求")
```

## Prometheus 指标

```go
import (
    mebmetrics "github.com/iuboy/mebsuta/metrics"
    "github.com/prometheus/client_golang/prometheus"
)

registry := prometheus.NewRegistry()
registry.MustRegister(mebmetrics.GetMetricsAsCollector())
http.Handle("/metrics", promhttp.HandlerFor(registry, prometheus.HandlerOpts{}))
```

## 多输出 + panic recovery

多个 Handler 自动使用带 panic recovery 的 MultiHandler：

```go
logger, err := mebsuta.New(
    mebsuta.WithHandler(stdoutHandler),
    mebsuta.WithHandler(fileHandler),
    mebsuta.WithHandler(syslogHandler),
)
```

单个 Handler panic 不会影响其他 Handler。

## 资源清理

```go
defer mebsuta.CloseAll(logger.Handler())
```

`CloseAll` 递归关闭所有实现 `io.Closer` 的 Handler（FileHandler、AsyncHandler 等）。
