# Mebsuta

Go 结构化日志库，基于 `log/slog` Handler 插件架构。

## 特性

- **slog Handler 插件**：stdout、file、syslog、database 输出
- **装饰器链**：采样、异步写入、指标收集、上下文提取
- **文件轮转**：自研实现，时间 + 大小双策略，gzip 压缩
- **安全多输出**：MultiHandler 带 panic recovery
- **Prometheus 指标**：内置 HandlerMetrics 接口

## 安装

```bash
go get github.com/iuboy/mebsuta
```

## 快速开始

```go
package main

import (
    "log/slog"
    "github.com/iuboy/mebsuta"
)

func main() {
    logger, err := mebsuta.New(
        mebsuta.WithHandler(
            mebsuta.NewStdoutHandler(slog.LevelInfo, mebsuta.JSON),
        ),
    )
    if err != nil {
        log.Fatal(err)
    }
    slog.SetDefault(logger)
    defer mebsuta.CloseAll(logger.Handler())

    slog.Info("服务启动成功", "key", "value")
}
```

## 输出 Handler

### StdoutHandler

```go
h := mebsuta.NewStdoutHandler(slog.LevelInfo, mebsuta.JSON)
// 或
h := mebsuta.NewStdoutHandler(slog.LevelInfo, mebsuta.Console)
```

### FileHandler（自研轮转）

```go
import "github.com/iuboy/mebsuta/config"

h, err := mebsuta.NewFileHandler(config.FileConfig{
    Path:         "/var/log/app.log",
    MaxSizeMB:    100,
    MaxBackups:   5,
    MaxAgeDays:   30,
    Compress:     true,
    Format:       mebsuta.JSON,
})
```

### SyslogHandler

```go
h, err := mebsuta.NewSyslogHandler(config.SyslogConfig{
    Network:  "tcp",
    Address:  "localhost:514",
    Tag:      "my-app",
    RFC5424:  true,
})
```

### DatabaseHandler

```go
h, err := mebsuta.NewDatabaseHandler(config.DatabaseConfig{
    DriverName:     "mysql",
    DataSourceName: "user:pass@tcp(localhost:3306)/logs",
    TableName:      "logs",
    BatchSize:      100,
    BatchInterval:  5 * time.Second,
})
```

## 多输出

```go
logger, err := mebsuta.New(
    mebsuta.WithHandler(mebsuta.NewStdoutHandler(slog.LevelInfo, mebsuta.JSON)),
    mebsuta.WithHandler(mebsuta.NewFileHandler(fileConfig)),
    mebsuta.WithHandler(mebsuta.NewSyslogHandler(syslogConfig)),
)
```

多个 Handler 自动使用 `slog.NewMultiHandler`，每个子 Handler 独立 panic recovery。

## 装饰器

### 采样

```go
inner := mebsuta.NewStdoutHandler(slog.LevelInfo, mebsuta.JSON)
h := mebsuta.WithSampling(inner, config.SamplingConfig{
    Enabled:    true,
    Initial:    100,
    Thereafter: 10,
    Window:     time.Minute,
})
```

### 异步写入

```go
h := mebsuta.WithAsync(inner, mebsuta.AsyncConfig{
    BufferSize: 1024,
})
defer mebsuta.CloseAll(h)
```

### 指标收集

```go
h := mebsuta.WithMetrics(inner, myMetrics, "stdout")
```

### 上下文提取

```go
h := mebsuta.WithContextExtractor(inner, func(ctx context.Context) []slog.Attr {
    if id, ok := ctx.Value(myKey).(string); ok {
        return []slog.Attr{slog.String("request_id", id)}
    }
    return nil
})
```

装饰器可以自由组合：

```go
h := mebsuta.WithMetrics(
    mebsuta.WithSampling(inner, samplingCfg),
    myMetrics, "stdout",
)
```

## 监控指标

```go
import (
    mebmetrics "github.com/iuboy/mebsuta/metrics"
    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promhttp"
)

registry := prometheus.NewRegistry()
registry.MustRegister(mebmetrics.GetMetricsAsCollector())
http.Handle("/metrics", promhttp.HandlerFor(registry, prometheus.HandlerOpts{}))
```

### 可用指标

| 指标 | 类型 | 说明 |
|------|------|------|
| `mebsuta_log_writes_total` | Counter | 日志写入总数 |
| `mebsuta_log_dropped_total` | Counter | 日志丢弃总数 |
| `mebsuta_log_errors_total` | Counter | 日志错误总数 |
| `mebsuta_batch_writes_total` | Counter | 批量写入总数 |
| `mebsuta_batch_size` | Histogram | 批量写入大小 |
| `mebsuta_batch_latency_seconds` | Histogram | 批量写入延迟 |
| `mebsuta_buffer_usage` | Gauge | 缓冲区使用率 |
| `mebsuta_active_connections` | Gauge | 活跃连接数 |
| `mebsuta_idle_connections` | Gauge | 空闲连接数 |

## 测试

```bash
go test -race -count=1 ./...
go test -bench=. -benchmem .
```

## 许可证

MIT License
