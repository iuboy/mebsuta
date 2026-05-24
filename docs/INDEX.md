# API 参考

## Handler

| Handler | 构造函数 | 说明 |
|---------|----------|------|
| StdoutHandler | `NewStdoutHandler(cfg StdoutConfig)` | 控制台输出 |
| FileHandler | `NewFileHandler(rotateCfg filerotate.Config, cfg FileConfig)` | 文件输出，自研轮转 |
| SyslogHandler | `syslog.NewHandler(cfg syslog.Config)` | Syslog 输出（独立模块） |
| DatabaseHandler | `database.NewHandler(cfg database.Config)` | 数据库批量写入（独立模块） |

## 装饰器

| 装饰器 | 构造函数 | 说明 |
|--------|----------|------|
| SamplingHandler | `WithSampling(inner, cfg)` | 时间窗口采样 |
| AsyncHandler | `WithAsync(inner, cfg)` | 异步缓冲写入 |
| MetricsHandler | `WithMetrics(inner, m, name)` | 指标收集 |
| ContextExtractor | `WithContextExtractor(inner, fn)` | 上下文字段提取 |

## 配置类型

### StdoutConfig / FileConfig

```go
StdoutConfig{
    Level:  slog.LevelInfo,  // 日志级别过滤
    Format: "json",          // "json" 或 "console"
}

FileConfig{
    Level:  slog.LevelInfo,
    Format: "json",
}
```

### filerotate.Config

```go
filerotate.Config{
    Path:           "/var/log/app.log",
    MaxSizeMB:      100,        // 0 → 100
    MaxBackups:     5,          // 0 → 5
    MaxAgeDays:     30,         // 0 → 30
    Compress:       BoolPtr(true),
    RotateInterval: 24 * time.Hour,
}
```

### SamplingConfig

```go
SamplingConfig{
    Enabled:    true,
    Initial:    100,   // 0 → 100
    Thereafter: 10,    // 0 → 10
    Window:     time.Second, // 0 → 1s
}
```

### AsyncConfig

```go
AsyncConfig{
    BufferSize: 256,  // 0 → 256
}
```

## 审计日志

审计功能位于独立模块 `mebsuta/audit`：

```go
import "github.com/iuboy/mebsuta/audit"

audit.AuditEvent(audit.EventLogin, "user login",
    "actor", "user:42",
    "success", true,
)
```

## 上下文提取

```go
h := mebsuta.WithContextExtractor(inner, func(ctx context.Context) []slog.Attr {
    if id, ok := ctx.Value(myKey).(string); ok {
        return []slog.Attr{slog.String("request_id", id)}
    }
    return nil
})
```

## 资源清理

```go
defer mebsuta.CloseAll(logger.Handler())
```

`CloseAll` 递归关闭所有实现 `io.Closer` 的 Handler。

## 模块结构

| 模块 | 独立 go.mod | 说明 |
|------|------------|------|
| `mebsuta` | 根模块 | 核心日志库 |
| `mebsuta/audit` | 是 | 审计/合规功能 |
| `mebsuta/syslog` | 是 | Syslog 输出 |
| `mebsuta/database` | 是 | 数据库批量写入 |
| `mebsuta/metrics` | 是 | Prometheus 指标 |
| `mebsuta/filerotate` | 否 | 文件轮转 Writer |
| `mebsuta/attrutil` | 否 | Attribute 工具 |
| `mebsuta/mebsutetest` | 否 | 测试辅助 |
