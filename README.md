# Mebsuta

基于 `log/slog` 的结构化日志库。

## 安装

```bash
go get github.com/iuboy/mebsuta
```

## 快速开始

```go
logger, err := mebsuta.New()
if err != nil {
    log.Fatal(err)
}
slog.SetDefault(logger)
defer mebsuta.CloseAll(logger.Handler())

slog.Info("hello", "key", "value")
```

JSON 输出契约：

```json
{"time":"2026-05-21T14:00:00Z","level":"INFO","message":"hello","attributes":{"key":"value"}}
```

## Handler 链组合

`New()` 接受可变参数，按声明顺序组装 handler 链。装饰器（`UseAsync`、`UseSampling`）声明越晚越靠外层：

```go
logger, _ := mebsuta.New(
    mebsuta.UseFile(
        filerotate.Config{Path: "/var/log/app.log"},
        mebsuta.FileConfig{Level: slog.LevelDebug},
    ),
    mebsuta.UseStdout(mebsuta.StdoutConfig{Format: "console"}),
    mebsuta.UseSampling(mebsuta.SamplingConfig{Enabled: true}),
    mebsuta.UseAsync(mebsuta.AsyncConfig{BufferSize: 512}),
)
```

## Handler

| Handler | 构造函数 | 说明 |
|---------|----------|------|
| `NewStdoutHandler(StdoutConfig)` | `UseStdout(cfg)` | 控制台输出 |
| `NewFileHandler(filerotate.Config, FileConfig)` | `UseFile(rotateCfg, cfg)` | 文件输出，自研轮转 |
| `syslog.NewHandler(syslog.Config)` | `WithHandler(h)` | Syslog 输出 |
| `database.NewHandler(database.Config)` | `WithHandler(h)` | 数据库批量写入 |

## 装饰器

| 装饰器 | 说明 |
|--------|------|
| `UseAsync(cfg)` | 异步缓冲写入。自动检测 syslog/database 的内置缓冲，避免双重缓冲 |
| `UseSampling(cfg)` | 时间窗口采样。Error 和 Audit 级别始终通过 |
| `UseMetrics(m, name)` | Prometheus 指标收集 |
| `UseContextExtractor(fn)` | 从 `context.Context` 提取字段 |

## 资源清理

```go
defer mebsuta.CloseAll(logger.Handler())
```

`CloseAll` 递归关闭所有实现了 `io.Closer` 的 handler（AsyncHandler、FileHandler、SyslogHandler、DatabaseHandler）。使用 `defer` 确保程序退出前缓冲区被刷盘。

## 错误处理

handler 内部错误（文件轮转失败、数据库写入失败等）通过 `ErrorHandler` 回调报告，不返回给调用方：

```go
mebsuta.WithErrorHandler(func(he mebsuta.HandlerError) {
    log.Printf("component=%s op=%s err=%v", he.Component, he.Operation, he.Err)
})
```

- `DefaultErrorHandler` — 写入 stderr
- `SilentErrorHandler()` — 丢弃所有内部错误

## 审计日志

```go
import "github.com/iuboy/mebsuta/audit"

audit.AuditEvent(audit.EventLogin, "user login",
    "actor", "user:42",
    "success", true,
)
```

`LevelAudit` 高于 `LevelError`，所有配置为 Error 级别的 handler 都会接收审计记录。采样器始终放行审计记录。

## 配置

```go
// 文件输出
mebsuta.UseFile(
    filerotate.Config{Path: "/var/log/app.log"},
    mebsuta.FileConfig{Level: slog.LevelDebug},
)

// 多输出 + 采样 + 异步
mebsuta.UseStdout(mebsuta.StdoutConfig{})
mebsuta.UseSampling(mebsuta.SamplingConfig{Enabled: true, Initial: 100, Thereafter: 10})
mebsuta.UseAsync(mebsuta.AsyncConfig{BufferSize: 512})
```

## 文档

- [API 参考](docs/INDEX.md)
- [TLS 配置](docs/TLS.md)
- [性能基准](docs/BENCHMARKS.md)
- [更新日志](CHANGELOG.md)
