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

## Handler

| Handler | 说明 |
|---------|------|
| `NewStdoutHandler(StdoutConfig)` | 控制台输出 |
| `NewFileHandler(filerotate.Config, FileConfig)` | 文件输出，自研轮转 |
| `syslog.NewHandler(syslog.Config)` | Syslog 输出 |
| `database.NewHandler(database.Config)` | 数据库批量写入 |

## 文档

- [TLS 配置](docs/TLS.md)
- [性能基准](docs/BENCHMARKS.md)
