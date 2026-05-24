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

`New()` 零配置即返回 JSON 格式输出到 stdout 的 logger。

JSON 输出使用稳定契约：

```json
{"time":"2026-05-21T14:00:00Z","level":"INFO","message":"hello","attributes":{"key":"value"}}
```

## 配置输出

```go
// 文件输出
logger, err := mebsuta.New(
    mebsuta.UseFile(
        filerotate.Config{Path: "/var/log/app.log"},
        mebsuta.FileConfig{Level: slog.LevelDebug},
    ),
)

// 多输出 + 采样 + 异步
logger, err := mebsuta.New(
    mebsuta.UseStdout(mebsuta.StdoutConfig{}),
    mebsuta.UseFile(
        filerotate.Config{Path: "/var/log/app.log", MaxSizeMB: 200},
        mebsuta.FileConfig{},
    ),
    mebsuta.UseSampling(mebsuta.SamplingConfig{
        Enabled: true, Initial: 100, Thereafter: 10,
    }),
    mebsuta.UseAsync(mebsuta.AsyncConfig{BufferSize: 512}),
)
```

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

## 审计日志

审计功能位于独立模块 `mebsuta/audit`：

```go
import "github.com/iuboy/mebsuta/audit"

audit.AuditEvent(audit.EventLogin, "user login",
    "actor", "user:42",
    "success", true,
    "ip", "127.0.0.1",
)
```

## 示例

```bash
go run ./examples/basic    # 最简 stdout 输出
go run ./examples/file     # 文件输出 + 轮转
go run ./examples/sampling # 采样装饰器
go run ./examples/async    # 异步写入
go run ./examples/chain    # 完整生产配置链
```

## 测试

```bash
./scripts/test.sh unit
./scripts/test.sh vet
./scripts/test.sh fmt
```

集成测试依赖服务：`scripts/docker-compose.yml`。

## 文档

| 文档 | 说明 |
|------|------|
| [TLS 配置](docs/TLS.md) | SyslogHandler TLS 安全配置 |
| [性能基准](docs/BENCHMARKS.md) | 性能基准测试 |
