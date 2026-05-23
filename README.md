# Mebsuta Go

> A production-grade structured logging library built on `log/slog`, with an **Audit level** and **compliance-ready JSON output** (GB/T 22239, GM/T 0054).
>
> 基于 `log/slog` 的结构化日志库，核心差异化：审计级别 (LevelAudit) + 合规输出格式 (GB/T 22239, GM/T 0054)。

## Why Mebsuta?

| | Mebsuta | slog (stdlib) | zap | zerolog |
|---|---|---|---|---|
| Audit level | ✅ `LevelAudit` + audit helpers | ❌ no audit level | ❌ no audit level | ❌ no audit level |
| Compliance output | ✅ GB/T 22239 / GM/T 0054 | ❌ | ❌ | ❌ |
| slog.Handler plugin | ✅ drop-in handler chain | ✅ (baseline) | ❌ separate API | ❌ separate API |
| Multi-output fanout | ✅ safe multi-handler with panic recovery | ❌ | ❌ | ❌ |
| Async + Sampling | ✅ built-in decorators | ❌ | ❌ | ❌ |
| File rotation | ✅ size + time, gzip, crash-safe | ❌ | ❌ (need lumberjack) | ❌ |
| Database output | ✅ batch write (MySQL/Postgres/SQLite) | ❌ | ❌ | ❌ |
| Syslog (TLS) | ✅ RFC5424 + TLS | ❌ | ❌ | ❌ |
| Prometheus metrics | ✅ per-handler counters/latency | ❌ | ❌ | ❌ |

For teams that need **compliance audit trails** (Chinese cybersecurity standard GB/T 22239, cryptographic evaluation GM/T 0054), Mebsuta is the only Go logging library with a dedicated Audit level and structured audit output built in.

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

`New()` 零配置即返回 JSON 格式输出到 stdout 的生产级 logger。

JSON 输出使用稳定契约：

```json
{"time":"2026-05-21T14:00:00Z","level":"INFO","message":"hello","attributes":{"key":"value"}}
```

审计日志使用 `AUDIT` 级别，并将审计元数据提升为顶层字段：

```go
mebsuta.AuditEvent(
    mebsuta.EventLogin,
    "user login",
    "actor", "user:42",
    "success", true,
    "ip", "127.0.0.1",
)
```

## 配置输出

```go
// 文件输出
logger, err := mebsuta.New(
    mebsuta.UseFile(mebsuta.FileConfig{Path: "/var/log/app.log"}),
)

// 全配置
logger, err := mebsuta.New(
    mebsuta.UseFile(mebsuta.FileConfig{
        Path: "/var/log/app.log",
        Level: slog.LevelDebug,
        MaxSizeMB: 200,
    }),
    mebsuta.UseAsync(mebsuta.AsyncConfig{BufferSize: 512}),
)
```

## Handler

| Handler | 构造函数 | 说明 |
| --- | --- | --- |
| StdoutHandler | `NewStdoutHandler(cfg StdoutConfig)` | 控制台输出 |
| FileHandler | `NewFileHandler(cfg FileConfig) (*FileHandler, error)` | 文件输出，自研轮转 |
| SyslogHandler | `syslog.NewHandler(cfg syslog.Config) (*syslog.Handler, error)` | Syslog 输出 |
| DatabaseHandler | `database.NewHandler(cfg database.Config) (*database.Handler, error)` | 数据库批量写入 |

## 装饰器

| Decorator | Constructor | Description |
| --- | --- | --- |
| SamplingHandler | `WithSampling(inner, cfg)` | 时间窗口采样 |
| AsyncHandler | `WithAsync(inner, cfg)` | 异步缓冲写入 |
| MetricsHandler | `WithMetrics(inner, m, name)` | 指标收集 |
| ContextExtractor | `WithContextExtractor(inner, fn)` | 上下文字段提取 |

## 文档

| 文档 | 描述 |
| --- | --- |
| [SPEC.md](SPEC.md) | 行为规范和兼容性契约 |
| [TLS Configuration](docs/TLS.md) | SyslogHandler TLS 安全配置指南 |
| [Benchmarks](docs/BENCHMARKS.md) | 性能基准测试和优化建议 |

## 示例

可运行示例位于 `examples/` 目录：

```bash
go run ./examples/basic    # 最简 stdout 输出
go run ./examples/file     # 文件输出 + 轮转
go run ./examples/sampling # 采样装饰器
go run ./examples/async    # 异步写入
go run ./examples/chain    # 完整生产配置链
```

## 测试

```bash
go test -race -count=1 ./...
go vet ./...
gofmt -s -l .
go run golang.org/x/vuln/cmd/govulncheck@latest ./...
```

也可以使用脚本：

```bash
./test.sh unit
./test.sh vet
./test.sh fmt
```

Docker 依赖服务配置位于 `docker-compose.yml`。

## 发布

发布标签使用 `vX.Y.Z`，详见 `VERSIONING.md`。
