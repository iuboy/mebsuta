# Mebsuta Go

基于 `log/slog` 的结构化日志库。

## 安装

```bash
go get github.com/iuboy/mebsuta/go
```

## 快速开始

```go
logger, err := mebsuta.New(
    mebsuta.WithHandler(mebsuta.NewStdoutHandler(slog.LevelInfo, mebsuta.JSON)),
)
if err != nil {
    log.Fatal(err)
}
slog.SetDefault(logger)
defer mebsuta.CloseAll(logger.Handler())

slog.Info("hello", "key", "value")
```

JSON 输出使用跨语言稳定契约：

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

## Handler

| Handler | 构造函数 | 说明 |
| --- | --- | --- |
| StdoutHandler | `NewStdoutHandler(level, format)` | 控制台输出 |
| FileHandler | `NewFileHandler(cfg, level) (*FileHandler, error)` | 文件输出，自研轮转 |
| SyslogHandler | `NewSyslogHandler(cfg, level) (*SyslogHandler, error)` | Syslog 输出 |
| DatabaseHandler | `database.NewDatabaseHandler(cfg, level) (*database.DatabaseHandler, error)` | 数据库批量写入 |

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
| [TLS Configuration](docs/TLS.md) | SyslogHandler TLS 安全配置指南 |
| [Benchmarks](docs/BENCHMARKS.md) | 性能基准测试和优化建议 |
| [Godoc](https://pkg.go.dev/github.com/iuboy/mebsuta/go) | 完整 API 文档和示例 |

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

## 仓库规范

Go 实现遵循根目录 `SPEC.md` 的共享行为契约。新增或修改与 Rust 共享的行为时，请同步更新根目录 `TESTING.md` 的测试矩阵。

Go 发布标签使用 `go/vX.Y.Z`，详见根目录 `VERSIONING.md`。
