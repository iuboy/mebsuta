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

### stdout 与 SIGPIPE

stdout handler 直接写 fd 1。当读取端提前退出时（例如 `myapp | grep xxx` 在
grep 命中后关闭管道），写入会收到 SIGPIPE——Go 对 fd 1/2 的默认行为是**不忽略
该信号，进程直接终止**。这在交互式 shell 里常被误判为程序崩溃。生产环境建议
使用 `UseFile`（文件输出），或确保管道消费端读完全部输出（如 `grep` 后接
`|| true` 的场景改用重定向到文件）。

### 异步缓冲

`AsyncConfig.BufferSize` 有上限 `mebsuta.MaxAsyncBufferSize`（10000，与
syslog/database 的积压上限对齐）：channel 在构造期一次性分配，超限值是构造期
OOM 面。`New(UseAsync(...))` 对超限配置返回 `*ConfigError`；直接调用
`WithAsync` 时上报错误并钳制到上限。

## 装饰器

| 装饰器 | 说明 |
|--------|------|
| `UseAsync(cfg)` | 异步缓冲写入。自动检测 syslog/database 的内置缓冲，避免双重缓冲 |
| `UseSampling(cfg)` | 时间窗口采样。Error 和 Audit 级别始终通过 |
| `UseMetrics(m, name)` | Prometheus 指标收集 |
| `UseContextExtractor(fn)` | 从 `context.Context` 提取字段 |

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
    Compress:       mebsuta.BoolPtr(true),
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
    BufferSize:   256, // 0 → 256，上限 MaxAsyncBufferSize (10000)
    ErrorTimeout: time.Second, // Error+ 记录满缓冲时的有界阻塞时长，0 → 1s
}
```

### syslog.Config

完整字段参见 [TLS 配置](docs/TLS.md)。

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

JSON 输出契约的顶层审计字段（`event_type`/`actor`/`success`）按级别区分信任锚：AUDIT 级记录的 record 级同名 attribute 会提升到顶层（preset 冲突时 preset 优先）；非 AUDIT 级记录仅 preset attributes 提升，record 级同键值留在 `attributes` 下——普通日志站点无法伪造审计字段。详见 [docs/SPEC.md](docs/SPEC.md)。

## 模块结构

单模块仓库，所有子包共享根 go.mod，按需导入即可。

| 模块 | 说明 |
|------|------|
| `mebsuta` | 核心日志库 |
| `mebsuta/audit` | 审计/合规功能 |
| `mebsuta/syslog` | Syslog 输出 |
| `mebsuta/database` | 数据库批量写入 |
| `mebsuta/metrics` | Prometheus 指标 |
| `mebsuta/filerotate` | 文件轮转 Writer |
| `mebsuta/attrutil` | Attribute 工具 |
| `mebsuta/mebsutatest` | 测试辅助 |

## 文档

- [行为规范](docs/SPEC.md)
- [贡献指南](docs/CONTRIBUTING.md)
- [测试策略](docs/TESTING.md)
- [版本策略](docs/VERSIONING.md)
- [迁移指南](docs/MIGRATION.md)
- [TLS 配置](docs/TLS.md)
- [性能基准](docs/BENCHMARKS.md)
- [更新日志](CHANGELOG.md)
