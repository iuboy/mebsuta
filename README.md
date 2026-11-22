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
    Compress:       mebsuta.Ptr(true),
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
mebsuta.WithErrorHandler(func(he *mebsuta.HandlerError) {
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
| `mebsuta` | 核心日志库（含 `StartSpan`/`Counter` 等遥测门面与 `TraceContextExtractor`） |
| `mebsuta/telemetry` | OTel 三信号（traces/metrics/logs）OTLP/HTTP 一键引导 |
| `mebsuta/otlp` | slog → OTel 日志管线桥接 handler |
| `mebsuta/audit` | 审计/合规功能 |
| `mebsuta/syslog` | Syslog 输出（**维护模式**：可用、有测试、不新增特性） |
| `mebsuta/database` | 数据库批量写入 |
| `mebsuta/metrics` | Prometheus 指标 |
| `mebsuta/filerotate` | 文件轮转 Writer |
| `mebsuta/prombridge` | Prometheus Registry → OTel 指标桥（存量 prometheus 服务零改造接入） |
| `mebsuta/internal/attrutil`、`mebsuta/internal/textutil`、`mebsuta/internal/handlerkit` | 内部实现缝（Attribute 展平、UTF-8 截断、handler 共享管线：ErrorSlot/RateGate/AttrsSub/图遍历辅助），非消费面 |
| `mebsuta/mebsutatest` | 测试辅助（含 OTLP 捕获接收器） |

## 遥测引导（telemetry）

`mebsuta/telemetry` 一次调用完成 OpenTelemetry 三信号（traces/metrics/logs）
的 OTLP/HTTP 引导：资源标识、头采样、批处理、W3C 传播与优雅关停，替代各
项目手写的 internal/telemetry 样板。Endpoint 留空即全 no-op，本地开发零负担。

```go
tel, err := telemetry.Start(ctx, telemetry.Config{
    ServiceName: "castor",
    Endpoint:    "http://mebsuta-forwarder:4318", // 留空 → no-op
})
if err != nil {
    return err
}
defer tel.Shutdown(context.Background())
```

依赖边界：`telemetry` 子包经官方 OTel SDK exporter 传递链入 grpc（仅编译
产物，运行时不激活）；根包、`mebsuta/otlp` 与 `mebsutatest` 保持
grpc-free（otlp handler 是纯 API 桥，mebsutatest 用 slim proto 解码）。
只使用日志能力的消费方（如 mebsuta-forwarder 的 loginit）不受影响。

## TLS / mTLS（telemetry）

OTLP/HTTP 端点的凭据面（镜像 mbta 四件套形态）：

```go
tel, _ := telemetry.Start(ctx, telemetry.Config{
    ServiceName: "wasat",
    Endpoint:    "https://collector.internal:4318", // 自签/私有 CA 部署形态
    TLSCAFile:   "/etc/wasat/ca.pem",               // 私有 CA；缺省走系统信任池
    TLSServerName: "collector.internal",            // 端点与证书 SAN 不一致时覆写
    // mTLS（接收侧启用客户端证书验证时）：
    // TLSCertFile: "client.pem", TLSKeyFile: "client.key",
})
```

规则：裸 `host:port` + 任一 TLS 字段 → 升级为 TLS（覆盖 LAN 明文默认）；
显式 `http://` + TLS 字段 → `Validate` 拒绝；`TLSCertFile`/`TLSKeyFile`
必须成对。SDK 导出错误经 `Config.OTelErrorHandler` 进入 mebsuta
ErrorHandler 链（`SetGlobal=false` 时不触碰 otel 全局，自行
`otel.SetErrorHandler`）。

## Prometheus 指标桥（prombridge）

存量 prometheus 指标服务零改造接入 OTLP 路径：

```go
bridge, _ := prombridge.Start(ctx, tel.MeterProvider(), promReg,
    prombridge.WithInterval(30*time.Second))
defer bridge.Close()
```

忠实映射 counter（按轮询差分）与 gauge（last-write-wins）；histogram/summary
**跳过**（OTel API 无法忠实表达预聚合 bucket 计数），`Bridge.Skipped()`
提供诚实健康面。

## 日志直发 OTLP（otlp handler）

`mebsuta/otlp` 把 slog 记录桥接进 OTel 日志管线，与本地输出
（stdout/file/database）通过 `WithHandler` 自由组合。日志-追踪关联是原生
的：logs SDK 从发射上下文自动填充 TraceID/SpanID，在 span 内打日志即关联。

```go
tel, _ := telemetry.Start(ctx, telemetry.Config{
    ServiceName: "castor",
    Endpoint:    "http://mebsuta-forwarder:4318",
})
defer tel.Shutdown(ctx)

logger, _ := mebsuta.New(
    mebsuta.WithHandler(otlp.NewHandler(tel.LoggerProvider(), otlp.Config{})),
    mebsuta.UseStdout(mebsuta.StdoutConfig{}),
)
slog.SetDefault(logger)
```

## 遥测门面（span/指标）

根包提供 zap/slog 风格的全局函数，经 otel 全局（`telemetry.Start` 默认
注册）工作；未注册时自动落回 no-op，测试与本地开发零负担：

```go
ctx, span := mebsuta.StartSpan(ctx, "handle_request")   // 返回完整 trace.Span
defer span.End()

mebsuta.Counter(ctx, "requests_total", 1, attribute.String("route", "/api"))
mebsuta.Histogram(ctx, "latency_ms", 12.3)
mebsuta.Gauge(ctx, "queue_depth", 7)

// 本地输出的 trace 关联（OTLP 路径无需提取器）：
//   mebsuta.UseContextExtractor(mebsuta.TraceContextExtractor())
```

## 遥测支持的依赖矩阵

| 信号 \ 后端 | OTLP/HTTP（第一支持） | database 落库 | MBTA | syslog 等旧协议 |
|------------|----------------------|---------------|------|----------------|
| 日志 | `otlp` handler（经 `telemetry.Start`） | `database.NewHandler`（含事务一致双写） | 现有 `mbta` | 现有 `syslog`（维护模式） |
| 追踪 | `telemetry` | `telemetry.Config.Database`（SpanExporter，方式 B） | 协议已具备（mbta-go `SignalRecord` 含 trace 字段），mebsuta 侧 exporter 待实现 | — |
| 遥测 | `telemetry` | `telemetry.Config.Database`（MetricExporter，限低基数） | 协议已具备（`metric_fields`/`temporality`/`exp_histogram`），mebsuta 侧 exporter 待实现 | — |

方式 A（OTel 直传）/方式 B（mebsuta 落库）在 `telemetry.Config` 一键切换；
两者并存即 traces/metrics 双写：

```go
tel, _ := telemetry.Start(ctx, telemetry.Config{
    ServiceName: "castor",
    Database: &telemetry.DatabaseConfig{Driver: "postgres", DSN: dsn}, // 方式 B
    Endpoint:    "http://mebsuta-forwarder:4318",                       // 方式 A（并存=双写）
})
defer tel.Shutdown(ctx)
```

## 热重载

运行时可调面（应用侧挂 SIGHUP/管理 API/配置中心推送即可，mebsuta 不做
信号处理）：

| 能力 | 方式 |
|------|------|
| **日志级别** | 构造期 `Config.Level` 传 `mebsuta.NewLevelVar(...)`（全部 handler 的 Level 均为 `slog.Leveler`，std 库原子热调）；运行时 `applied, skipped, err := mebsuta.SetLevel(logger, level)`——walk 遍历 handler 图（与 `SetFileMaxAge` 同款），固定级别 handler 进 `skipped` 诚实面 |
| 保留窗 | `mebsuta.SetFileMaxAge(logger, days)` |
| ErrorHandler | `atomic.Pointer` 带锁热换 |

不可热调（边界）：采样率（SDK sampler 构造期固定）、异步/批量参数
（in-flight 缓冲迁移风险大于收益）。telemetry 的 endpoint/采样迁移用
**代次轮换**模式：新 `telemetry.Start` → `SetGlobal` 覆盖（触发覆盖
告警）→ 旧 `Shutdown`。全局单例面地图见 [docs/GLOBALS.md](docs/GLOBALS.md)。

## 文档

- [行为规范](docs/SPEC.md)
- [贡献指南](docs/CONTRIBUTING.md)
- [测试策略](docs/TESTING.md)
- [版本策略](docs/VERSIONING.md)
- [迁移指南](docs/MIGRATION.md)
- [TLS 配置](docs/TLS.md)
- [性能基准](docs/BENCHMARKS.md)
- [更新日志](CHANGELOG.md)
