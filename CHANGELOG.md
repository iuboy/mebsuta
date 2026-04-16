# 更新日志

本项目的所有重要变更都将记录在此文件中。

格式基于 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.0.0/)，
并遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [0.3.0] - 2026-04-16

### 新增

- `mebsuta.ErrorHandler` 类型 — Handler 内部错误处理函数，可自定义输出目标
- `mebsuta.WithErrorHandler(fn ErrorHandler) HandlerOption` — 注入自定义错误处理
- `mebsuta.DefaultErrorHandler` — 默认错误处理（写入 os.Stderr）
- `errorHandlerSetter` 内部接口 — 自动传播 ErrorHandler 到所有子 handler
- `database/` 子包隔离 — DatabaseHandler 独立子包，消除循环引用
- `database.SetErrorHandler(fn)` — 供用户手动设置 database handler 的错误处理

## [0.3.1] - 2026-04-16

### 修复

- 修复 `reportError` 未统一使用导致 `WithErrorHandler(nil)` 时 panic（5 处）
- 修复 `compressFile` 未 nil 检查 errorHandler 导致异步压缩 panic
- 修复 `syslog_handler.go` RFC5424 格式缺失 MSGID 字段
- 修复 `syslog_handler.go` 指数退避 retryCount 无上限导致 int64 溢出 panic
- 修复 `database_handler.go` flush 重试 context 共享导致重试机制失效
- 修复 `metrics/metrics.go` Register 使用 MustRegister 导致无法捕获重复注册
- 修复 `WithAttrs().WithGroup()` 链式调用时已累积属性被静默丢弃（Syslog/Async/Database）

### 改进

- `safeMultiHandler` panic recovery 在 nil errorHandler 时回退到 DefaultErrorHandler
- `propagateErrorHandler` 递归解包装饰器链，自动注入到所有支持的 handler
- `config/sanitizer.go` 移除死代码 `reflect` 依赖
- `config/types.go` 移除无用的 `validate:"..."` struct tags
- 测试文件 for 循环现代化为 Go 1.26 range 语法

## [0.2.0] - 2026-04-15

### 破坏性变更

- 全面从 `go.uber.org/zap` 迁移到 `log/slog` Handler 插件架构
- `mebsuta.New()` 返回 `*slog.Logger`，不再返回自定义 Logger 类型
- `mebsuta.Init(cfg)` / `mebsuta.InitWithDetails(cfg)` / `mebsuta.CreateLogger(cfg)` / `mebsuta.NewFromConfig(cfg)` 移除
- `mebsuta.GetLogger()` / `mebsuta.SetLogger()` / `mebsuta.IsInitialized()` 全局状态函数移除
- `logger.Zl()` / `logger.Sugar()` / `logger.Sync()` / `logger.With()` / `logger.WithContext()` 移除
- `mebsuta.SetContextExtractor(fn)` 移除，改为 `WithContextExtractor` 装饰器
- `mebsuta.OnError` / `mebsuta.OnInitError` / `mebsuta.Try` / `mebsuta.RetryWithBackoff` / `mebsuta.SetGlobalContext` 移除
- `core/` / `internal/adapter/` / `errors/` / `examples/` / `integration/` 包移除
- `config.LoggerConfig` / `config.InitConfig` / `config.Builder` 移除
- `mebsuta.EncodingType` 从 config 包移到根包，`config.FileConfig.Format` 改为 `string` 类型
- `config.SamplingConfig` / `config.SyslogConfig` / `config.DatabaseConfig` / `config.FileConfig` 保留在 `config` 包
- `mebsuta.AsyncConfig.DropOnFull` 字段移除（始终丢弃）

### 新增

- `mebsuta.New(opts ...HandlerOption) (*slog.Logger, error)` — 基于 functional options 创建 logger
- `mebsuta.WithHandler(h slog.Handler) HandlerOption` — 添加输出 handler
- `mebsuta.CloseAll(handler slog.Handler) error` — 递归关闭所有 io.Closer（支持装饰器链解包）
- `mebsuta.NewStdoutHandler(level slog.Level, format EncodingType) *StdoutHandler` — stdout 输出
- `mebsuta.NewFileHandler(cfg config.FileConfig, level slog.Level) (*FileHandler, error)` — 文件输出，内置轮转
- `mebsuta.NewSyslogHandler(cfg config.SyslogConfig, level slog.Level) (*SyslogHandler, error)` — syslog 输出
- `mebsuta.NewDatabaseHandler(cfg config.DatabaseConfig, level slog.Level) (*DatabaseHandler, error)` — 数据库批量写入
- `mebsuta.WithSampling(inner slog.Handler, cfg config.SamplingConfig) slog.Handler` — 时间窗口采样装饰器
- `mebsuta.WithAsync(inner slog.Handler, cfg AsyncConfig) slog.Handler` — 异步写入装饰器
- `mebsuta.WithMetrics(inner slog.Handler, m HandlerMetrics, name string) slog.Handler` — 指标收集装饰器
- `mebsuta.WithContextExtractor(inner slog.Handler, extract ContextExtractor) slog.Handler` — 上下文字段提取装饰器
- `mebsuta.HandlerMetrics` 接口 — 指标收集抽象
- `mebsuta.AsyncConfig` — 异步写入配置（BufferSize）
- `mebsuta.AsyncDropped(h slog.Handler) int64` — 查询异步丢弃数量
- `mebsuta.LogEntry` / `mebsuta.RecordToLogEntry(r slog.Record) LogEntry` — 通用日志条目
- 文件轮转：时间 + 大小双策略，gzip 压缩，原子 rename，崩溃恢复
- `safeMultiHandler` 包装 `slog.NewMultiHandler`，per-handler panic recovery
- `levelHandler` 嵌入提供通用 Enabled 级别过滤
- `config.DefaultSyslogNetwork` / `config.DefaultSyslogTag` 常量

### 改进

- `safeMultiHandler.WithAttrs` / `WithGroup` 正确传播到所有子 handler
- `safeMultiHandler.Close()` 递归关闭所有子 handler
- `CloseAll` 通过 `handlerUnwrapper` 接口递归解包装饰器链
- `*metrics.Metrics` 实现 `HandlerMetrics` 接口（ObserveHandle/IncError/IncDropped）
- FileHandler.doRotate 在 os.Create 失败后设置 closed 状态，避免静默日志丢失
- safeMultiHandler 单 handler 时串行调用，避免不必要的 goroutine 开销
- config 包作为配置类型的唯一位置，移除根包中的重复定义
- `errors.Join` 替代自定义 `joinErrors`
- 移除未使用的 contextKey 常量和 DropOnFull 死代码

### 移除

- `go.uber.org/zap` / `go.uber.org/zapcore` 依赖
- `github.com/natefinch/lumberjack` 依赖
- `core/` / `internal/adapter/` / `errors/` / `examples/` / `integration/` 包
- `config.LoggerConfig` / `config.InitConfig` / `config.Builder`
- `AsyncConfig.DropOnFull` 字段和 `DropOnFull()` 函数
- `contextKey` 类型和 RequestContextKey/UserContextKey/TraceIDContextKey/CustomIDContextKey 常量

## [0.1.0] - 2024-12-XX

### 新增

- 支持多种输出目标：控制台、文件、SQL 数据库、InfluxDB、Syslog
- 高性能异步批量写入
- 内置 Prometheus 指标监控
- 动态日志采样功能
- 结构化日志支持
- 上下文感知日志
- JSON 和 Console 两种编码格式
- 日志轮转和压缩
- 连接池管理
- 配置验证和默认值

### 文档

- 完整的中文 README
- API 文档和示例代码
- 版本规范说明

---

## 变更类型说明

- **新增**: 新功能
- **改进**: 现有功能的改进
- **修复**: Bug 修复
- **变更**: 重大变更或破坏性变更
- **弃用**: 即将移除的功能
- **移除**: 已移除的功能
- **安全**: 安全相关的修复或改进
