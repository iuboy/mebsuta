# Migration Guide

## v0.3.x → 独立仓库

项目从双语言 monorepo 拆分为独立 Go 仓库。Rust 版本移至独立仓库 `mebsuta-rust`。

### Import Path 变更

```go
// before (monorepo)
import "github.com/iuboy/mebsuta/go"
import "github.com/iuboy/mebsuta/go/config"
import "github.com/iuboy/mebsuta/go/metrics"

// after (独立仓库)
import "github.com/iuboy/mebsuta"
import "github.com/iuboy/mebsuta/metrics"
```

### Install 命令变更

```bash
# before (monorepo)
go get github.com/iuboy/mebsuta/go@go/v0.4.0

# after (独立仓库)
go get github.com/iuboy/mebsuta@v0.4.0
```

### Tag Scheme 变更

| Period | Tag Format | Example |
|--------|------------|---------|
| Before monorepo split | `vX.Y.Z` (root) | `v0.3.4` |
| During monorepo | `go/vX.Y.Z` | `go/v0.4.0` |
| After independent repo | `vX.Y.Z` | `v0.4.0` |

## v0.2 核心变化

- `mebsuta.New()` 返回 `*slog.Logger`（不再是自定义 Logger 类型）
- 输出通过 `slog.Handler` 插件实现
- 装饰器（采样、异步、指标）通过函数包装 Handler
- 移除了 `go.uber.org/zap` 依赖

## 已移除的 API

| 旧 API | 替代 |
|--------|------|
| `mebsuta.Init(cfg)` | `mebsuta.New(opts...)` |
| `mebsuta.CreateLogger(cfg)` | `mebsuta.New(opts...)` |
| `mebsuta.NewFromConfig(cfg)` | `mebsuta.New(opts...)` |
| `mebsuta.GetLogger()` | `slog.Default()` |
| `mebsuta.SetLogger(zl)` | `slog.SetDefault(logger)` |
| `mebsuta.IsInitialized()` | 检查 `slog.Default()` |
| `mebsuta.SetContextExtractor(fn)` | `WithContextExtractor` 装饰器 |
| `logger.Zl()` | 直接使用 `*slog.Logger` |
| `logger.Sugar()` | 使用 `fmt.Sprintf` |
| `logger.Sync()` | `mebsuta.CloseAll(handler)` |
| `logger.WithContext(ctx)` | `slog.InfoContext(ctx, ...)` |
| `logger.With(fields...)` | `logger.WithAttrs(attrs...)` |
| `zap.String/Int/...` | `slog.String/Int/...` |

## 已移除的包

| 包 | 原因 |
|----|------|
| `core/` | 被 slog Handler 替代 |
| `internal/adapter/` | 被 slog Handler 替代 |
| `errors/` | 使用标准 `fmt.Errorf` |
| `examples/categraf/` | 配置方式已变更 |
| `config/` | Config 类型提升到主包 |

## 已移除的依赖

| 依赖 | 原因 |
|------|------|
| `go.uber.org/zap` | 转向 slog |
| `github.com/natefinch/lumberjack` | 自研文件轮转 |
