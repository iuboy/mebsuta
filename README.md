# Mebsuta 日志库

一个高性能、结构化的 Go 日志库，专为微服务设计。

## 特性

- **多输出支持**：控制台、文件、SQL数据库（MySQL、PostgreSQL）、InfluxDB、Syslog
- **高性能**：异步批量写入，编码器缓存优化
- **监控集成**：内置 Prometheus 指标支持
- **动态采样**：智能日志采样，避免日志爆炸
- **完整错误处理**：自定义错误类型，错误链追踪
- **上下文感知**：支持从 context 中提取日志字段
- **中文文档**：完整的中文注释和错误消息

## 安装

```bash
go get github.com/iuboy/mebsuta
```

## 快速开始

### 基础使用

```go
package main

import (
    "github.com/iuboy/mebsuta"
    "github.com/iuboy/mebsuta/config"
)

func main() {
    // 创建配置
    cfg := config.LoggerConfig{
        ServiceName: "my-service",
        DebugMode:   false,
        Outputs: []config.OutputConfig{
            {
                Type:     config.Stdout,
                Level:    config.InfoLevel,
                Encoding: config.JSON,
                Enabled:  true,
            },
        },
        Encoder: config.EncoderConfig{
            MessageKey: "msg",
            LevelKey:   "level",
            TimeKey:    "time",
        },
    }

    // 初始化日志
    if err := mebsuta.Init(cfg); err != nil {
        panic(err)
    }

    // 记录日志
    mebsuta.Info("服务启动成功")
    mebsuta.Error("发生错误", mebsuta.String("code", "500"))
}
```

### 数据库输出

```go
cfg := config.LoggerConfig{
    ServiceName: "my-service",
    Outputs: []config.OutputConfig{
        {
            Type:    config.DB,
            Level:   config.InfoLevel,
            Enabled: true,
            Database: &config.DatabaseConfig{
                DriverName:     "mysql",
                DataSourceName: "user:password@tcp(localhost:3306)/dbname",
                TableName:      "logs",
                BatchSize:      100,
                BatchInterval:   time.Second * 5,
            },
        },
    },
}
```

### InfluxDB 输出

```go
cfg := config.LoggerConfig{
    Outputs: []config.OutputConfig{
        {
            Type:    config.DB,
            Level:   config.InfoLevel,
            Enabled: true,
            Database: &config.DatabaseConfig{
                DriverName: "influxdb",
                TimeSeries: &config.TimeSeriesConfig{
                    URL:    "http://localhost:8086",
                    Token:   "your-token",
                    Org:    "my-org",
                    Bucket:  "logs",
                },
            },
        },
    },
}
```

### 日志采样

```go
cfg := config.LoggerConfig{
    Sampling: config.SamplingConfig{
        Enabled:    true,
        Initial:    100,  // 初始记录100条
        Thereafter: 10,   // 之后每10条记录1条
        Window:     time.Minute,
    },
}
```

### 上下文日志

```go
// 设置上下文提取器
mebsuta.SetContextExtractor(func(ctx context.Context) []zap.Field {
    if id, ok := ctx.Value("request_id").(string); ok {
        return []zap.Field{zap.String("request_id", id)}
    }
    return nil
})

// 使用上下文
mebsuta.WithContext(ctx).Info("处理请求")
```

## 配置选项

### LoggerConfig

| 字段 | 类型 | 说明 |
|------|------|------|
| ServiceName | string | 服务名称 |
| DebugMode | bool | 调试模式 |
| Outputs | []OutputConfig | 输出配置列表 |
| Encoder | EncoderConfig | 编码器配置 |
| Sampling | SamplingConfig | 采样配置 |

### OutputConfig

| 字段 | 类型 | 说明 |
|------|------|------|
| Type | OutputType | 输出类型（Stdout、File、DB、Syslog）|
| Level | LogLevel | 日志级别 |
| Encoding | EncodingType | 编码类型（JSON、Console）|
| Enabled | bool | 是否启用 |
| File | *FileConfig | 文件配置 |
| Database | *DatabaseConfig | 数据库配置 |
| Syslog | *SyslogConfig | Syslog配置 |

## 监控指标

Mebsuta 内置 Prometheus 指标支持，可以与 Categraf、Prometheus、Grafana 等监控系统集成。

### 快速集成

```go
import (
    "net/http"
    "github.com/iuboy/mebsuta"
    "github.com/iuboy/mebsuta/config"
    mebmetrics "github.com/iuboy/mebsuta/metrics"
    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promhttp"
)

func main() {
    // 初始化日志
    cfg := config.LoggerConfig{
        ServiceName: "my-service",
        Outputs: []config.OutputConfig{
            {
                Type:     config.Stdout,
                Level:    config.InfoLevel,
                Encoding: config.JSON,
                Enabled:  true,
            },
        },
    }
    mebsuta.Init(cfg)

    // 注册 Mebsuta 指标
    registry := prometheus.NewRegistry()
    registry.MustRegister(mebmetrics.GetMetricsAsCollector())

    // 暴露指标端点（供 Categraf 抓取）
    http.Handle("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{
        EnableOpenMetrics: true,
    }))
    http.ListenAndServe(":2112", nil)
}
```

### Categraf 配置

创建 Categraf 配置文件 `conf/input.prometheus/mebsuta.toml`:

```toml
[[instances]]
urls = ["http://localhost:2112/metrics"]
name_prefix = "mebsuta_"
labels = { service = "my-service" }
```

详细集成指南请参考：[Categraf 集成文档](docs/CATEGRAF.md)

### 可用指标

### 日志写入指标

- `mebsuta_log_writes_total` - 日志写入总数（按级别和输出标签）
- `mebsuta_log_dropped_total` - 日志丢弃总数
- `mebsuta_log_errors_total` - 日志错误总数

### 批量写入指标

- `mebsuta_batch_writes_total` - 批量写入总数
- `mebsuta_batch_size` - 批量写入大小分布
- `mebsuta_batch_latency_seconds` - 批量写入延迟分布
- `mebsuta_batch_failures_total` - 批量写入失败总数

### 缓冲区指标

- `mebsuta_buffer_usage` - 缓冲区使用率
- `mebsuta_buffer_full_total` - 缓冲区满事件总数

### 连接池指标

- `mebsuta_active_connections` - 活跃连接数
- `mebsuta_idle_connections` - 空闲连接数

## 错误处理

Mebsuta 使用自定义错误类型，支持错误链追踪：

```go
import meberrors "github.com/iuboy/mebsuta/errors"

// 检查错误
if err != nil {
    if meberrors.IsMebsutaError(err) {
        code := meberrors.GetCode(err)
        msg := meberrors.GetMessage(err)
        fmt.Printf("[%s] %s\n", code, msg)
    }
}
```

## 性能优化

1. **编码器缓存**：使用 LRU 缓存策略，避免重复创建编码器
2. **异步批量写入**：所有数据库写入都是异步的，支持批量操作
3. **连接池管理**：数据库连接使用连接池，支持最大连接数配置
4. **背压机制**：缓冲区满时自动丢弃日志，避免阻塞主程序

## 测试

项目提供了完整的测试脚本，用于运行所有测试项。

### 运行测试

使用提供的 `test.sh` 脚本运行测试：

```bash
# 运行所有测试（包括竞态检测和覆盖率报告）
./test.sh

# 或使用 all 选项
./test.sh all
```

### 测试选项

测试脚本支持多种测试模式：

```bash
# 仅运行单元测试
./test.sh unit

# 运行竞态检测测试
./test.sh race

# 运行测试并生成覆盖率报告
./test.sh cover

# 运行基准测试
./test.sh benchmark

# 检查代码格式
./test.sh fmt

# 运行 go vet 检查
./test.sh vet

# 清理测试文件
./test.sh clean

# 显示帮助信息
./test.sh help
```

### 测试覆盖率

运行 `./test.sh cover` 后会生成 HTML 格式的覆盖率报告 `coverage.html`，可以在浏览器中打开查看详细的代码覆盖率。

### 测试覆盖范围

- **单元测试**：各个包的单元测试
- **集成测试**：使用 testcontainers 进行数据库集成测试
- **竞态检测**：使用 `-race` 标志检测并发问题
- **覆盖率报告**：生成详细的代码覆盖率报告

## 最佳实践

1. **正确初始化**：确保在程序启动时正确初始化日志
2. **合理设置采样**：在高流量场景下启用采样
3. **监控指标**：定期检查日志指标，及时发现问题
4. **错误处理**：使用 `defer mebsuta.Sync()` 确保日志刷新
5. **运行测试**：在提交代码前运行 `./test.sh all` 确保所有测试通过

## 许可证

MIT License

## 更多文档

- [完整文档](docs/INDEX.md) - 详细的配置和集成指南
- [贡献指南](CONTRIBUTING.md) - 如何贡献代码
- [安全政策](SECURITY.md) - 安全漏洞报告
- [版本规范](VERSIONING.md) - 版本管理和兼容性
- [更新日志](CHANGELOG.md) - 版本更新记录

## 相关项目

- [Zap](https://github.com/uber-go/zap) - Uber的高性能Go日志库
- [Prometheus](https://prometheus.io/) - 监控指标收集
- [Lumberjack](https://github.com/natefinch/lumberjack) - 日志轮转库
