# Mebsuta 文档

本目录包含 Mebsuta 日志库的详细文档。

## 文档索引

- [快速开始](#快速开始)
- [配置指南](#配置指南)
- [集成指南](#集成指南)
- [生产部署](#生产部署)

## 快速开始

### 基本用法

```go
import (
    "github.com/iuboy/mebsuta"
    "github.com/iuboy/mebsuta/config"
)

func main() {
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
        Encoder: config.EncoderConfig{
            MessageKey: "msg",
            LevelKey:   "level",
            TimeKey:    "time",
        },
    }

    if err := mebsuta.Init(cfg); err != nil {
        log.Fatal(err)
    }
    defer mebsuta.Sync()

    mebsuta.Info("服务启动成功")
}
```

### 使用Builder模式

```go
cfg, err := config.NewLoggerConfigBuilder("my-service").
    AddStdoutOutput(config.InfoLevel, config.Console).
    WithSampling(100, 10, 60*time.Second).
    Build()

if err != nil {
    log.Fatal(err)
}

mebsuta.InitWithDetails(cfg)
```

## 配置指南

### 编码器配置

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| MessageKey | string | "msg" | 日志消息字段名 |
| LevelKey | string | "level" | 日志级别字段名 |
| TimeKey | string | "time" | 时间字段名 |
| TimeFormat | string | RFC3339Nano | 时间格式 |
| TimeZone | string | "UTC" | 时区 |
| EnableCaller | bool | false | 是否显示调用者信息 |
| EnableStacktrace | bool | false | 是否显示堆栈跟踪 |

### 输出配置

#### 控制台输出 (Stdout)

```go
{
    Type:     config.Stdout,
    Level:    config.InfoLevel,
    Encoding: config.JSON, // 或 config.Console
    Enabled:  true,
}
```

#### 文件输出 (File)

```go
{
    Type:     config.File,
    Level:    config.DebugLevel,
    Encoding: config.JSON,
    Enabled:  true,
    File: &config.FileConfig{
        Path:       "/var/log/app/app.log",
        MaxSizeMB:  100,
        MaxBackups: 5,
        MaxAgeDays: 30,
        Compress:   true,
    },
}
```

#### 数据库输出 (Database)

```go
{
    Type:     config.DB,
    Level:    config.InfoLevel,
    Encoding: config.JSON,
    Enabled:  true,
    Database: &config.DatabaseConfig{
        DriverName:     "mysql",
        DataSourceName: "user:pass@tcp(localhost:3306)/logs",
        TableName:      "app_logs",
        BatchSize:      100,
        BatchInterval:  5 * time.Second,
    },
}
```

### 采样配置

```go
Sampling: &config.SamplingConfig{
    Enabled:    true,
    Initial:    100,  // 初始100条全部记录
    Thereafter: 10,   // 之后每10条记录1条
    Window:     60 * time.Second, // 时间窗口60秒
}
```

## 集成指南

### Prometheus监控

```go
import (
    mebmetrics "github.com/iuboy/mebsuta/metrics"
    "github.com/prometheus/client_golang/prometheus"
)

// 注册指标
prometheus.MustRegister(mebmetrics.GetMetrics())

// 在HTTP处理器中暴露指标
http.Handle("/metrics", promhttp.Handler())
```

### Grafana集成

使用提供的 [Categraf集成示例](../examples/categraf_integration/) 进行Grafana配置。

### Categraf集成

使用提供的 [Categraf集成示例](../examples/categraf_integration/) 配置日志收集。创建配置文件 `conf/input.prometheus/mebsuta.toml`:

```toml
[[instances]]
urls = ["http://localhost:2112/metrics"]
name_prefix = "mebsuta_"
labels = { service = "my-service" }
```

## 生产部署

### 部署清单

- [ ] 配置日志轮转避免磁盘占满
- [ ] 设置合理的采样率
- [ ] 配置监控和告警
- [ ] 使用非特权用户运行日志进程
- [ ] 配置日志文件权限为 0600
- [ ] 确保日志目录有足够的磁盘空间
- [ ] 配置日志级别为 Info 或 Warning
- [ ] 测试日志写入性能

### Docker部署

```dockerfile
FROM golang:1.22-alpine AS builder

WORKDIR /app
COPY . .
RUN go mod download
RUN go build -o mebsuta .

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /app
COPY --from=builder /app/mebsuta /usr/local/bin/

# 创建日志目录
RUN mkdir -p /var/log/app
ENV LOG_PATH=/var/log/app/app.log

CMD ["mebsuta"]
```

### systemd服务

```ini
[Unit]
Description=Mebsuta Logger Service
After=network.target

[Service]
Type=simple
User=logger
Group=logger
ExecStart=/usr/local/bin/mebsuta
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

## 故障排查

### 常见问题

1. **日志丢失**
   - 检查缓冲区使用率指标
   - 确认磁盘空间充足
   - 验证数据库连接

2. **性能问题**
   - 调整采样率
   - 增加批量大小
   - 使用异步输出

3. **内存泄漏**
   - 检查goroutine数量
   - 确保正确调用Sync()
   - 监控内存使用

## 迁移指南

### 从 v0.x 迁移到 v1.0

v1.0 保持与 v0.x 的向后兼容性，无需修改现有代码即可升级。

### API变更

无破坏性变更。

---

更多信息请参考：
- [主README](../README.md)
- [API文档](../example_test.go)
- [版本规范](../VERSIONING.md)
- [更新日志](../CHANGELOG.md)
