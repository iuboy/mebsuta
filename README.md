# Mebsuta

Rust 结构化日志库，Handler 插件架构。同时保留 Go 版本（见 `go/` 目录）。

## 特性

- **Handler 插件**：Stdout、File、Syslog 输出
- **装饰器链**：Sampling（采样）、Async（异步写入）、Metrics（指标收集）
- **文件轮转**：大小 + 时间双策略，gzip 压缩，旧备份清理
- **MultiHandler**：fan-out 多输出 + per-handler panic recovery
- **Prometheus 指标**：独立 `mebsuta-metrics` crate
- **tracing 桥接**：`MebsutaLayer` 将 tracing 事件转发到 Handler
- **泛型装饰器**：`Sampling<H>` 编译时单态化，零 vtable 开销

## 安装

```toml
[dependencies]
mebsuta = "0.1"
```

可选：
```toml
mebsuta-tracing = "0.1"   # tracing bridge
mebsuta-metrics = "0.1"   # Prometheus 指标
```

## 快速开始

```rust
use mebsuta::*;

fn main() {
    let handler = StdoutHandler::new(Level::Info, Format::Json);
    let r = arc_record(Level::Info, "服务启动成功");
    handler.handle(&r).unwrap();
    handler.flush();
}
```

## 装饰器组合

```rust
use mebsuta::*;

let stdout = StdoutHandler::new(Level::Info, Format::Json);
let sampling = Sampling::new(stdout, 100, 10, 1000);

let r = arc_record(Level::Info, "sampled message");
sampling.handle(&r).unwrap();
sampling.flush();
```

## 输出 Handler

### StdoutHandler

```rust
let h = StdoutHandler::new(Level::Info, Format::Json);
// 或
let h = StdoutHandler::new(Level::Info, Format::Text);
```

### FileHandler（含轮转）

```rust
let rotation = RotationConfig {
    max_size_bytes: 100 * 1024 * 1024, // 100 MB
    rotate_interval_secs: 86400,        // 每天轮转
    max_backups: 5,
    max_age_days: 30,
    compress: true,
    ..Default::default()
};
let mut h = FileHandler::with_rotation("/var/log/app.log", Level::Info, Format::Json, rotation)?;
h.handle(&arc_record(Level::Info, "hello"))?;
h.close()?;
```

### SyslogHandler

```rust
use mebsuta::{SyslogHandler, SyslogConfig, SyslogTransport, SyslogFormat};

let config = SyslogConfig {
    transport: SyslogTransport::Udp,
    format: SyslogFormat::RFC5424,
    address: "127.0.0.1:514".to_owned(),
    tag: "my-app".to_owned(),
    ..Default::default()
};
let h = SyslogHandler::new(Level::Info, config)?;
```

## MultiHandler（多输出）

```rust
let h = MultiHandler::new(vec![
    Box::new(StdoutHandler::new(Level::Info, Format::Json)),
    Box::new(FileHandler::new("app.log", Level::Debug, Format::Text).unwrap()),
]);
h.handle(&arc_record(Level::Info, "fan-out")).unwrap();
```

## Async（异步写入）

```rust
let inner = StdoutHandler::new(Level::Info, Format::Json);
let mut async_h = Async::with_buffer_size(inner, 1024);

async_h.handle(&arc_record(Level::Info, "async message")).unwrap();
async_h.close_if_needed(); // graceful drain
```

## Metrics（Prometheus 指标）

```rust
use mebsuta_metrics::{Metrics, MetricsCounters};
use prometheus::Registry;

let registry = Registry::new();
let counters = MetricsCounters::new("myapp", &registry).unwrap();
let inner = StdoutHandler::new(Level::Info, Format::Json);
let metrics = Metrics::new(inner, counters);

metrics.handle(&arc_record(Level::Info, "counted")).unwrap();
println!("total: {}", metrics.counters.total());
```

## Tracing 桥接

```rust
use mebsuta_tracing::MebsutaLayer;
use mebsuta::{StdoutHandler, Level, Format};
use tracing_subscriber::layer::SubscriberExt;

let handler = StdoutHandler::new(Level::Info, Format::Json);
let layer = MebsutaLayer::new(handler);
let subscriber = tracing_subscriber::registry().with(layer);
tracing::subscriber::set_global_default(subscriber).unwrap();

tracing::info!("this goes through mebsuta");
```

## Crate 结构

| Crate | 说明 |
|-------|------|
| `mebsuta` | 核心：Handler trait、装饰器、输出 Handler |
| `mebsuta-tracing` | tracing → mebsuta 桥接 |
| `mebsuta-metrics` | Prometheus 指标装饰器 |

## Go 版本

Go 版本保留在 `go/` 目录，完整可用：

```bash
cd go && go test -race -count=1 ./...
```

## 测试

```bash
cargo test
cargo test --workspace
```

## 许可证

MIT License
