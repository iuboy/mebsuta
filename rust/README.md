# Mebsuta Rust

Rust 结构化日志库，Handler 插件架构。

## 特性

- **Handler 插件**：Stdout、File、Syslog 输出
- **装饰器链**：Sampling（采样）、Async（异步写入）、Metrics（指标收集）
- **文件轮转**：大小 + 时间双策略，gzip 压缩，旧备份清理
- **MultiHandler**：fan-out 多输出 + per-handler panic recovery
- **Prometheus 指标**：独立 `mebsuta-metrics` crate
- **tracing 桥接**：`MebsutaLayer` 将 tracing 事件转发到 Handler
- **泛型装饰器**：`Sampling<H>` 编译时单态化，零 vtable 开销

## 安装

Crate 尚未发布到 crates.io。当前通过本地路径引用：

```toml
[dependencies]
mebsuta = { path = "../rust/mebsuta" }
```

可选：

```toml
mebsuta-tracing = { path = "../rust/mebsuta-tracing" }  # tracing bridge
mebsuta-metrics = { path = "../rust/mebsuta-metrics" }   # Prometheus 指标
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

JSON 输出使用跨语言稳定契约：

```json
{"time":"2026-05-21T14:00:00Z","level":"INFO","message":"hello","attributes":{"key":"value"}}
```

审计日志使用带事件类型的 `Level::Audit(EventType)`：

```rust
let r = RecordBuilder::new(Level::Audit(EventType::Login), "user login")
    .actor("user:42")
    .success(true)
    .attr("ip", "127.0.0.1")
    .build();
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
let h = StdoutHandler::new(Level::Info, Format::Text);
```

### FileHandler（含轮转）

```rust
let rotation = RotationConfig {
    max_size_bytes: 100 * 1024 * 1024,
    rotate_interval_secs: 86400,
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

## Crate 结构

| Crate | 说明 |
| --- | --- |
| `mebsuta` | 核心：Handler trait、装饰器、输出 Handler |
| `mebsuta-tracing` | tracing -> mebsuta 桥接 |
| `mebsuta-metrics` | Prometheus 指标装饰器 |

## 测试

```bash
cargo test --workspace
cargo fmt --all -- --check
cargo clippy --workspace -- -D warnings
cargo audit
```

## 仓库规范

Rust 实现遵循根目录 `SPEC.md` 的共享行为契约。新增或修改与 Go 共享的行为时，请同步更新根目录 `TESTING.md` 的测试矩阵。

Rust 发布标签使用 `rust/vX.Y.Z`，详见根目录 `VERSIONING.md`。
