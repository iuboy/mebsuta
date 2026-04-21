//! mebsuta — Rust structured logging library with Handler plugin architecture.
//!
//! Provides a `Handler` trait with composable decorators (Sampling, Async, Metrics)
//! and multiple output handlers (Stdout, File, Syslog, Database).
//!
//! # TODO (P2 — 密评 GM/T 0054 / GB/T 39786)
//!
//! 以下功能需专门分析和计划后再实施：
//!
//! - HMAC-SM3 日志完整性保护模块（每条日志追加签名，写入 chain）
//! - 完整性验证工具（批量校验日志链）
//! - 密钥管理（SM3 HMAC 密钥加载、轮换机制）
//! - Syslog TLS 传输（`SyslogTransport::Tls` + rustls）

mod async_handler;
mod config;
mod context;
mod database;
mod error;
mod file;
mod handler;
mod level;
mod multi;
mod record;
mod sampling;
mod stdout;
mod syslog;
mod time;
mod value;

pub use async_handler::Async;
pub use config::{
    AsyncConfig, DatabaseConfig as ConfigDatabaseConfig, FileConfig as ConfigFileConfig,
    MebsutaConfig, SamplingConfig as ConfigSamplingConfig, StdoutConfig,
    SyslogConfig as ConfigSyslogConfig, mask_dsn_password, sanitize_config,
};
pub use context::{ExtractorFn, WithContext};
pub use database::{DatabaseConfig, DatabaseHandler};
pub use error::Error;
pub use file::{FileHandler, RotationConfig};
pub use handler::{Close, Handler, Middleware, Terminal, close_all};
pub use level::Level;
pub use multi::MultiHandler;
pub use record::{
    Context, EventType, OwnedRecord, RecordBuilder, arc_record, audit_record, sanitize_utf8,
};
pub use sampling::Sampling;
pub use stdout::{Format, StdoutHandler};
pub use syslog::{SyslogConfig, SyslogFormat, SyslogHandler, SyslogTransport};
pub use value::{Key, Value};
