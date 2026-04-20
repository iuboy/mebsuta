//! mebsuta — Rust structured logging library with Handler plugin architecture.
//!
//! Provides a `Handler` trait with composable decorators (Sampling, Async, Metrics)
//! and multiple output handlers (Stdout, File, Syslog, Database).

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
mod time;
mod stdout;
mod syslog;
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
pub use record::{Context, OwnedRecord, RecordBuilder, arc_record, sanitize_utf8};
pub use sampling::Sampling;
pub use stdout::{Format, StdoutHandler};
pub use syslog::{SyslogConfig, SyslogFormat, SyslogHandler, SyslogTransport};
pub use value::{Key, Value};
