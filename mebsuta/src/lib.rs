//! mebsuta — Rust structured logging library with Handler plugin architecture.
//!
//! Provides a `Handler` trait with composable decorators (Sampling, Async, Metrics)
//! and multiple output handlers (Stdout, File, Syslog, Database).

mod async_handler;
mod error;
mod file;
mod handler;
mod level;
mod multi;
mod record;
mod sampling;
mod stdout;
mod syslog;
mod value;

pub use async_handler::Async;
pub use error::Error;
pub use file::{FileHandler, RotationConfig};
pub use handler::{Close, Handler, Middleware, Terminal, close_all};
pub use level::Level;
pub use multi::MultiHandler;
pub use record::{Context, OwnedRecord, RecordBuilder, arc_record};
pub use sampling::Sampling;
pub use stdout::{Format, StdoutHandler};
pub use syslog::{SyslogConfig, SyslogFormat, SyslogHandler, SyslogTransport};
pub use value::{Key, Value};
