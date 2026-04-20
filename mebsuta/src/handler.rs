use std::sync::Arc;

use crate::error::Error;
use crate::record::Context;
use crate::value::{Key, Value};

/// Type alias for the error handler callback to reduce complexity.
pub(crate) type ErrorHandler =
    Arc<std::sync::Mutex<Option<Box<dyn Fn(&str, &Error) + Send + Sync>>>>;

/// Core log processing trait.
///
/// All output handlers and decorators implement this trait.
/// Generic decorators (Sampling, Async, Metrics) use `H: Handler`
/// for compile-time monomorphization (zero vtable overhead).
///
/// Handler must be `Send + Sync` (thread-safe) and `Clone` (for `with_attrs`).
pub trait Handler: Send + Sync {
    /// Check whether this handler processes logs at the given level.
    /// Lightweight gate on the hot path.
    fn enabled(&self, ctx: &Context<'_>) -> bool;

    /// Process a log record.
    fn handle(&self, record: &Arc<crate::record::OwnedRecord>) -> Result<(), Error>;

    /// Clone into a boxed trait object.
    fn clone_box(&self) -> Box<dyn Handler>;

    /// Create a new handler with additional attributes prepended to every record.
    fn with_attrs(&self, attrs: Vec<(Key, Value)>) -> Box<dyn Handler>
    where
        Self: Sized + 'static,
    {
        Box::new(AttrsHandler {
            inner: self.clone_box(),
            attrs,
        })
    }

    /// Object-safe version of `with_attrs` for `Box<dyn Handler>`.
    fn with_attrs_boxed(&self, attrs: Vec<(Key, Value)>) -> Box<dyn Handler> {
        Box::new(AttrsHandler {
            inner: self.clone_box(),
            attrs,
        })
    }

    /// Create a new handler with a group prefix.
    fn with_group(&self, name: &str) -> Box<dyn Handler>
    where
        Self: Sized + 'static,
    {
        Box::new(GroupHandler {
            inner: self.clone_box(),
            group: name.to_owned(),
        })
    }

    /// Object-safe version of `with_group` for `Box<dyn Handler>`.
    fn with_group_boxed(&self, name: &str) -> Box<dyn Handler> {
        Box::new(GroupHandler {
            inner: self.clone_box(),
            group: name.to_owned(),
        })
    }

    /// Set an error handler callback. Called when internal errors occur.
    #[allow(clippy::type_complexity)]
    fn set_error_handler(&self, handler: Option<Box<dyn Fn(&str, &Error) + Send + Sync>>);

    /// Flush buffered data (if any).
    fn flush(&self) {}

    /// Resource cleanup hook. Override in types that need cleanup.
    fn close_if_needed(&mut self) -> Option<Result<(), Error>> {
        None
    }
}

/// Resource cleanup trait for handlers that manage resources (files, connections).
pub trait Close: Handler {
    fn close(&mut self) -> Result<(), Error>;
}

/// Recursively close all handlers in a decorator chain.
pub fn close_all(handler: &mut dyn Handler) -> Result<(), Error> {
    handler.close_if_needed().unwrap_or(Ok(()))
}

/// Marker trait for terminal handlers (Stdout, File, Syslog, Database).
pub trait Terminal: Handler {}

/// Marker trait for middleware/decorator handlers (Sampling, Async, Metrics).
pub trait Middleware<H: Handler>: Handler {
    fn inner(&self) -> &H;
}

// ---------------------------------------------------------------------------
// AttrsHandler and GroupHandler (returned by with_attrs / with_group)
// ---------------------------------------------------------------------------

struct AttrsHandler {
    inner: Box<dyn Handler>,
    attrs: Vec<(Key, Value)>,
}

impl Handler for AttrsHandler {
    fn enabled(&self, ctx: &Context<'_>) -> bool {
        self.inner.enabled(ctx)
    }

    fn handle(&self, record: &Arc<crate::record::OwnedRecord>) -> Result<(), Error> {
        // Append pre-defined attrs to the record
        let mut combined = record.attrs.clone();
        combined.extend(self.attrs.iter().cloned());
        let enriched = crate::record::OwnedRecord {
            attrs: combined,
            ..(**record).clone()
        };
        self.inner.handle(&Arc::new(enriched))
    }

    fn clone_box(&self) -> Box<dyn Handler> {
        Box::new(AttrsHandler {
            inner: self.inner.clone_box(),
            attrs: self.attrs.clone(),
        })
    }

    fn set_error_handler(&self, handler: Option<Box<dyn Fn(&str, &Error) + Send + Sync>>) {
        self.inner.set_error_handler(handler);
    }

    fn flush(&self) {
        self.inner.flush();
    }

    fn close_if_needed(&mut self) -> Option<Result<(), Error>> {
        self.inner.close_if_needed()
    }
}

struct GroupHandler {
    inner: Box<dyn Handler>,
    group: String,
}

impl Handler for GroupHandler {
    fn enabled(&self, ctx: &Context<'_>) -> bool {
        self.inner.enabled(ctx)
    }

    fn handle(&self, record: &Arc<crate::record::OwnedRecord>) -> Result<(), Error> {
        // The inner handler is responsible for applying the group prefix
        // in its output format (JSON nesting, Text dot notation, etc.)
        self.inner.handle(record)
    }

    fn clone_box(&self) -> Box<dyn Handler> {
        Box::new(GroupHandler {
            inner: self.inner.clone_box(),
            group: self.group.clone(),
        })
    }

    fn set_error_handler(&self, handler: Option<Box<dyn Fn(&str, &Error) + Send + Sync>>) {
        self.inner.set_error_handler(handler);
    }

    fn flush(&self) {
        self.inner.flush();
    }

    fn close_if_needed(&mut self) -> Option<Result<(), Error>> {
        self.inner.close_if_needed()
    }
}
