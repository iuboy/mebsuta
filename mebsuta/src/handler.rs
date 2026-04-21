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
        Box::new(GroupHandler::new(self.clone_box(), name.to_owned()))
    }

    /// Object-safe version of `with_group` for `Box<dyn Handler>`.
    fn with_group_boxed(&self, name: &str) -> Box<dyn Handler> {
        Box::new(GroupHandler::new(self.clone_box(), name.to_owned()))
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
    group_prefix: String,
}

impl GroupHandler {
    fn new(inner: Box<dyn Handler>, group: String) -> Self {
        let group_prefix = format!("{group}.");
        GroupHandler {
            inner,
            group,
            group_prefix,
        }
    }
}

impl Handler for GroupHandler {
    fn enabled(&self, ctx: &Context<'_>) -> bool {
        self.inner.enabled(ctx)
    }

    fn handle(&self, record: &Arc<crate::record::OwnedRecord>) -> Result<(), Error> {
        let mut enriched = (**record).clone();
        let prefix = &self.group_prefix;
        enriched.attrs = record
            .attrs
            .iter()
            .map(|(k, v)| {
                let prefixed = format!("{prefix}{}", k.as_str());
                (Key::new(prefixed), v.clone())
            })
            .collect();
        self.inner.handle(&Arc::new(enriched))
    }

    fn clone_box(&self) -> Box<dyn Handler> {
        Box::new(GroupHandler::new(
            self.inner.clone_box(),
            self.group.clone(),
        ))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arc_record;
    use crate::level::Level;
    use crate::record::Context;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Clone)]
    struct Mock {
        count: Arc<AtomicUsize>,
        last_attrs: Arc<std::sync::Mutex<Vec<(Key, Value)>>>,
    }

    impl Mock {
        fn new() -> Self {
            Mock {
                count: Arc::new(AtomicUsize::new(0)),
                last_attrs: Arc::new(std::sync::Mutex::new(Vec::new())),
            }
        }
        #[expect(dead_code)]
        fn count(&self) -> usize {
            self.count.load(Ordering::Relaxed)
        }
        fn last_attrs(&self) -> Vec<(Key, Value)> {
            self.last_attrs.lock().unwrap().clone()
        }
    }

    impl Handler for Mock {
        fn enabled(&self, _ctx: &Context<'_>) -> bool {
            true
        }
        fn handle(&self, record: &std::sync::Arc<crate::record::OwnedRecord>) -> Result<(), Error> {
            self.count.fetch_add(1, Ordering::Relaxed);
            *self.last_attrs.lock().unwrap() = record.attrs.clone();
            Ok(())
        }
        fn clone_box(&self) -> Box<dyn Handler> {
            Box::new(self.clone())
        }
        fn set_error_handler(&self, _: Option<Box<dyn Fn(&str, &Error) + Send + Sync>>) {}
    }

    #[test]
    fn group_handler_prefixes_keys() {
        let mock = Mock::new();
        let h = mock.with_group("app");
        let r = crate::record::RecordBuilder::new(Level::Info, "test")
            .attr("key", "val")
            .build();
        h.handle(&std::sync::Arc::new(r)).unwrap();
        let attrs = mock.last_attrs();
        assert_eq!(attrs.len(), 1);
        assert_eq!(attrs[0].0.as_str(), "app.key");
        assert_eq!(attrs[0].1.to_string(), "val");
    }

    #[test]
    fn group_handler_no_attrs() {
        let mock = Mock::new();
        let h = mock.with_group("ns");
        let r = arc_record(Level::Info, "no attrs");
        h.handle(&r).unwrap();
        assert!(mock.last_attrs().is_empty());
    }

    #[test]
    fn group_handler_clone_preserves_prefix() {
        let mock = Mock::new();
        let h = mock.with_group("svc");
        let h2 = h.clone_box();
        let r = crate::record::RecordBuilder::new(Level::Info, "x")
            .attr("a", 1i64)
            .build();
        h2.handle(&std::sync::Arc::new(r)).unwrap();
        let attrs = mock.last_attrs();
        assert_eq!(attrs[0].0.as_str(), "svc.a");
    }
}
