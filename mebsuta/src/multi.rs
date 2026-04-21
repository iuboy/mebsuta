use std::panic::AssertUnwindSafe;
use std::sync::Arc;

use crate::error::Error;
use crate::handler::{ErrorHandler, Handler, close_all};
use crate::record::{Context, OwnedRecord};

/// Fan-out handler: sends each record to all sub-handlers.
/// Each sub-handler call is wrapped in `catch_unwind` for panic isolation.
pub struct MultiHandler {
    handlers: Vec<Box<dyn Handler>>,
    error_handler: ErrorHandler,
}

impl MultiHandler {
    pub fn new(handlers: Vec<Box<dyn Handler>>) -> Self {
        MultiHandler {
            handlers,
            error_handler: Arc::new(std::sync::Mutex::new(None)) as ErrorHandler,
        }
    }
}

impl Handler for MultiHandler {
    fn enabled(&self, ctx: &Context<'_>) -> bool {
        self.handlers.iter().any(|h| h.enabled(ctx))
    }

    fn handle(&self, record: &Arc<OwnedRecord>) -> Result<(), Error> {
        for h in &self.handlers {
            let ctx = Context::new(record.level.clone());
            if !h.enabled(&ctx) {
                continue;
            }
            let record = Arc::clone(record);
            let result = std::panic::catch_unwind(AssertUnwindSafe(|| h.handle(&record)));
            match result {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    if let Some(ref eh) = *self
                        .error_handler
                        .lock()
                        .expect("multi error handler lock poisoned")
                    {
                        eh("multi", &e);
                    }
                }
                Err(_) => {
                    if let Some(ref eh) = *self
                        .error_handler
                        .lock()
                        .expect("multi error handler lock poisoned")
                    {
                        eh("multi", &Error::HandlerPanic);
                    }
                }
            }
        }
        Ok(())
    }

    fn clone_box(&self) -> Box<dyn Handler> {
        Box::new(MultiHandler {
            handlers: self.handlers.iter().map(|h| h.clone_box()).collect(),
            error_handler: Arc::clone(&self.error_handler),
        })
    }

    fn with_attrs(&self, attrs: Vec<(crate::value::Key, crate::value::Value)>) -> Box<dyn Handler>
    where
        Self: Sized + 'static,
    {
        Box::new(MultiHandler {
            handlers: self
                .handlers
                .iter()
                .map(|h| h.with_attrs_boxed(attrs.clone()))
                .collect(),
            error_handler: Arc::clone(&self.error_handler),
        })
    }

    fn with_group(&self, name: &str) -> Box<dyn Handler>
    where
        Self: Sized + 'static,
    {
        Box::new(MultiHandler {
            handlers: self
                .handlers
                .iter()
                .map(|h| h.with_group_boxed(name))
                .collect(),
            error_handler: Arc::clone(&self.error_handler),
        })
    }

    fn set_error_handler(&self, handler: Option<Box<dyn Fn(&str, &Error) + Send + Sync>>) {
        *self
            .error_handler
            .lock()
            .expect("multi error handler lock poisoned") = handler;
    }

    fn flush(&self) {
        for h in &self.handlers {
            let _ = std::panic::catch_unwind(AssertUnwindSafe(|| h.flush()));
        }
    }

    fn close_if_needed(&mut self) -> Option<Result<(), Error>> {
        let mut errors = Vec::new();
        for h in &mut self.handlers {
            if let Err(e) = close_all(h.as_mut()) {
                errors.push(e);
            }
        }
        if errors.is_empty() {
            Some(Ok(()))
        } else {
            Some(Err(Error::Handler(
                errors
                    .iter()
                    .map(|e| e.to_string())
                    .collect::<Vec<_>>()
                    .join(", "),
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

    use super::*;
    use crate::arc_record;
    use crate::level::Level;

    /// Mock handler that counts handle() calls.
    #[derive(Clone)]
    struct Mock {
        count: Arc<AtomicUsize>,
    }

    impl Mock {
        fn new() -> Self {
            Mock {
                count: Arc::new(AtomicUsize::new(0)),
            }
        }

        fn count(&self) -> usize {
            self.count.load(AtomicOrdering::Relaxed)
        }
    }

    impl Handler for Mock {
        fn enabled(&self, _ctx: &Context<'_>) -> bool {
            true
        }

        fn handle(&self, _record: &Arc<OwnedRecord>) -> Result<(), Error> {
            self.count.fetch_add(1, AtomicOrdering::Relaxed);
            Ok(())
        }

        fn clone_box(&self) -> Box<dyn Handler> {
            Box::new(self.clone())
        }

        fn set_error_handler(&self, _handler: Option<Box<dyn Fn(&str, &Error) + Send + Sync>>) {}
    }

    #[test]
    fn fan_out_two_handlers() {
        let m1 = Mock::new();
        let m2 = Mock::new();
        let multi = MultiHandler::new(vec![Box::new(m1.clone()), Box::new(m2.clone())]);

        let r = arc_record(Level::Info, "test");
        multi.handle(&r).unwrap();

        assert_eq!(m1.count(), 1);
        assert_eq!(m2.count(), 1);
    }

    #[test]
    fn fan_out_four_handlers() {
        let mocks: Vec<Mock> = (0..4).map(|_| Mock::new()).collect();
        let boxes: Vec<Box<dyn Handler>> = mocks
            .iter()
            .map(|m| Box::new(m.clone()) as Box<dyn Handler>)
            .collect();
        let multi = MultiHandler::new(boxes);

        let r = arc_record(Level::Info, "test");
        multi.handle(&r).unwrap();

        for m in &mocks {
            assert_eq!(m.count(), 1);
        }
    }

    #[test]
    fn enabled_any() {
        let warn_only = crate::StdoutHandler::new(Level::Warn, crate::Format::Json);
        let debug_only = crate::StdoutHandler::new(Level::Debug, crate::Format::Json);
        let multi = MultiHandler::new(vec![Box::new(warn_only), Box::new(debug_only)]);

        assert!(multi.enabled(&Context::new(Level::Info)));
        assert!(!multi.enabled(&Context::new(Level::Trace)));
    }

    #[test]
    fn panic_recovery() {
        let good = Mock::new();
        let bad = PanicHandler;
        let multi = MultiHandler::new(vec![Box::new(good.clone()), Box::new(bad)]);

        let r = arc_record(Level::Info, "test");
        let _ = multi.handle(&r);

        assert_eq!(good.count(), 1);
    }

    /// Handler that always panics.
    struct PanicHandler;

    impl Handler for PanicHandler {
        fn enabled(&self, _ctx: &Context<'_>) -> bool {
            true
        }

        fn handle(&self, _record: &Arc<OwnedRecord>) -> Result<(), Error> {
            panic!("intentional test panic");
        }

        fn clone_box(&self) -> Box<dyn Handler> {
            Box::new(PanicHandler)
        }

        fn set_error_handler(&self, _handler: Option<Box<dyn Fn(&str, &Error) + Send + Sync>>) {}
    }

    /// Handler that always errors.
    #[derive(Clone)]
    struct FailHandler;

    impl FailHandler {
        fn new() -> Self {
            FailHandler
        }
    }

    impl Handler for FailHandler {
        fn enabled(&self, _ctx: &Context<'_>) -> bool {
            true
        }

        fn handle(&self, _record: &Arc<OwnedRecord>) -> Result<(), Error> {
            Err(Error::Handler("always fails".to_owned()))
        }

        fn clone_box(&self) -> Box<dyn Handler> {
            Box::new(self.clone())
        }

        fn set_error_handler(&self, _: Option<Box<dyn Fn(&str, &Error) + Send + Sync>>) {}
    }

    #[test]
    fn swallows_handler_errors() {
        let good = Mock::new();
        let bad = FailHandler::new();
        let multi = MultiHandler::new(vec![Box::new(good.clone()), Box::new(bad)]);

        let r = arc_record(Level::Info, "test");
        // Should return Ok even though one handler errors
        assert!(multi.handle(&r).is_ok());
        assert_eq!(good.count(), 1);
    }

    #[test]
    fn single_handler_also_swallows_errors() {
        let bad = FailHandler::new();
        let multi = MultiHandler::new(vec![Box::new(bad)]);

        let r = arc_record(Level::Info, "test");
        // Single handler path should also swallow errors
        assert!(multi.handle(&r).is_ok());
    }
}
