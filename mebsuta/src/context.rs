use std::sync::Arc;

use crate::error::Error;
use crate::handler::{ErrorHandler, Handler, Middleware};
use crate::record::{Context, OwnedRecord};
use crate::value::{Key, Value};

/// Function that extracts additional attributes from a record.
pub type ExtractorFn = Arc<dyn Fn(&OwnedRecord) -> Vec<(Key, Value)> + Send + Sync>;

/// Context extractor decorator. Calls the extractor on each record and
/// merges the returned attributes before forwarding to the inner handler.
///
/// Useful for enriching records with runtime context (trace IDs from
/// thread-local storage, module-specific metadata, etc.).
pub struct WithContext<H> {
    inner: H,
    extractor: ExtractorFn,
    error_handler: ErrorHandler,
}

impl<H: Handler + Clone + 'static> WithContext<H> {
    pub fn new(inner: H, extractor: ExtractorFn) -> Self {
        WithContext {
            inner,
            extractor,
            error_handler: Arc::new(std::sync::Mutex::new(None)),
        }
    }
}

impl<H: Handler + Clone + 'static> Handler for WithContext<H> {
    fn enabled(&self, ctx: &Context<'_>) -> bool {
        self.inner.enabled(ctx)
    }

    fn handle(&self, record: &Arc<OwnedRecord>) -> Result<(), Error> {
        let extra = (self.extractor)(record);
        if extra.is_empty() {
            return self.inner.handle(record);
        }

        let mut combined = record.attrs.clone();
        combined.extend(extra);

        let enriched = OwnedRecord {
            attrs: combined,
            ..(**record).clone()
        };
        self.inner.handle(&Arc::new(enriched))
    }

    fn clone_box(&self) -> Box<dyn Handler> {
        Box::new(WithContext {
            inner: self.inner.clone(),
            extractor: self.extractor.clone(),
            error_handler: Arc::clone(&self.error_handler),
        })
    }

    fn set_error_handler(&self, handler: Option<Box<dyn Fn(&str, &Error) + Send + Sync>>) {
        *self.error_handler.lock().unwrap() = handler;
    }

    fn flush(&self) {
        self.inner.flush();
    }

    fn close_if_needed(&mut self) -> Option<Result<(), Error>> {
        self.inner.close_if_needed()
    }
}

impl<H: Handler + Clone + 'static> Middleware<H> for WithContext<H> {
    fn inner(&self) -> &H {
        &self.inner
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use super::*;
    use crate::arc_record;
    use crate::level::Level;

    #[derive(Clone)]
    struct Mock {
        count: Arc<AtomicUsize>,
        last_attrs: std::sync::Arc<std::sync::Mutex<Vec<(Key, Value)>>>,
    }

    impl Mock {
        fn new() -> Self {
            Mock {
                count: Arc::new(AtomicUsize::new(0)),
                last_attrs: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
            }
        }
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
        fn handle(&self, record: &Arc<OwnedRecord>) -> Result<(), Error> {
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
    fn extracts_and_merges_attrs() {
        let mock = Mock::new();
        let extractor: ExtractorFn = Arc::new(|_| {
            vec![
                ("trace_id".into(), "abc-123".into()),
                ("span_id".into(), "def-456".into()),
            ]
        });
        let ctx = WithContext::new(mock.clone(), extractor);

        let r = arc_record(Level::Info, "hello");
        ctx.handle(&r).unwrap();

        assert_eq!(mock.count(), 1);
        let attrs = mock.last_attrs();
        let trace_id = attrs.iter().find(|(k, _)| k.as_str() == "trace_id");
        assert!(trace_id.is_some());
        assert_eq!(trace_id.unwrap().1.to_string(), "abc-123");
    }

    #[test]
    fn no_extra_when_empty() {
        let mock = Mock::new();
        let extractor: ExtractorFn = Arc::new(|_| Vec::new());
        let ctx = WithContext::new(mock.clone(), extractor);

        let r = arc_record(Level::Info, "no extra");
        ctx.handle(&r).unwrap();

        assert_eq!(mock.count(), 1);
        assert!(mock.last_attrs().is_empty());
    }

    #[test]
    fn conditionally_extracts() {
        let mock = Mock::new();
        let extractor: ExtractorFn = Arc::new(|r| {
            if r.level == Level::Error {
                vec![("alert".into(), "true".into())]
            } else {
                Vec::new()
            }
        });
        let ctx = WithContext::new(mock.clone(), extractor);

        let r_info = arc_record(Level::Info, "info");
        ctx.handle(&r_info).unwrap();
        assert!(mock.last_attrs().is_empty());

        let r_err = arc_record(Level::Error, "error");
        ctx.handle(&r_err).unwrap();
        let attrs = mock.last_attrs();
        assert!(attrs.iter().any(|(k, _)| k.as_str() == "alert"));
    }
}
