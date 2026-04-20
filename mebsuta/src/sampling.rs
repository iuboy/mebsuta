use std::sync::atomic::{AtomicU64, Ordering};

use crate::error::Error;
use crate::handler::{Handler, Middleware};
use crate::level::Level;
use crate::record::{Context, OwnedRecord};

/// Sampling decorator. Passes the first `initial` records, then 1 in `thereafter`
/// thereafter. Error-level records always pass (never sampled).
///
/// Uses a monotonic counter for window reset (no wall-clock dependency).
pub struct Sampling<H> {
    inner: H,
    initial: u64,
    thereafter: u64,
    counter: AtomicU64,
    window_ticks: u64,
    window_start: AtomicU64,
}

impl<H: Handler> Sampling<H> {
    pub fn new(inner: H, initial: u64, thereafter: u64, window_ticks: u64) -> Self {
        Sampling {
            inner,
            initial,
            thereafter,
            counter: AtomicU64::new(0),
            window_ticks,
            window_start: AtomicU64::new(0),
        }
    }
}

impl<H: Handler + Clone + 'static> Handler for Sampling<H> {
    fn enabled(&self, ctx: &Context<'_>) -> bool {
        self.inner.enabled(ctx)
    }

    fn handle(&self, record: &std::sync::Arc<OwnedRecord>) -> Result<(), Error> {
        if record.level == Level::Error {
            return self.inner.handle(record);
        }

        let count = self.counter.fetch_add(1, Ordering::Relaxed);
        let window_start = self.window_start.load(Ordering::Relaxed);
        if count > 0 && count - window_start >= self.window_ticks {
            self.counter.store(1, Ordering::Relaxed);
            self.window_start.store(count, Ordering::Relaxed);
            return self.inner.handle(record);
        }

        let local_count = count - window_start;
        if local_count < self.initial {
            return self.inner.handle(record);
        }
        if (local_count - self.initial).is_multiple_of(self.thereafter) {
            return self.inner.handle(record);
        }

        Ok(())
    }

    fn clone_box(&self) -> Box<dyn Handler> {
        Box::new(Self {
            inner: self.inner.clone(),
            initial: self.initial,
            thereafter: self.thereafter,
            counter: AtomicU64::new(0),
            window_ticks: self.window_ticks,
            window_start: AtomicU64::new(0),
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

impl<H: Handler + Clone + 'static> Middleware<H> for Sampling<H> {
    fn inner(&self) -> &H {
        &self.inner
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::arc_record;
    use crate::record::Context;

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
            self.count.load(Ordering::Relaxed)
        }
    }

    impl Handler for Mock {
        fn enabled(&self, _ctx: &Context<'_>) -> bool {
            true
        }

        fn handle(&self, _record: &std::sync::Arc<OwnedRecord>) -> Result<(), Error> {
            self.count.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }

        fn clone_box(&self) -> Box<dyn Handler> {
            Box::new(self.clone())
        }

        fn set_error_handler(&self, _handler: Option<Box<dyn Fn(&str, &Error) + Send + Sync>>) {}
    }

    #[test]
    fn initial_passes_all() {
        let mock = Mock::new();
        let sampling = Sampling::new(mock.clone(), 5, 100, 1000);
        for _ in 0..5 {
            let r = arc_record(Level::Info, "x");
            let _ = sampling.handle(&r);
        }
        assert_eq!(mock.count(), 5);
    }

    #[test]
    fn thereafter_samples() {
        let mock = Mock::new();
        let sampling = Sampling::new(mock.clone(), 2, 3, 1000);
        // 2 initial + thereafter logic
        for i in 0..8 {
            let r = arc_record(Level::Info, format!("msg {i}"));
            let _ = sampling.handle(&r);
        }
        // initial 2 pass, then index 2,5 pass (every 3rd after initial)
        assert_eq!(mock.count(), 4);
    }

    #[test]
    fn error_always_passes() {
        let mock = Mock::new();
        let sampling = Sampling::new(mock.clone(), 0, 100, 1000);
        for _ in 0..10 {
            let r = arc_record(Level::Error, "err");
            let _ = sampling.handle(&r);
        }
        assert_eq!(mock.count(), 10);
    }

    #[test]
    fn window_reset() {
        let mock = Mock::new();
        let sampling = Sampling::new(mock.clone(), 2, 100, 5);
        // 5 records fills window (initial 2 pass, then 3 sampled out)
        for _ in 0..5 {
            let r = arc_record(Level::Info, "x");
            let _ = sampling.handle(&r);
        }
        let count_before = mock.count();
        // Next record triggers window reset and passes
        let r = arc_record(Level::Info, "reset");
        let _ = sampling.handle(&r);
        assert!(mock.count() > count_before);
    }
}
