use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use crate::error::Error;
use crate::handler::{Handler, Middleware};
use crate::level::Level;
use crate::record::{Context, OwnedRecord};

struct SamplingState {
    counter: AtomicU64,
    window_start: AtomicU64,
}

/// Sampling decorator. Passes the first `initial` records, then 1 in `thereafter`
/// thereafter. Error-level records always pass (never sampled).
///
/// Uses a monotonic counter for window reset (no wall-clock dependency).
///
/// # Concurrency
///
/// The counter uses `Ordering::Relaxed` atomics. Under high concurrency, the
/// effective sampling rate may deviate slightly from the configured ratio (e.g.,
/// a few extra records may pass during counter reset windows). This is acceptable
/// for observability sampling where exact precision is not required.
///
/// Clones share the same counter state via `Arc`, matching Go's pointer-sharing
/// semantics so that decoration (with_attrs/with_group) does not reset sampling.
pub struct Sampling<H> {
    inner: H,
    initial: u64,
    thereafter: u64,
    state: Arc<SamplingState>,
    window_ticks: u64,
}

impl<H: Handler> Sampling<H> {
    pub fn new(inner: H, initial: u64, thereafter: u64, window_ticks: u64) -> Self {
        Sampling {
            inner,
            initial,
            thereafter,
            state: Arc::new(SamplingState {
                counter: AtomicU64::new(0),
                window_start: AtomicU64::new(0),
            }),
            window_ticks,
        }
    }
}

impl<H: Handler + Clone + 'static> Handler for Sampling<H> {
    fn enabled(&self, ctx: &Context<'_>) -> bool {
        self.inner.enabled(ctx)
    }

    fn handle(&self, record: &std::sync::Arc<OwnedRecord>) -> Result<(), Error> {
        if matches!(record.level, Level::Error | Level::Audit(_)) {
            return self.inner.handle(record);
        }

        let count = self.state.counter.fetch_add(1, Ordering::Relaxed);
        let window_start = self.state.window_start.load(Ordering::Relaxed);
        let local_count = count.saturating_sub(window_start);

        if local_count >= self.window_ticks && count > 0 {
            self.state.counter.store(1, Ordering::Relaxed);
            self.state.window_start.store(count, Ordering::Relaxed);
            return self.inner.handle(record);
        }

        if local_count < self.initial {
            return self.inner.handle(record);
        }
        if local_count
            .saturating_sub(self.initial)
            .is_multiple_of(self.thereafter)
        {
            return self.inner.handle(record);
        }

        Ok(())
    }

    fn clone_box(&self) -> Box<dyn Handler> {
        Box::new(Self {
            inner: self.inner.clone(),
            initial: self.initial,
            thereafter: self.thereafter,
            state: Arc::clone(&self.state),
            window_ticks: self.window_ticks,
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
    use super::*;
    use crate::arc_record;
    use crate::testing::Mock;

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

    #[test]
    fn clone_box_shares_counter() {
        let mock = Mock::new();
        // initial=0, thereafter=100: records at local_count 0, 100, 200... pass
        let s1 = Sampling::new(mock.clone(), 0, 100, 10000);
        // Record 0 (counter=0, local=0): 0.is_multiple_of(100) = true → passes
        // Records 1-49: not multiples of 100 → sampled out
        for _ in 0..50 {
            let _ = s1.handle(&arc_record(Level::Info, "s1"));
        }
        assert_eq!(mock.count(), 1, "only counter=0 passes in first 50");

        // Clone shares counter via Arc — counter is now at 50
        let s2 = s1.clone_box();
        // If clone had reset counter, the next record would have counter=0 → passes.
        // With shared counter, counter continues from 50.
        for _ in 0..49 {
            let _ = s2.handle(&arc_record(Level::Info, "s2"));
        }
        assert_eq!(mock.count(), 1, "counter shared, no new pass at 50..98");

        // counter=99 → local=99, not multiple of 100
        let _ = s2.handle(&arc_record(Level::Info, "99"));
        assert_eq!(mock.count(), 1);

        // counter=100 → local=100, 100.is_multiple_of(100) → passes
        let _ = s2.handle(&arc_record(Level::Info, "100th"));
        assert_eq!(mock.count(), 2, "100th record passes via shared counter");
    }
}
