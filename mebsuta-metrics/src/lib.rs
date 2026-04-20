//! Prometheus metrics decorator for mebsuta.
//!
//! `Metrics<H>` wraps any handler and counts total/filtered/error records.

use std::sync::Arc;

use mebsuta::{Context, Error, Handler, Middleware, OwnedRecord};
use prometheus::{IntCounter, Opts, Registry};

/// Metrics counters collected from the handler pipeline.
#[derive(Clone)]
pub struct MetricsCounters {
    total: IntCounter,
    filtered: IntCounter,
    errors: IntCounter,
}

impl MetricsCounters {
    pub fn new(name_prefix: &str, registry: &Registry) -> Result<Self, prometheus::Error> {
        let total = IntCounter::with_opts(Opts::new(
            format!("{name_prefix}_log_writes_total"),
            "Total log records passed to handle()",
        ))?;
        let filtered = IntCounter::with_opts(Opts::new(
            format!("{name_prefix}_log_filtered_total"),
            "Records skipped by enabled() check",
        ))?;
        let errors = IntCounter::with_opts(Opts::new(
            format!("{name_prefix}_log_errors_total"),
            "Records that caused handle errors",
        ))?;
        registry.register(Box::new(total.clone()))?;
        registry.register(Box::new(filtered.clone()))?;
        registry.register(Box::new(errors.clone()))?;
        Ok(MetricsCounters {
            total,
            filtered,
            errors,
        })
    }

    pub fn total(&self) -> u64 {
        self.total.get()
    }

    pub fn filtered(&self) -> u64 {
        self.filtered.get()
    }

    pub fn errors(&self) -> u64 {
        self.errors.get()
    }
}

/// Metrics decorator. Counts records passing through and delegates to inner handler.
pub struct Metrics<H> {
    inner: H,
    counters: MetricsCounters,
}

impl<H> Metrics<H> {
    pub fn new(inner: H, counters: MetricsCounters) -> Self {
        Metrics { inner, counters }
    }
}

impl<H: Handler + Clone + 'static> Handler for Metrics<H> {
    fn enabled(&self, ctx: &Context<'_>) -> bool {
        self.inner.enabled(ctx)
    }

    fn handle(&self, record: &Arc<OwnedRecord>) -> Result<(), Error> {
        self.counters.total.inc();

        let ctx = Context::new(record.level);
        if !self.inner.enabled(&ctx) {
            self.counters.filtered.inc();
            return Ok(());
        }

        match self.inner.handle(record) {
            Ok(()) => Ok(()),
            Err(e) => {
                self.counters.errors.inc();
                Err(e)
            }
        }
    }

    fn clone_box(&self) -> Box<dyn Handler> {
        Box::new(Metrics {
            inner: self.inner.clone(),
            counters: self.counters.clone(),
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

impl<H: Handler + Clone + 'static> Middleware<H> for Metrics<H> {
    fn inner(&self) -> &H {
        &self.inner
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

    use super::*;
    use mebsuta::{Level, arc_record};

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
        fn set_error_handler(&self, _: Option<Box<dyn Fn(&str, &Error) + Send + Sync>>) {}
    }

    fn make_counters() -> MetricsCounters {
        let registry = Registry::new();
        MetricsCounters::new("test", &registry).unwrap()
    }

    #[test]
    fn counts_total() {
        let mock = Mock::new();
        let counters = make_counters();
        let metrics = Metrics::new(mock.clone(), counters.clone());

        for _ in 0..5 {
            let r = arc_record(Level::Info, "msg");
            metrics.handle(&r).unwrap();
        }
        assert_eq!(counters.total(), 5);
        assert_eq!(counters.filtered(), 0);
        assert_eq!(counters.errors(), 0);
    }

    #[test]
    fn counts_filtered() {
        let inner = mebsuta::StdoutHandler::new(Level::Warn, mebsuta::Format::Json);
        let counters = make_counters();
        let metrics = Metrics::new(inner, counters.clone());

        let r = arc_record(Level::Debug, "filtered");
        metrics.handle(&r).unwrap();

        assert_eq!(counters.total(), 1);
        assert_eq!(counters.filtered(), 1);
    }
}
