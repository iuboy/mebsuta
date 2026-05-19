use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};

use mebsuta::{
    Async, Context, Error, Format, Handler, Level, MultiHandler, Sampling, StdoutHandler,
    arc_record,
};

/// No-op handler for benchmarking without I/O overhead.
#[derive(Clone)]
struct NullHandler {
    count: Arc<AtomicUsize>,
}

impl NullHandler {
    fn new() -> Self {
        NullHandler {
            count: Arc::new(AtomicUsize::new(0)),
        }
    }
}

impl Handler for NullHandler {
    fn enabled(&self, _ctx: &Context<'_>) -> bool {
        true
    }
    fn handle(&self, _record: &std::sync::Arc<mebsuta::OwnedRecord>) -> Result<(), Error> {
        self.count.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
    fn clone_box(&self) -> Box<dyn Handler> {
        Box::new(self.clone())
    }
    fn set_error_handler(&self, _: Option<Box<dyn Fn(&str, &Error) + Send + Sync>>) {}
}

fn bench_stdout_json(c: &mut Criterion) {
    let handler = StdoutHandler::new(Level::Info, Format::Json);
    let r = arc_record(Level::Info, "benchmark message");

    c.bench_function("stdout_json", |b| {
        b.iter(|| {
            handler.handle(black_box(&r)).unwrap();
        })
    });
}

fn bench_stdout_text(c: &mut Criterion) {
    let handler = StdoutHandler::new(Level::Info, Format::Text);
    let r = arc_record(Level::Info, "benchmark message");

    c.bench_function("stdout_text", |b| {
        b.iter(|| {
            handler.handle(black_box(&r)).unwrap();
        })
    });
}

fn bench_null_baseline(c: &mut Criterion) {
    let handler = NullHandler::new();
    let r = arc_record(Level::Info, "benchmark");

    c.bench_function("null_handler", |b| {
        b.iter(|| {
            handler.handle(black_box(&r)).unwrap();
        })
    });
}

fn bench_sampling_pass(c: &mut Criterion) {
    let inner = NullHandler::new();
    let sampling = Sampling::new(inner, 1_000_000, 1, 1_000_000);
    let r = arc_record(Level::Info, "benchmark");

    c.bench_function("sampling_pass", |b| {
        b.iter(|| {
            sampling.handle(black_box(&r)).unwrap();
        })
    });
}

fn bench_sampling_drop(c: &mut Criterion) {
    let inner = NullHandler::new();
    let sampling = Sampling::new(inner, 1, 1_000_000, 1_000_000);
    let r = arc_record(Level::Info, "benchmark");

    c.bench_function("sampling_drop", |b| {
        b.iter(|| {
            sampling.handle(black_box(&r)).unwrap();
        })
    });
}

fn bench_async(c: &mut Criterion) {
    let inner = NullHandler::new();
    let async_h = Async::new(inner);
    let r = arc_record(Level::Info, "benchmark async");

    c.bench_function("async_handle", |b| {
        b.iter(|| {
            async_h.handle(black_box(&r)).unwrap();
        })
    });
}

fn bench_multi(c: &mut Criterion) {
    let mut group = c.benchmark_group("multi_handler");

    for count in [2usize, 4] {
        let handlers: Vec<Box<dyn Handler>> = (0..count)
            .map(|_| Box::new(NullHandler::new()) as Box<dyn Handler>)
            .collect();
        let multi = MultiHandler::new(handlers);
        let r = arc_record(Level::Info, "benchmark multi");

        group.bench_with_input(BenchmarkId::from_parameter(count), &count, |b, _| {
            b.iter(|| {
                multi.handle(black_box(&r)).unwrap();
            })
        });
    }
    group.finish();
}

fn bench_with_attrs(c: &mut Criterion) {
    let handler = StdoutHandler::new(Level::Info, Format::Json);
    let with_attrs = handler.with_attrs(vec![
        ("service".into(), "bench".into()),
        ("version".into(), "1.0.0".into()),
    ]);
    let r = arc_record(Level::Info, "benchmark");

    c.bench_function("with_attrs", |b| {
        b.iter(|| {
            with_attrs.handle(black_box(&r)).unwrap();
        })
    });
}

criterion_group!(
    benches,
    bench_null_baseline,
    bench_stdout_json,
    bench_stdout_text,
    bench_sampling_pass,
    bench_sampling_drop,
    bench_async,
    bench_multi,
    bench_with_attrs,
);
criterion_main!(benches);
