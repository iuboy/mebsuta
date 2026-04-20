use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::{Arc, Mutex};

use crate::error::Error;
use crate::handler::{Handler, Middleware};
use crate::record::{Context, OwnedRecord};

const DEFAULT_BUFFER_SIZE: usize = 256;

/// Async decorator: delegates log writes to a background worker thread.
///
/// Uses an mpsc sync channel. When the buffer is full, records are dropped
/// and counted via `dropped()`. Call `close()` (or drop) to drain gracefully.
pub struct Async<H: Handler + Clone + 'static> {
    inner: H,
    tx: Mutex<Option<SyncSender<Arc<OwnedRecord>>>>,
    closed: AtomicBool,
    dropped: AtomicI64,
    worker: Mutex<Option<std::thread::JoinHandle<()>>>,
}

impl<H: Handler + Clone + 'static> Async<H> {
    pub fn new(inner: H) -> Self {
        Self::with_buffer_size(inner, DEFAULT_BUFFER_SIZE)
    }

    pub fn with_buffer_size(inner: H, buffer_size: usize) -> Self {
        let (tx, rx): (SyncSender<Arc<OwnedRecord>>, Receiver<Arc<OwnedRecord>>) =
            mpsc::sync_channel(buffer_size);

        let inner_clone = inner.clone();
        let handle = std::thread::Builder::new()
            .name("mebsuta-async-worker".to_owned())
            .spawn(move || {
                for record in rx.iter() {
                    let _ = inner_clone.handle(&record);
                }
            })
            .expect("failed to spawn async worker thread");

        Async {
            inner,
            tx: Mutex::new(Some(tx)),
            closed: AtomicBool::new(false),
            dropped: AtomicI64::new(0),
            worker: Mutex::new(Some(handle)),
        }
    }

    pub fn dropped(&self) -> i64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

impl<H: Handler + Clone + 'static> Handler for Async<H> {
    fn enabled(&self, ctx: &Context<'_>) -> bool {
        self.inner.enabled(ctx)
    }

    fn handle(&self, record: &Arc<OwnedRecord>) -> Result<(), Error> {
        if self.closed.load(Ordering::Relaxed) {
            return Ok(());
        }

        let tx = self.tx.lock().unwrap();
        let Some(tx) = tx.as_ref() else {
            return Ok(());
        };

        match tx.try_send(Arc::clone(record)) {
            Ok(()) => Ok(()),
            Err(mpsc::TrySendError::Full(_)) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            Err(mpsc::TrySendError::Disconnected(_)) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
        }
    }

    fn clone_box(&self) -> Box<dyn Handler> {
        Box::new(Async {
            inner: self.inner.clone(),
            tx: Mutex::new(self.tx.lock().unwrap().clone()),
            closed: AtomicBool::new(false),
            dropped: AtomicI64::new(0),
            worker: Mutex::new(None),
        })
    }

    fn set_error_handler(&self, handler: Option<Box<dyn Fn(&str, &Error) + Send + Sync>>) {
        self.inner.set_error_handler(handler);
    }

    fn flush(&self) {
        std::thread::yield_now();
        self.inner.flush();
    }

    fn close_if_needed(&mut self) -> Option<Result<(), Error>> {
        if self
            .closed
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Some(Ok(()));
        }

        // Drop sender to signal worker to drain and exit
        self.tx.lock().unwrap().take();

        // Wait for worker to finish
        if let Some(handle) = self.worker.lock().unwrap().take() {
            let _ = handle.join();
        }

        Some(Ok(()))
    }
}

impl<H: Handler + Clone + 'static> Drop for Async<H> {
    fn drop(&mut self) {
        if !self.closed.load(Ordering::Relaxed) {
            self.closed.store(true, Ordering::Relaxed);
        }
        self.tx.lock().unwrap().take();
        if let Some(handle) = self.worker.lock().unwrap().take() {
            let _ = handle.join();
        }
    }
}

impl<H: Handler + Clone + 'static> Middleware<H> for Async<H> {
    fn inner(&self) -> &H {
        &self.inner
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

    use super::*;
    use crate::arc_record;
    use crate::level::Level;

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
        fn enabled(&self, _ctx: &crate::record::Context<'_>) -> bool {
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

    #[test]
    fn async_writes_all_records() {
        let mock = Mock::new();
        let mut async_h = Async::new(mock.clone());
        for i in 0..10 {
            let r = arc_record(Level::Info, format!("msg {i}"));
            async_h.handle(&r).unwrap();
        }
        // Close drains the channel and waits for worker
        async_h.close_if_needed();
        assert_eq!(mock.count(), 10);
    }

    #[test]
    fn async_channel_full_drops() {
        let mock = Mock::new();
        let async_h = Async::with_buffer_size(mock.clone(), 2);
        for i in 0..100 {
            let r = arc_record(Level::Info, format!("msg {i}"));
            let _ = async_h.handle(&r);
        }
        assert!(
            async_h.dropped() > 0,
            "Expected drops, got {}",
            async_h.dropped()
        );
    }

    #[test]
    fn async_close_is_idempotent() {
        let mock = Mock::new();
        let mut h = Async::new(mock.clone());
        h.close_if_needed();
        h.close_if_needed();
    }
}
