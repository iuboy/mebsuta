use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::mpsc::{self, SyncSender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::error::Error;
use crate::handler::{Handler, Middleware, recover_lock};
use crate::level::Level;
use crate::record::{Context, OwnedRecord};

const DEFAULT_BUFFER_SIZE: usize = 256;
const BLOCKING_SEND_TIMEOUT: Duration = Duration::from_secs(5);

enum AsyncMessage {
    Record(Arc<OwnedRecord>),
    Flush(std::sync::mpsc::Sender<()>),
}

struct AsyncInner<H: Handler + Clone + 'static> {
    inner: H,
    tx: Mutex<Option<SyncSender<AsyncMessage>>>,
    closed: AtomicBool,
    dropped: AtomicI64,
    worker: Mutex<Option<std::thread::JoinHandle<()>>>,
}

/// Async decorator: delegates log writes to a background worker thread.
///
/// Uses an mpsc sync channel. When the buffer is full, records are dropped
/// and counted via `dropped()`. Call `close()` (or drop) to drain gracefully.
/// `flush()` sends a barrier through the channel and waits for the worker to
/// process all pending records before returning.
///
/// Clones share the same channel and worker thread via `Arc`.
pub struct Async<H: Handler + Clone + 'static> {
    shared: Arc<AsyncInner<H>>,
}

impl<H: Handler + Clone + 'static> Async<H> {
    pub fn new(inner: H) -> Self {
        Self::with_buffer_size(inner, DEFAULT_BUFFER_SIZE)
    }

    pub fn with_buffer_size(inner: H, buffer_size: usize) -> Self {
        // SPEC: reject double-buffering (Async → Syslog/Database)
        assert!(
            !is_self_buffered(&inner),
            "mebsuta: Async cannot wrap a self-buffered handler (Syslog or Database). \
             These handlers maintain their own internal buffer; wrapping in Async \
             creates double-buffering and can lose records during close."
        );

        let (tx, rx) = mpsc::sync_channel(buffer_size);

        let inner_clone = inner.clone();
        let handle = std::thread::Builder::new()
            .name("mebsuta-async-worker".to_owned())
            .spawn(move || {
                for msg in rx.iter() {
                    match msg {
                        AsyncMessage::Record(record) => {
                            let _ = inner_clone.handle(&record);
                        }
                        AsyncMessage::Flush(ack) => {
                            inner_clone.flush();
                            let _ = ack.send(());
                        }
                    }
                }
            })
            .expect("failed to spawn async worker thread");

        Async {
            shared: Arc::new(AsyncInner {
                inner,
                tx: Mutex::new(Some(tx)),
                closed: AtomicBool::new(false),
                dropped: AtomicI64::new(0),
                worker: Mutex::new(Some(handle)),
            }),
        }
    }

    pub fn dropped(&self) -> i64 {
        self.shared.dropped.load(Ordering::Relaxed)
    }
}

impl<H: Handler + Clone + 'static> Handler for Async<H> {
    fn enabled(&self, ctx: &Context<'_>) -> bool {
        self.shared.inner.enabled(ctx)
    }

    fn handle(&self, record: &Arc<OwnedRecord>) -> Result<(), Error> {
        if self.shared.closed.load(Ordering::Relaxed) {
            return Ok(());
        }

        let tx = recover_lock(&self.shared.tx);
        let Some(tx) = tx.as_ref() else {
            return Ok(());
        };

        let msg = AsyncMessage::Record(Arc::clone(record));

        if record.level.severity() >= Level::Error.severity() {
            // Error/Audit: blocking send with timeout, never silently drop
            let deadline = Instant::now() + BLOCKING_SEND_TIMEOUT;
            let mut msg = Some(msg);
            loop {
                match tx.try_send(msg.take().unwrap()) {
                    Ok(()) => return Ok(()),
                    Err(mpsc::TrySendError::Full(m)) => {
                        if Instant::now() >= deadline {
                            self.shared.dropped.fetch_add(1, Ordering::Relaxed);
                            return Ok(());
                        }
                        msg = Some(m);
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(mpsc::TrySendError::Disconnected(_)) => {
                        self.shared.dropped.fetch_add(1, Ordering::Relaxed);
                        return Ok(());
                    }
                }
            }
        } else {
            match tx.try_send(msg) {
                Ok(()) => Ok(()),
                Err(mpsc::TrySendError::Full(_)) => {
                    self.shared.dropped.fetch_add(1, Ordering::Relaxed);
                    Ok(())
                }
                Err(mpsc::TrySendError::Disconnected(_)) => {
                    self.shared.dropped.fetch_add(1, Ordering::Relaxed);
                    Ok(())
                }
            }
        }
    }

    fn clone_box(&self) -> Box<dyn Handler> {
        Box::new(Async {
            shared: Arc::clone(&self.shared),
        })
    }

    fn set_error_handler(&self, handler: Option<Box<dyn Fn(&str, &Error) + Send + Sync>>) {
        self.shared.inner.set_error_handler(handler);
    }

    fn flush(&self) {
        if self.shared.closed.load(Ordering::Relaxed) {
            return;
        }
        let (ack_tx, ack_rx) = mpsc::channel();
        let tx = recover_lock(&self.shared.tx);
        let Some(tx) = tx.as_ref() else {
            return;
        };
        // Best-effort: if channel is full, yield and let worker drain naturally
        match tx.try_send(AsyncMessage::Flush(ack_tx)) {
            Ok(()) => {
                let _ = tx;
                let _ = ack_rx.recv();
            }
            Err(_) => {
                let _ = tx;
                std::thread::yield_now();
                self.shared.inner.flush();
            }
        }
    }

    fn close_if_needed(&mut self) -> Option<Result<(), Error>> {
        if Arc::strong_count(&self.shared) > 1 {
            return None;
        }

        if self
            .shared
            .closed
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Some(Ok(()));
        }

        recover_lock(&self.shared.tx).take();

        if let Some(handle) = recover_lock(&self.shared.worker).take() {
            let _ = handle.join();
        }

        Some(Ok(()))
    }
}

impl<H: Handler + Clone + 'static> Drop for Async<H> {
    fn drop(&mut self) {
        if Arc::strong_count(&self.shared) > 1 {
            return;
        }
        if let Some(result) = self.close_if_needed() {
            let _ = result;
        }
    }
}

impl<H: Handler + Clone + 'static> Middleware<H> for Async<H> {
    fn inner(&self) -> &H {
        &self.shared.inner
    }
}

/// Runtime check for self-buffered inner handlers.
/// Uses Any type checking to detect SyslogHandler and DatabaseHandler at runtime,
/// since the Handler trait doesn't expose type information through generics.
fn is_self_buffered<H: Handler + 'static>(handler: &H) -> bool {
    use std::any::Any;
    let any: &dyn Any = handler;
    // Check common wrapper types that might contain a self-buffered inner
    any.is::<crate::syslog::SyslogHandler>()
        || any.is::<crate::database::DatabaseHandler>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arc_record;
    use crate::level::Level;
    use crate::testing::Mock;

    #[test]
    fn async_writes_all_records() {
        let mock = Mock::new();
        let mut async_h = Async::new(mock.clone());
        for i in 0..10 {
            let r = arc_record(Level::Info, format!("msg {i}"));
            async_h.handle(&r).unwrap();
        }
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

    #[test]
    fn async_clone_shares_worker() {
        let mock = Mock::new();
        let mut h1 = Async::new(mock.clone());
        let h2 = h1.clone_box();
        let r = arc_record(Level::Info, "from clone");
        h2.handle(&r).unwrap();
        drop(h2);
        h1.close_if_needed();
        assert_eq!(mock.count(), 1);
    }

    #[test]
    fn async_clone_does_not_close_worker() {
        let mock = Mock::new();
        let mut h1 = Async::new(mock.clone());
        let h2 = h1.clone_box();
        drop(h2);
        let r = arc_record(Level::Info, "after clone drop");
        h1.handle(&r).unwrap();
        h1.close_if_needed();
        assert_eq!(mock.count(), 1);
    }

    #[test]
    fn async_flush_drains_channel() {
        let mock = Mock::new();
        let mut h = Async::new(mock.clone());
        for i in 0..10 {
            let r = arc_record(Level::Info, format!("msg {i}"));
            h.handle(&r).unwrap();
        }
        h.flush();
        assert_eq!(mock.count(), 10);
        h.close_if_needed();
    }

    #[test]
    fn async_closed_ignores_writes() {
        let mock = Mock::new();
        let mut h = Async::new(mock.clone());
        h.close_if_needed();
        let r = arc_record(Level::Info, "after close");
        h.handle(&r).unwrap();
        assert_eq!(mock.count(), 0);
    }

    #[test]
    fn async_error_record_not_dropped_on_full_buffer() {
        use crate::record::EventType;

        let mock = Mock::new();
        let mut async_h = Async::with_buffer_size(mock.clone(), 1);

        // Fill the buffer with info records so it's at capacity
        for _ in 0..10 {
            let r = arc_record(Level::Info, "filler");
            let _ = async_h.handle(&r);
        }

        // Error and Audit records should still be delivered (blocking send)
        let err = arc_record(Level::Error, "error msg");
        async_h.handle(&err).unwrap();

        let audit = arc_record(Level::Audit(EventType::Login), "audit msg");
        async_h.handle(&audit).unwrap();

        async_h.close_if_needed();

        let total = mock.count();
        assert!(
            total >= 2,
            "Error/Audit records must not be dropped, got {total} records"
        );
    }
}
