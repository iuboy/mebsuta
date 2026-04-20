use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::{Arc, Mutex};

use crate::error::Error;
use crate::handler::{Close, ErrorHandler, Handler, Terminal};
use crate::level::Level;
use crate::record::{Context, OwnedRecord};
const DEFAULT_BATCH_SIZE: usize = 100;
const DEFAULT_BATCH_INTERVAL_SECS: u64 = 5;
const FLUSH_RETRIES: usize = 3;

/// Configuration for DatabaseHandler.
#[derive(Debug, Clone)]
pub struct DatabaseConfig {
    pub path: String,
    pub table: String,
    pub batch_size: usize,
    pub batch_interval_secs: u64,
    pub retry_delay_ms: u64,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        DatabaseConfig {
            path: ":memory:".to_owned(),
            table: "logs".to_owned(),
            batch_size: DEFAULT_BATCH_SIZE,
            batch_interval_secs: DEFAULT_BATCH_INTERVAL_SECS,
            retry_delay_ms: 500,
        }
    }
}

/// Handler that writes log records to a SQLite database in batches.
pub struct DatabaseHandler {
    level: Level,
    config: DatabaseConfig,
    conn: Mutex<Option<rusqlite::Connection>>,
    tx: Mutex<Option<SyncSender<LogEntry>>>,
    closed: AtomicBool,
    dropped: AtomicI64,
    error_handler: ErrorHandler,
    worker: Mutex<Option<std::thread::JoinHandle<()>>>,
}

struct LogEntry {
    time: String,
    level: String,
    message: String,
    fields: String,
}

impl DatabaseHandler {
    pub fn new(level: Level, config: DatabaseConfig) -> Result<Self, Error> {
        let conn = rusqlite::Connection::open(&config.path)?;
        let table = &config.table;
        conn.execute_batch(&format!(
            "CREATE TABLE IF NOT EXISTS {table} (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                time TEXT NOT NULL,
                level TEXT NOT NULL,
                message TEXT NOT NULL,
                fields TEXT NOT NULL DEFAULT '{{}}'
            )"
        ))?;

        let batch_size = config.batch_size;
        let batch_interval = config.batch_interval_secs;
        let retry_delay = config.retry_delay_ms;
        let table_name = config.table.clone();

        let (tx, rx): (SyncSender<LogEntry>, Receiver<LogEntry>) =
            mpsc::sync_channel(batch_size * 10);

        let db_path = config.path.clone();
        let worker = std::thread::Builder::new()
            .name("mebsuta-db-worker".to_owned())
            .spawn(move || {
                run_worker(rx, &db_path, &table_name, batch_size, batch_interval, retry_delay);
            })
            .expect("failed to spawn database worker thread");

        Ok(DatabaseHandler {
            level,
            config,
            conn: Mutex::new(Some(conn)),
            tx: Mutex::new(Some(tx)),
            closed: AtomicBool::new(false),
            dropped: AtomicI64::new(0),
            error_handler: Arc::new(std::sync::Mutex::new(None)),
            worker: Mutex::new(Some(worker)),
        })
    }

    pub fn dropped(&self) -> i64 {
        self.dropped.load(Ordering::Relaxed)
    }

    fn record_to_entry(record: &OwnedRecord) -> LogEntry {
        let fields = if record.attrs.is_empty() {
            "{}".to_owned()
        } else {
            let mut parts = Vec::new();
            for (k, v) in &record.attrs {
                parts.push(format!(
                    "\"{}\":{}",
                    crate::value::escape_json(k.as_str()),
                    crate::value::value_to_json(v)
                ));
            }
            format!("{{{}}}", parts.join(","))
        };

        LogEntry {
            time: format!("{:?}", record.time),
            level: record.level.to_string(),
            message: record.message.clone(),
            fields,
        }
    }

    #[expect(dead_code)]
    fn call_error_handler(&self, component: &str, err: &Error) {
        if let Some(ref eh) = *self.error_handler.lock().unwrap() {
            eh(component, err);
        }
    }
}

fn run_worker(
    rx: Receiver<LogEntry>,
    db_path: &str,
    table: &str,
    batch_size: usize,
    batch_interval_secs: u64,
    retry_delay_ms: u64,
) {
    let conn = match rusqlite::Connection::open(db_path) {
        Ok(c) => c,
        Err(_) => return,
    };

    let mut batch: Vec<LogEntry> = Vec::with_capacity(batch_size);

    loop {
        let timeout = std::time::Duration::from_secs(batch_interval_secs);

        match rx.recv_timeout(timeout) {
            Ok(entry) => {
                batch.push(entry);
                if batch.len() >= batch_size {
                    flush_batch(&conn, table, &batch, retry_delay_ms);
                    batch.clear();
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if !batch.is_empty() {
                    flush_batch(&conn, table, &batch, retry_delay_ms);
                    batch.clear();
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                if !batch.is_empty() {
                    flush_batch(&conn, table, &batch, retry_delay_ms);
                }
                return;
            }
        }
    }
}

fn flush_batch(conn: &rusqlite::Connection, table: &str, batch: &[LogEntry], retry_delay_ms: u64) {
    for attempt in 0..FLUSH_RETRIES {
        match insert_batch(conn, table, batch) {
            Ok(()) => return,
            Err(_) if attempt < FLUSH_RETRIES - 1 => {
                std::thread::sleep(std::time::Duration::from_millis(retry_delay_ms));
            }
            Err(_) => return,
        }
    }
}

fn insert_batch(
    conn: &rusqlite::Connection,
    table: &str,
    batch: &[LogEntry],
) -> Result<(), Error> {
    let sql = format!("INSERT INTO {table} (time, level, message, fields) VALUES (?, ?, ?, ?)");
    // Use a transaction for batch insert
    let tx = conn.unchecked_transaction()?;
    {
        let mut stmt = tx.prepare(&sql)?;
        for entry in batch {
            stmt.execute(rusqlite::params![entry.time, entry.level, entry.message, entry.fields])?;
        }
    }
    tx.commit()?;
    Ok(())
}

impl Handler for DatabaseHandler {
    fn enabled(&self, ctx: &Context<'_>) -> bool {
        ctx.level >= self.level
    }

    fn handle(&self, record: &Arc<OwnedRecord>) -> Result<(), Error> {
        if self.closed.load(Ordering::Relaxed) {
            return Ok(());
        }

        let tx = self.tx.lock().unwrap();
        let Some(tx) = tx.as_ref() else {
            return Ok(());
        };

        let entry = Self::record_to_entry(record);
        match tx.try_send(entry) {
            Ok(()) => Ok(()),
            Err(_) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
        }
    }

    fn clone_box(&self) -> Box<dyn Handler> {
        Box::new(DatabaseHandler {
            level: self.level,
            config: self.config.clone(),
            conn: Mutex::new(None),
            tx: Mutex::new(None),
            closed: AtomicBool::new(true),
            dropped: AtomicI64::new(0),
            error_handler: Arc::clone(&self.error_handler),
            worker: Mutex::new(None),
        })
    }

    fn set_error_handler(&self, handler: Option<Box<dyn Fn(&str, &Error) + Send + Sync>>) {
        *self.error_handler.lock().unwrap() = handler;
    }

    fn flush(&self) {
        // Wake up the worker by sending a batch-interval worth of sleep
        // The worker's recv_timeout will expire and flush
        std::thread::yield_now();
    }

    fn close_if_needed(&mut self) -> Option<Result<(), Error>> {
        Some(self.close())
    }
}

impl Close for DatabaseHandler {
    fn close(&mut self) -> Result<(), Error> {
        if self
            .closed
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Ok(());
        }

        // Drop sender to signal worker to drain and exit
        self.tx.lock().unwrap().take();

        // Wait for worker to finish
        if let Some(handle) = self.worker.lock().unwrap().take() {
            let _ = handle.join();
        }

        // Close connection
        if let Some(conn) = self.conn.lock().unwrap().take() {
            let _ = conn.close();
        }
        Ok(())
    }
}

impl Terminal for DatabaseHandler {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arc_record;

    fn temp_db_path(name: &str) -> String {
        let dir = std::env::temp_dir().join("mebsuta_test_db");
        let _ = std::fs::create_dir_all(&dir);
        dir.join(format!("{name}.db")).to_string_lossy().to_string()
    }

    fn cleanup_db(path: &str) {
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn database_writes_records() {
        let path = temp_db_path("writes_records");
        let _ = std::fs::remove_file(&path);

        let config = DatabaseConfig {
            path: path.clone(),
            batch_size: 10,
            batch_interval_secs: 1,
            ..DatabaseConfig::default()
        };
        let mut h = DatabaseHandler::new(Level::Info, config).unwrap();

        for i in 0..15 {
            let r = arc_record(Level::Info, format!("msg {i}"));
            h.handle(&r).unwrap();
        }

        h.close().unwrap();

        // Verify records in database
        let conn = rusqlite::Connection::open(&path).unwrap();
        let count: i64 = conn.query_row("SELECT COUNT(*) FROM logs", [], |row| row.get(0)).unwrap();
        assert_eq!(count, 15);

        let msg: String = conn
            .query_row("SELECT message FROM logs WHERE id = 1", [], |row| row.get(0))
            .unwrap();
        assert_eq!(msg, "msg 0");

        cleanup_db(&path);
    }

    #[test]
    fn database_level_filter() {
        let path = temp_db_path("level_filter");
        let _ = std::fs::remove_file(&path);

        let config = DatabaseConfig {
            path: path.clone(),
            batch_size: 10,
            batch_interval_secs: 1,
            ..DatabaseConfig::default()
        };
        let h = DatabaseHandler::new(Level::Warn, config).unwrap();

        assert!(!h.enabled(&Context::new(Level::Debug)));
        assert!(h.enabled(&Context::new(Level::Warn)));
        assert!(h.enabled(&Context::new(Level::Error)));

        drop(h);
        cleanup_db(&path);
    }

    #[test]
    fn database_close_idempotent() {
        let config = DatabaseConfig::default();
        let mut h = DatabaseHandler::new(Level::Info, config).unwrap();
        h.close().unwrap();
        h.close().unwrap();
    }

    #[test]
    fn database_closed_ignores_writes() {
        let config = DatabaseConfig::default();
        let mut h = DatabaseHandler::new(Level::Info, config).unwrap();
        h.close().unwrap();

        let r = arc_record(Level::Info, "after close");
        h.handle(&r).unwrap(); // Should silently skip
    }
}
