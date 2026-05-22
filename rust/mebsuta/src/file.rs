use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use crate::error::Error;
use crate::handler::{Close, ErrorHandler, Handler, Terminal, call_error_handler, recover_lock};
use crate::level::Level;
use crate::record::{Context, OwnedRecord};
use crate::stdout::{Format, format_json, format_text};
use crate::time::{backup_timestamp, now_secs};

pub(crate) const DEFAULT_MAX_FILE_SIZE_BYTES: u64 = 100 * 1024 * 1024;

/// File rotation configuration.
#[derive(Debug, Clone)]
pub struct RotationConfig {
    pub max_size_bytes: u64,
    pub rotate_interval_secs: u64,
    pub max_backups: usize,
    pub max_age_days: u32,
    pub compress: bool,
}

impl Default for RotationConfig {
    fn default() -> Self {
        RotationConfig {
            max_size_bytes: DEFAULT_MAX_FILE_SIZE_BYTES,
            rotate_interval_secs: 0,
            max_backups: 0,
            max_age_days: 0,
            compress: false,
        }
    }
}

/// Restrict log file permissions to owner-only (0o600) on Unix.
fn restrict_file_permissions(file: &File) {
    #[cfg(unix)]
    {
        let _ = file.set_permissions(std::fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    {
        let _ = file;
    }
}

/// Handler that writes log records to a file with optional rotation.
pub struct FileHandler {
    level: Level,
    format: Format,
    state: Arc<FileState>,
    error_handler: ErrorHandler,
}

struct FileState {
    path: PathBuf,
    writer: Mutex<BufWriter<File>>,
    size: AtomicI64,
    rotated_at: AtomicU64,
    closed: AtomicBool,
    rotation: RotationConfig,
    compress_wg: Mutex<Vec<std::thread::JoinHandle<()>>>,
}

impl FileHandler {
    pub fn new(path: impl Into<PathBuf>, level: Level, format: Format) -> Result<Self, Error> {
        Self::with_rotation(path, level, format, RotationConfig::default())
    }

    pub fn with_rotation(
        path: impl Into<PathBuf>,
        level: Level,
        format: Format,
        rotation: RotationConfig,
    ) -> Result<Self, Error> {
        let path = path.into();

        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)?;
        }

        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        restrict_file_permissions(&file);

        let size = file.metadata()?.len() as i64;

        let state = Arc::new(FileState {
            path,
            writer: Mutex::new(BufWriter::new(file)),
            size: AtomicI64::new(size),
            rotated_at: AtomicU64::new(now_secs()),
            closed: AtomicBool::new(false),
            rotation,
            compress_wg: Mutex::new(Vec::new()),
        });

        Ok(FileHandler {
            level,
            format,
            state,
            error_handler: Arc::new(Mutex::new(None)),
        })
    }

    fn write_record(&self, record: &std::sync::Arc<OwnedRecord>) -> Result<(), Error> {
        let output = match self.format {
            Format::Json => format_json(record),
            Format::Text => format_text(record),
        };

        let mut writer = recover_lock(&self.state.writer);
        let bytes = output.as_bytes();
        if let Err(e) = writer.write_all(bytes) {
            if matches!(record.level, Level::Error | Level::Audit(_)) {
                eprintln!(
                    "mebsuta: file write failed for {:?} record: {}",
                    record.level, e
                );
            }
            call_error_handler(&self.error_handler, "file", &Error::Io(e));
            return Ok(());
        }
        if let Err(e) = writer.write_all(b"\n") {
            call_error_handler(&self.error_handler, "file", &Error::Io(e));
            return Ok(());
        }
        self.state
            .size
            .fetch_add(bytes.len() as i64 + 1, Ordering::Relaxed);

        Ok(())
    }

    fn needs_rotation(&self) -> bool {
        let cfg = &self.state.rotation;
        if cfg.max_size_bytes > 0
            && self.state.size.load(Ordering::Relaxed) >= cfg.max_size_bytes as i64
        {
            return true;
        }
        if cfg.rotate_interval_secs > 0 {
            let elapsed = now_secs() - self.state.rotated_at.load(Ordering::Relaxed);
            if elapsed >= cfg.rotate_interval_secs {
                return true;
            }
        }
        false
    }

    fn do_rotate(&self) {
        let mut writer = recover_lock(&self.state.writer);
        if self.state.closed.load(Ordering::Relaxed) {
            return;
        }
        if !self.needs_rotation() {
            return;
        }

        let backup = self.backup_name();
        let path = &self.state.path;

        if let Err(e) = writer.get_mut().flush() {
            call_error_handler(&self.error_handler, "file", &Error::Io(e));
        }

        if let Err(e) = writer.get_mut().sync_all() {
            call_error_handler(&self.error_handler, "file", &Error::Io(e));
        }

        if let Err(e) = fs::rename(path, &backup) {
            call_error_handler(&self.error_handler, "file", &Error::from(e));
            return;
        }

        match OpenOptions::new().create(true).append(true).open(path) {
            Ok(new_file) => {
                restrict_file_permissions(&new_file);
                *writer = BufWriter::new(new_file);
                self.state.size.store(0, Ordering::Relaxed);
                self.state.rotated_at.store(now_secs(), Ordering::Relaxed);
            }
            Err(e) => {
                call_error_handler(&self.error_handler, "file", &Error::from(e));
                if let Ok(fallback) = OpenOptions::new().create(true).append(true).open(path) {
                    restrict_file_permissions(&fallback);
                    *writer = BufWriter::new(fallback);
                }
                self.state.rotated_at.store(now_secs(), Ordering::Relaxed);
            }
        }

        if self.state.rotation.compress {
            let backup_path = backup.clone();
            let eh = self.error_handler.clone();
            let handle = std::thread::spawn(move || {
                compress_file(&backup_path, move |e: &Error| {
                    call_error_handler(&eh, "file", e);
                });
            });
            let mut wg = recover_lock(&self.state.compress_wg);
            // Reap finished handles to prevent unbounded growth
            wg.retain(|h| !h.is_finished());
            wg.push(handle);
        }

        self.cleanup_backups();
    }

    fn backup_name(&self) -> PathBuf {
        let now = backup_timestamp();
        let base = format!("{}.{}", self.state.path.display(), now);
        if !Path::new(&base).exists() {
            return PathBuf::from(base);
        }
        for i in 1..1000 {
            let candidate = format!("{}.{}.{}", self.state.path.display(), now, i);
            if !Path::new(&candidate).exists() {
                return PathBuf::from(candidate);
            }
        }
        PathBuf::from(format!("{}.{}", self.state.path.display(), now_secs()))
    }

    fn cleanup_backups(&self) {
        let cfg = &self.state.rotation;
        if cfg.max_backups == 0 && cfg.max_age_days == 0 {
            return;
        }

        let dir = match self.state.path.parent() {
            Some(d) => d,
            None => return,
        };
        let base = match self.state.path.file_name() {
            Some(n) => n.to_string_lossy().to_string(),
            None => return,
        };

        let entries = match fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => return,
        };

        let prefix = format!("{base}.");
        let mut backups: Vec<String> = Vec::new();

        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name == base || !name.starts_with(&prefix) {
                continue;
            }
            backups.push(name);
        }

        // Sort by filename (contains embedded timestamp) descending
        backups.sort_by(|a, b| b.cmp(a));

        if cfg.max_backups > 0 && backups.len() > cfg.max_backups {
            for name in &backups[cfg.max_backups..] {
                let _ = fs::remove_file(dir.join(name));
            }
            backups.truncate(cfg.max_backups);
        }

        if cfg.max_age_days > 0 {
            let cutoff_secs =
                now_secs().saturating_sub(cfg.max_age_days as u64 * crate::time::SECS_PER_DAY);
            let cutoff_ts = {
                let days = cutoff_secs / crate::time::SECS_PER_DAY;
                let time_of_day = cutoff_secs % crate::time::SECS_PER_DAY;
                let (y, m, d) = crate::time::days_to_ymd(days);
                let h = time_of_day / 3600;
                let min = (time_of_day % 3600) / 60;
                let sec = time_of_day % 60;
                format!("{y:04}{m:02}{d:02}-{h:02}{min:02}{sec:02}")
            };
            for name in &backups {
                // Extract timestamp from filename: basename.YYYYMMDD-HHMMSS[.N]
                let suffix = &name[prefix.len()..];
                let ts_part: String = suffix
                    .chars()
                    .take_while(|c| c.is_ascii_digit() || *c == '-')
                    .collect();
                if ts_part < cutoff_ts {
                    let _ = fs::remove_file(dir.join(name));
                }
            }
        }
    }
}

impl Handler for FileHandler {
    fn enabled(&self, ctx: &Context<'_>) -> bool {
        ctx.level.severity() >= self.level.severity()
    }

    fn handle(&self, record: &std::sync::Arc<OwnedRecord>) -> Result<(), Error> {
        if self.state.closed.load(Ordering::Relaxed) {
            return Ok(());
        }

        if self.needs_rotation() {
            self.do_rotate();
        }

        if self.state.closed.load(Ordering::Relaxed) {
            return Ok(());
        }

        self.write_record(record)
    }

    fn clone_box(&self) -> Box<dyn Handler> {
        Box::new(FileHandler {
            level: self.level.clone(),
            format: self.format,
            state: Arc::clone(&self.state),
            error_handler: Arc::clone(&self.error_handler),
        })
    }

    fn set_error_handler(&self, handler: Option<Box<dyn Fn(&str, &Error) + Send + Sync>>) {
        *recover_lock(&self.error_handler) = handler;
    }

    fn flush(&self) {
        let mut w = recover_lock(&self.state.writer);
        let _ = w.flush();
    }

    fn close_if_needed(&mut self) -> Option<Result<(), Error>> {
        Some(self.close())
    }
}

impl Close for FileHandler {
    fn close(&mut self) -> Result<(), Error> {
        if self
            .state
            .closed
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Ok(());
        }

        for handle in recover_lock(&self.state.compress_wg).drain(..) {
            let _ = handle.join();
        }

        let mut writer = recover_lock(&self.state.writer);
        let _ = writer.flush();
        Ok(())
    }
}

impl Terminal for FileHandler {}

impl Drop for FileHandler {
    fn drop(&mut self) {
        if Arc::strong_count(&self.state) > 1 {
            return;
        }
        let _ = self.close();
    }
}

fn compress_file(backup_path: &Path, on_error: impl Fn(&Error) + Send) {
    use std::io::{Read, Write};

    let gz_path = format!("{}.gz", backup_path.display());
    let tmp_path = format!("{}.tmp", gz_path);

    let result = (|| -> Result<(), Error> {
        let src = std::fs::File::open(backup_path)?;
        let mut src = std::io::BufReader::new(src);
        let dst = std::fs::File::create(&tmp_path)?;
        restrict_file_permissions(&dst);
        let mut gz = flate2::write::GzEncoder::new(dst, flate2::Compression::default());
        let mut buf = [0u8; 8192];
        loop {
            match src.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => gz.write_all(&buf[..n])?,
                Err(e) => return Err(Error::Io(e)),
            }
        }
        gz.finish()?;
        fs::rename(&tmp_path, &gz_path)?;
        let _ = fs::remove_file(backup_path);
        Ok(())
    })();

    if let Err(e) = result {
        let _ = fs::remove_file(&tmp_path);
        on_error(&e);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arc_record;
    use crate::handler::Close;
    use std::io::Read;

    fn temp_log_path(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join("mebsuta_test").join(name);
        let _ = fs::create_dir_all(&dir);
        dir.join("test.log")
    }

    fn cleanup(path: &Path) {
        let _ = fs::remove_file(path);
        if let Some(dir) = path.parent() {
            for e in fs::read_dir(dir)
                .unwrap_or_else(|_| fs::read_dir(".").unwrap())
                .flatten()
            {
                let _ = fs::remove_file(e.path());
            }
            let _ = fs::remove_dir(dir);
        }
    }

    #[test]
    fn file_handler_writes_json() {
        let path = temp_log_path("writes_json");
        let _ = fs::remove_file(&path);
        let mut h = FileHandler::new(&path, Level::Info, Format::Json).unwrap();
        let r = arc_record(Level::Info, "hello file");
        h.handle(&r).unwrap();
        h.flush();
        h.close().unwrap();

        let content = fs::read_to_string(&path).unwrap();
        assert!(content.contains("\"message\":\"hello file\""));
        assert!(content.contains("\"level\":\"INFO\""));
        cleanup(&path);
    }

    #[test]
    fn file_handler_writes_text() {
        let path = temp_log_path("writes_text");
        let _ = fs::remove_file(&path);
        let mut h = FileHandler::new(&path, Level::Info, Format::Text).unwrap();
        let r = arc_record(Level::Info, "text msg");
        h.handle(&r).unwrap();
        h.flush();
        h.close().unwrap();

        let content = fs::read_to_string(&path).unwrap();
        assert!(content.contains("text msg"));
        cleanup(&path);
    }

    #[test]
    fn file_handler_level_filter() {
        let path = temp_log_path("level_filter");
        let _ = fs::remove_file(&path);
        let h = FileHandler::new(&path, Level::Warn, Format::Json).unwrap();
        let ctx_debug = Context::new(Level::Debug);
        let ctx_warn = Context::new(Level::Warn);
        assert!(!h.enabled(&ctx_debug));
        assert!(h.enabled(&ctx_warn));
        cleanup(&path);
    }

    #[test]
    fn size_rotation() {
        let path = temp_log_path("size_rotation");
        let _ = fs::remove_file(&path);

        let rotation = RotationConfig {
            max_size_bytes: 100,
            rotate_interval_secs: 0,
            max_backups: 0,
            max_age_days: 0,
            compress: false,
        };

        let mut h = FileHandler::with_rotation(&path, Level::Info, Format::Json, rotation).unwrap();

        // Write enough records to trigger rotation
        for i in 0..50 {
            let r = arc_record(
                Level::Info,
                format!("message number {i} with padding data xxxxxxxxxxxx"),
            );
            h.handle(&r).unwrap();
        }
        h.flush();
        h.close().unwrap();

        // Should have at least the main log file and one backup
        let dir = path.parent().unwrap();
        let entries: Vec<_> = fs::read_dir(dir).unwrap().filter_map(|e| e.ok()).collect();
        // Main file + at least one backup
        assert!(
            entries.len() >= 2,
            "Expected rotation but found {} files",
            entries.len()
        );

        // Cleanup all
        for e in entries {
            let _ = fs::remove_file(e.path());
        }
        cleanup(&path);
    }

    #[test]
    fn close_is_idempotent() {
        let path = temp_log_path("idempotent_close");
        let _ = fs::remove_file(&path);
        let mut h = FileHandler::new(&path, Level::Info, Format::Json).unwrap();
        h.close().unwrap();
        h.close().unwrap();
        cleanup(&path);
    }

    #[test]
    fn closed_handler_ignores_writes() {
        let path = temp_log_path("closed_ignores");
        let _ = fs::remove_file(&path);
        let mut h = FileHandler::new(&path, Level::Info, Format::Json).unwrap();
        let r = arc_record(Level::Info, "before close");
        h.handle(&r).unwrap();
        h.close().unwrap();

        let r2 = arc_record(Level::Info, "after close");
        h.handle(&r2).unwrap(); // Should silently skip

        let content = fs::read_to_string(&path).unwrap();
        assert!(content.contains("before close"));
        assert!(!content.contains("after close"));
        cleanup(&path);
    }

    #[test]
    fn gzip_compress() {
        use std::sync::atomic::AtomicBool;
        let dir = std::env::temp_dir().join("mebsuta_test").join("gzip_test");
        let _ = fs::create_dir_all(&dir);
        let src_path = dir.join("data.txt");
        fs::write(&src_path, "hello compression world\n".repeat(100)).unwrap();

        let error_called = std::sync::Arc::new(AtomicBool::new(false));
        let ec_clone = error_called.clone();
        compress_file(&src_path, move |_| {
            ec_clone.store(true, std::sync::atomic::Ordering::Relaxed)
        });

        assert!(
            !error_called.load(std::sync::atomic::Ordering::Relaxed),
            "compress should not error"
        );

        let gz_path = dir.join("data.txt.gz");
        assert!(gz_path.exists(), "gz file should exist");
        assert!(!src_path.exists(), "original should be removed");

        // Verify gz is valid
        let gz_file = fs::File::open(&gz_path).unwrap();
        let mut decoder = flate2::read::GzDecoder::new(gz_file);
        let mut content = String::new();
        decoder.read_to_string(&mut content).unwrap();
        assert!(content.contains("hello compression world"));

        let _ = fs::remove_file(&gz_path);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    #[cfg(unix)]
    fn file_permissions_restricted() {
        use std::os::unix::fs::PermissionsExt;
        let path = temp_log_path("file_perms");
        let _ = fs::remove_file(&path);
        let mut h = FileHandler::new(&path, Level::Info, Format::Json).unwrap();
        let r = arc_record(Level::Info, "perm test");
        h.handle(&r).unwrap();
        h.close().unwrap();

        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "log file should have 0600 permissions");

        cleanup(&path);
    }

    #[test]
    fn concurrent_writes_no_loss() {
        use std::sync::Arc;
        use std::thread;

        let path = temp_log_path("concurrent");
        let _ = fs::remove_file(&path);
        let h = Arc::new(std::sync::Mutex::new(
            FileHandler::new(&path, Level::Info, Format::Json).unwrap(),
        ));

        let n_threads = 4;
        let n_records = 50;
        let mut handles = Vec::new();

        for i in 0..n_threads {
            let h = Arc::clone(&h);
            handles.push(thread::spawn(move || {
                for j in 0..n_records {
                    let r = arc_record(Level::Info, &format!("t{}-r{}", i, j));
                    let h = h.lock().unwrap();
                    h.handle(&r).unwrap();
                }
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        {
            let mut h = h.lock().unwrap();
            h.close().unwrap();
        }

        let content = fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().filter(|l| !l.is_empty()).collect();
        assert_eq!(
            lines.len(),
            n_threads * n_records,
            "expected {} records, got {}",
            n_threads * n_records,
            lines.len()
        );

        cleanup(&path);
    }
}
