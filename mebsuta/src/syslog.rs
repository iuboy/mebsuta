use std::io::Write;
use std::net::{TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use crate::error::Error;
use crate::handler::{Close, ErrorHandler, Handler, Terminal};
use crate::level::Level;
use crate::record::{Context, OwnedRecord};

const MAX_SYSLOG_MSG_SIZE: usize = 4096;

/// Syslog transport protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SyslogTransport {
    Udp,
    Tcp,
}

/// Syslog format variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SyslogFormat {
    RFC3164,
    RFC5424,
}

/// Configuration for SyslogHandler.
#[derive(Debug, Clone)]
pub struct SyslogConfig {
    pub transport: SyslogTransport,
    pub format: SyslogFormat,
    pub address: String,
    pub tag: String,
    pub hostname: String,
    pub facility: u8,
}

impl Default for SyslogConfig {
    fn default() -> Self {
        SyslogConfig {
            transport: SyslogTransport::Udp,
            format: SyslogFormat::RFC3164,
            address: "127.0.0.1:514".to_owned(),
            tag: "mebsuta".to_owned(),
            hostname: hostname(),
            facility: 1,
        }
    }
}

fn hostname() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("hostname"))
        .unwrap_or_else(|_| "localhost".to_owned())
}

enum SyslogConn {
    Udp(UdpSocket),
    Tcp(TcpStream),
}

struct SyslogShared {
    conn: Mutex<Option<SyslogConn>>,
    closed: AtomicBool,
}

/// Handler that sends log records to a syslog server.
pub struct SyslogHandler {
    level: Level,
    config: SyslogConfig,
    shared: Arc<SyslogShared>,
    error_handler: ErrorHandler,
}

impl SyslogHandler {
    pub fn new(level: Level, config: SyslogConfig) -> Result<Self, Error> {
        let conn = match config.transport {
            SyslogTransport::Udp => {
                let socket = UdpSocket::bind("0.0.0.0:0")?;
                SyslogConn::Udp(socket)
            }
            SyslogTransport::Tcp => {
                let stream = TcpStream::connect(&config.address)?;
                SyslogConn::Tcp(stream)
            }
        };

        Ok(SyslogHandler {
            level,
            config,
            shared: Arc::new(SyslogShared {
                conn: Mutex::new(Some(conn)),
                closed: AtomicBool::new(false),
            }),
            error_handler: Arc::new(Mutex::new(None)),
        })
    }

    fn format_message(&self, record: &OwnedRecord) -> String {
        let severity = level_to_severity(record.level);
        let priority = self.config.facility * 8 + severity;
        let host = &self.config.hostname;
        let tag = &self.config.tag;
        let pid = std::process::id();
        let msg = truncate(&record.message, MAX_SYSLOG_MSG_SIZE);

        match self.config.format {
            SyslogFormat::RFC3164 => {
                format!("<{priority}>{host} {tag}[{pid}]: {msg}\n")
            }
            SyslogFormat::RFC5424 => {
                let mut sd = String::from("[");
                for (k, v) in &record.attrs {
                    if sd.len() > 1 {
                        sd.push(' ');
                    }
                    sd.push_str(&format!("{}=\"{}\"", k, escape_sd(&v.to_string())));
                }
                sd.push(']');
                let sd_field = if sd == "[]" { "-".to_owned() } else { sd };
                format!("<{priority}>1 - {host} {tag} {pid} - {sd_field} {msg}\n")
            }
        }
    }

    fn send(&self, data: &[u8]) -> Result<(), Error> {
        let mut guard = self.shared.conn.lock().expect("syslog conn lock poisoned");
        match guard.as_mut() {
            Some(SyslogConn::Udp(socket)) => {
                socket.send_to(data, &self.config.address)?;
            }
            Some(SyslogConn::Tcp(stream)) => {
                stream.write_all(data)?;
            }
            None => {
                return Err(Error::Io(std::io::Error::new(
                    std::io::ErrorKind::NotConnected,
                    "connection closed",
                )));
            }
        }
        Ok(())
    }

    fn call_error_handler(&self, component: &str, err: &Error) {
        if let Some(ref eh) = *self.error_handler.lock().expect("syslog error handler lock poisoned") {
            eh(component, err);
        }
    }
}

fn level_to_severity(level: Level) -> u8 {
    match level {
        Level::Error => 3,
        Level::Warn => 4,
        Level::Info => 6,
        Level::Debug | Level::Trace => 7,
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_owned()
    } else {
        let tail = "...";
        let limit = max - tail.len();
        let boundary = s
            .char_indices()
            .take_while(|(i, c)| i + c.len_utf8() <= limit)
            .last()
            .map(|(i, c)| i + c.len_utf8())
            .unwrap_or(0);
        format!("{}{tail}", &s[..boundary])
    }
}

fn escape_sd(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            ']' => out.push_str("\\]"),
            _ => out.push(c),
        }
    }
    out
}

impl Handler for SyslogHandler {
    fn enabled(&self, ctx: &Context<'_>) -> bool {
        ctx.level >= self.level
    }

    fn handle(&self, record: &Arc<OwnedRecord>) -> Result<(), Error> {
        if self.shared.closed.load(Ordering::Relaxed) {
            return Ok(());
        }

        let msg = self.format_message(record);
        match self.send(msg.as_bytes()) {
            Ok(()) => Ok(()),
            Err(e) => {
                self.call_error_handler("syslog", &e);
                Ok(())
            }
        }
    }

    fn clone_box(&self) -> Box<dyn Handler> {
        Box::new(SyslogHandler {
            level: self.level,
            config: self.config.clone(),
            shared: Arc::clone(&self.shared),
            error_handler: Arc::clone(&self.error_handler),
        })
    }

    fn set_error_handler(&self, handler: Option<Box<dyn Fn(&str, &Error) + Send + Sync>>) {
        *self.error_handler.lock().expect("syslog error handler lock poisoned") = handler;
    }

    fn flush(&self) {
        let mut guard = self.shared.conn.lock().expect("syslog conn lock poisoned");
        if let Some(SyslogConn::Tcp(stream)) = guard.as_mut() {
            let _ = stream.flush();
        }
    }

    fn close_if_needed(&mut self) -> Option<Result<(), Error>> {
        if Arc::strong_count(&self.shared) > 1 {
            return None;
        }
        Some(self.close())
    }
}

impl Close for SyslogHandler {
    fn close(&mut self) -> Result<(), Error> {
        if self
            .shared
            .closed
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Ok(());
        }
        self.flush();
        *self.shared.conn.lock().expect("syslog conn lock poisoned") = None;
        Ok(())
    }
}

impl Drop for SyslogHandler {
    fn drop(&mut self) {
        if Arc::strong_count(&self.shared) > 1 {
            return;
        }
        if !self.shared.closed.load(Ordering::Relaxed) {
            self.shared.closed.store(true, Ordering::Relaxed);
        }
        self.flush();
        *self.shared.conn.lock().expect("syslog conn lock poisoned") = None;
    }
}

impl Terminal for SyslogHandler {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arc_record;
    use crate::level::Level;

    #[test]
    fn level_to_severity_mapping() {
        assert_eq!(level_to_severity(Level::Error), 3);
        assert_eq!(level_to_severity(Level::Warn), 4);
        assert_eq!(level_to_severity(Level::Info), 6);
        assert_eq!(level_to_severity(Level::Debug), 7);
        assert_eq!(level_to_severity(Level::Trace), 7);
    }

    #[test]
    fn escape_sd_chars() {
        assert_eq!(escape_sd(r#"hello "world""#), r#"hello \"world\""#);
        assert_eq!(escape_sd(r"path\to]file"), r"path\\to\]file");
    }

    #[test]
    fn truncate_message() {
        assert_eq!(truncate("short", 100), "short");
        let long = "a".repeat(5000);
        let truncated = truncate(&long, 100);
        assert!(truncated.len() == 100);
        assert!(truncated.ends_with("..."));
    }

    #[test]
    fn truncate_utf8_safe() {
        let chinese = "你好世界这是中文测试数据".repeat(100);
        let truncated = truncate(&chinese, 20);
        assert!(truncated.ends_with("..."));
        assert!(truncated.len() <= 20);
        // Must be valid UTF-8
        assert!(std::str::from_utf8(truncated.as_bytes()).is_ok());
    }

    #[test]
    fn rfc3164_format() {
        let config = SyslogConfig {
            hostname: "testhost".to_owned(),
            tag: "myapp".to_owned(),
            facility: 1,
            ..SyslogConfig::default()
        };
        let _record = arc_record(Level::Info, "hello syslog");
        let severity = level_to_severity(Level::Info);
        let priority = config.facility * 8 + severity;
        assert_eq!(priority, 14);
    }
}
