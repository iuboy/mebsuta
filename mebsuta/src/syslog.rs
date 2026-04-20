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
        return s.to_owned();
    }
    if max < 4 {
        // Not enough room for any char + "...", find the largest char boundary <= max
        let boundary = s
            .char_indices()
            .take_while(|(i, c)| i + c.len_utf8() <= max)
            .last()
            .map(|(i, c)| i + c.len_utf8())
            .unwrap_or(0);
        return s[..boundary].to_owned();
    }
    let limit = max - 3;
    let boundary = s
        .char_indices()
        .take_while(|(i, c)| i + c.len_utf8() <= limit)
        .last()
        .map(|(i, c)| i + c.len_utf8())
        .unwrap_or(0);
    format!("{}...", &s[..boundary])
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

    // Helper: assert result is valid UTF-8 and within byte limit
    fn assert_valid_utf8_within(s: &str, max: usize) {
        assert!(
            std::str::from_utf8(s.as_bytes()).is_ok(),
            "result is not valid UTF-8: {s:?}"
        );
        assert!(
            s.len() <= max,
            "result len {} exceeds max {}: {:?}",
            s.len(),
            max,
            s
        );
    }

    // --- 1-byte ASCII (U+0000..U+007F) ---

    #[test]
    fn truncate_ascii_short() {
        assert_eq!(truncate("hi", 10), "hi");
    }

    #[test]
    fn truncate_ascii_exact_boundary() {
        assert_eq!(truncate("abcde", 5), "abcde");
    }

    #[test]
    fn truncate_ascii_long() {
        let s = "abcdefghij".repeat(100);
        let t = truncate(&s, 20);
        assert_valid_utf8_within(&t, 20);
        assert!(t.ends_with("..."));
        assert_eq!(&t[..17], "abcdefghijabcdefg");
    }

    #[test]
    fn truncate_ascii_one_over() {
        assert_eq!(truncate("abcdef", 5), "ab...");
    }

    // --- 2-byte UTF-8 (U+0080..U+07FF): é, ñ, ö, µ ---

    #[test]
    fn truncate_2byte_latin() {
        // é = 2 bytes (0xC3 0xA9)
        let s = "café".repeat(100);
        let t = truncate(&s, 10);
        assert_valid_utf8_within(&t, 10);
        assert!(t.ends_with("..."));
    }

    #[test]
    fn truncate_2byte_boundary_exact() {
        // "ééééé" = 10 bytes, max = 10 → no truncation
        assert_eq!(truncate("ééééé", 10), "ééééé");
    }

    #[test]
    fn truncate_2byte_boundary_split() {
        // "ééééé" = 10 bytes, max = 9 → must not split mid-é
        let t = truncate("ééééé", 9);
        assert_valid_utf8_within(&t, 9);
        assert!(t.ends_with("..."));
        // limit = 6, fits 3 é (6 bytes), result = "ééé..." = 9 bytes
        assert_eq!(t, "ééé...");
    }

    #[test]
    fn truncate_2byte_all_extended_latin() {
        // ñ=2B ö=2B Ü=2B — all 2-byte
        let s = "ñöÜ".repeat(100);
        let t = truncate(&s, 12);
        assert_valid_utf8_within(&t, 12);
        assert!(t.ends_with("..."));
    }

    // --- 3-byte UTF-8 (U+0800..U+FFFF): CJK, Korean, U+FFFD ---

    #[test]
    fn truncate_3byte_cjk() {
        // 你 = 3 bytes (0xE4 0xBD 0xA0)
        let s = "你好世界".repeat(100);
        let t = truncate(&s, 15);
        assert_valid_utf8_within(&t, 15);
        assert!(t.ends_with("..."));
    }

    #[test]
    fn truncate_3byte_cjk_boundary() {
        // "你好" = 6 bytes, max = 6 → no truncation
        assert_eq!(truncate("你好", 6), "你好");
    }

    #[test]
    fn truncate_3byte_cjk_split() {
        // "你好" = 6 bytes, max = 5 → limit=2, 你(3B) doesn't fit → "..."
        let t = truncate("你好", 5);
        assert_valid_utf8_within(&t, 5);
        assert_eq!(t, "...");
    }

    #[test]
    fn truncate_3byte_replacement_char() {
        // U+FFFD = 3 bytes
        let s = "\u{FFFD}".repeat(100);
        let t = truncate(&s, 10);
        assert_valid_utf8_within(&t, 10);
        assert!(t.ends_with("..."));
    }

    #[test]
    fn truncate_3byte_korean() {
        let s = "한글테스트".repeat(100);
        let t = truncate(&s, 20);
        assert_valid_utf8_within(&t, 20);
        assert!(t.ends_with("..."));
    }

    // --- 4-byte UTF-8 (U+10000..U+10FFFF): emoji, CJK Extension B ---

    #[test]
    fn truncate_4byte_emoji() {
        // 🎉 = 4 bytes (0xF0 0x9F 0x8E 0x89)
        let s = "🎉🎊🎁".repeat(100);
        let t = truncate(&s, 15);
        assert_valid_utf8_within(&t, 15);
        assert!(t.ends_with("..."));
    }

    #[test]
    fn truncate_4byte_emoji_boundary() {
        // "🎉🎉" = 8 bytes, max = 8 → no truncation
        assert_eq!(truncate("🎉🎉", 8), "🎉🎉");
    }

    #[test]
    fn truncate_4byte_emoji_split() {
        // "🎉🎉" = 8 bytes, max = 7 → must not split 🎉
        let t = truncate("🎉🎉", 7);
        assert_valid_utf8_within(&t, 7);
        assert_eq!(t, "🎉...");
    }

    #[test]
    fn truncate_4byte_cjk_ext() {
        // 𐍈 = U+10348, 4 bytes (Gothic letter)
        let s = "𐍈".repeat(100);
        let t = truncate(&s, 10);
        assert_valid_utf8_within(&t, 10);
        assert!(t.ends_with("..."));
    }

    #[test]
    fn truncate_4byte_only_one_fits() {
        // max = 7: limit=4, fits one 4-byte char → "𐍈..."
        let t = truncate("𐍈test", 7);
        assert_valid_utf8_within(&t, 7);
        assert_eq!(t, "𐍈...");
    }

    // --- Mixed byte widths ---

    #[test]
    fn truncate_mixed_ascii_cjk_emoji() {
        // "a你🎉" = 1 + 3 + 4 = 8 bytes
        assert_eq!(truncate("a你🎉", 8), "a你🎉");
        let t = truncate("a你🎉", 7);
        assert_valid_utf8_within(&t, 7);
        assert_eq!(t, "a你...");
    }

    #[test]
    fn truncate_mixed_latin_cjk() {
        // café = c(1)+a(1)+f(1)+é(2) = 5 bytes, 你(3), 好(3) = 11 bytes total
        assert_eq!(truncate("café你好", 11), "café你好");
        let t = truncate("café你好", 10);
        assert_valid_utf8_within(&t, 10);
        // limit=7, café(5B) fits, 你(3B) → 5+3=8 > 7 → "café..."
        assert_eq!(t, "café...");
    }

    #[test]
    fn truncate_mixed_1_2_3_4_bytes() {
        // a(1) + é(2) + 你(3) + 🎉(4) = 10 bytes
        assert_eq!(truncate("aé你🎉", 10), "aé你🎉");
        let t = truncate("aé你🎉", 9);
        assert_valid_utf8_within(&t, 9);
        // limit=6, "aé你" = 1+2+3 = 6 → "aé你..."
        assert_eq!(t, "aé你...");
    }

    // --- Edge cases ---

    #[test]
    fn truncate_empty_string() {
        assert_eq!(truncate("", 10), "");
    }

    #[test]
    fn truncate_max_equals_string_len() {
        assert_eq!(truncate("abc", 3), "abc");
    }

    #[test]
    fn truncate_max_zero() {
        assert_eq!(truncate("hello", 0), "");
    }

    #[test]
    fn truncate_max_one() {
        // max=1 < 4: no "...", just safe-truncate to char boundary
        assert_eq!(truncate("abc", 1), "a");
    }

    #[test]
    fn truncate_max_one_utf8() {
        // é is 2 bytes, doesn't fit in 1 byte → empty
        assert_eq!(truncate("éabc", 1), "");
    }

    #[test]
    fn truncate_max_two() {
        // max=2 < 4: no "...", fit what we can
        assert_eq!(truncate("abcdef", 2), "ab");
        assert_eq!(truncate("éabc", 2), "é");
    }

    #[test]
    fn truncate_max_three() {
        // max=3 < 4: no "..."
        assert_eq!(truncate("abcdef", 3), "abc");
    }

    #[test]
    fn truncate_combining_characters() {
        // é as e + U+0301 (combining acute accent): 1 + 2 = 3 bytes
        let s = "e\u{0301}test"; // "étest" with combining char
        let t = truncate(s, 6);
        assert_valid_utf8_within(&t, 6);
        assert!(t.ends_with("..."));
    }

    #[test]
    fn truncate_rtl_text() {
        // Arabic: مرحبا = 5 chars, each 2 bytes = 10 bytes
        let s = "مرحبا".repeat(100);
        let t = truncate(&s, 15);
        assert_valid_utf8_within(&t, 15);
        assert!(t.ends_with("..."));
    }

    #[test]
    fn truncate_only_multibyte_no_ascii() {
        // "你好世界" = 12 bytes, max=12 → no truncation
        assert_eq!(truncate("你好世界", 12), "你好世界");
        let t = truncate("你好世界", 11);
        assert_valid_utf8_within(&t, 11);
        assert_eq!(t, "你好...");
    }

    #[test]
    fn truncate_single_char_too_large() {
        // A single 4-byte emoji, max = 3 → char doesn't fit, empty
        let t = truncate("🎉", 3);
        assert_valid_utf8_within(&t, 3);
        // max=3 < 4, no "...", char doesn't fit → empty
        assert_eq!(t, "");
    }

    #[test]
    fn truncate_single_char_fits_exactly() {
        // A single 4-byte emoji, max = 4 → fits exactly
        assert_eq!(truncate("🎉", 4), "🎉");
    }

    #[test]
    fn truncate_ascii_max_4() {
        // max=4, "abcde" = 5 bytes → limit=1, "a..." = 4 bytes
        let t = truncate("abcde", 4);
        assert_valid_utf8_within(&t, 4);
        assert_eq!(t, "a...");
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
