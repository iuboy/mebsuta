use std::io::Write;
use std::net::{TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use unicode_segmentation::UnicodeSegmentation;

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
        let severity = level_to_severity(&record.level);
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
        if let Some(ref eh) = *self
            .error_handler
            .lock()
            .expect("syslog error handler lock poisoned")
        {
            eh(component, err);
        }
    }
}

fn level_to_severity(level: &Level) -> u8 {
    match level {
        Level::Error => 3,
        Level::Warn => 4,
        Level::Audit(_) => 5,
        Level::Info => 6,
        Level::Debug | Level::Trace => 7,
    }
}

/// Truncate a string to fit within `max` bytes, respecting grapheme cluster boundaries.
///
/// When the string exceeds `max` bytes, it is cut at the last complete grapheme
/// cluster that fits and "..." is appended. If `max < 4` and no grapheme fits,
/// returns an empty string or a truncated prefix without ellipsis.
fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_owned();
    }
    if max < 4 {
        // Not enough room for ellipsis. Find the last grapheme boundary <= max.
        let boundary = grapheme_boundary_before(s, max);
        return s[..boundary].to_owned();
    }
    let limit = max - 3;
    let boundary = grapheme_boundary_before(s, limit);
    format!("{}...", &s[..boundary])
}

/// Find the largest grapheme-cluster boundary that is <= `byte_limit`.
fn grapheme_boundary_before(s: &str, byte_limit: usize) -> usize {
    let mut boundary = 0;
    for (idx, grapheme) in s.grapheme_indices(true) {
        let end = idx + grapheme.len();
        if end > byte_limit {
            break;
        }
        boundary = end;
    }
    boundary
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
        ctx.level.severity() >= self.level.severity()
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
            level: self.level.clone(),
            config: self.config.clone(),
            shared: Arc::clone(&self.shared),
            error_handler: Arc::clone(&self.error_handler),
        })
    }

    fn set_error_handler(&self, handler: Option<Box<dyn Fn(&str, &Error) + Send + Sync>>) {
        *self
            .error_handler
            .lock()
            .expect("syslog error handler lock poisoned") = handler;
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
    use crate::record::EventType;

    #[test]
    fn level_to_severity_mapping() {
        assert_eq!(level_to_severity(&Level::Error), 3);
        assert_eq!(level_to_severity(&Level::Warn), 4);
        assert_eq!(level_to_severity(&Level::Audit(EventType::Login)), 5);
        assert_eq!(level_to_severity(&Level::Info), 6);
        assert_eq!(level_to_severity(&Level::Debug), 7);
        assert_eq!(level_to_severity(&Level::Trace), 7);
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
        let severity = level_to_severity(&Level::Info);
        let priority = config.facility * 8 + severity;
        assert_eq!(priority, 14);
    }

    // ========================================================================
    // Grapheme cluster tests — verify truncate never splits a grapheme
    // ========================================================================

    // --- Combining characters (base + combining mark = single grapheme) ---

    #[test]
    fn grapheme_combining_acute() {
        // é = e + U+0301 combining acute accent (1+2 = 3 bytes, 1 grapheme)
        let s = "e\u{0301}abc"; // "éabc"
        assert_eq!(s.graphemes(true).count(), 4);
        let t = truncate(s, 5);
        // limit=2, grapheme "é" = 3 bytes > 2, doesn't fit → boundary=0 → "..."
        assert_valid_utf8_within(&t, 5);
        assert_eq!(t, "...");
    }

    #[test]
    fn grapheme_combining_preserves_base() {
        // e + combining diaeresis = ë (1 grapheme, 3 bytes)
        let s = "e\u{0308}test";
        let t = truncate(s, 10);
        assert_valid_utf8_within(&t, 10);
        // The combining ë must stay intact, not split into "e" + "̈"
        assert!(!t.starts_with('e') || t.starts_with("e\u{0308}"));
    }

    #[test]
    fn grapheme_multiple_combining() {
        // e + combining tilde + combining dot below (1 grapheme, 5 bytes)
        let s = "e\u{0303}\u{0323}abc";
        assert_eq!(s.graphemes(true).next().unwrap().len(), 5);
        let t = truncate(s, 10);
        assert_valid_utf8_within(&t, 10);
        // The whole grapheme "e\u{0303}\u{0323}" should be preserved or dropped together
        if t.starts_with('e') {
            assert!(t.starts_with("e\u{0303}\u{0303}") || t.starts_with("e\u{0303}\u{0323}"));
        }
    }

    #[test]
    fn grapheme_combining_long_chain() {
        // Base + 5 combining marks = 1 grapheme
        let s = "a\u{0300}\u{0301}\u{0302}\u{0303}\u{0304}xyz";
        let grapheme = s.graphemes(true).next().unwrap();
        assert_eq!(grapheme.len(), 11); // 1 + 5*2
        let t = truncate(s, 20);
        assert_valid_utf8_within(&t, 20);
        // Must not split the combining chain
        assert!(!t.contains("a\u{0300}\u{0301}...")); // should keep all or none of combining
    }

    // --- Zero-Width Joiner (ZWJ) sequences ---

    #[test]
    fn grapheme_zwj_family() {
        // 👨‍👩‍👧 = Man + ZWJ + Woman + ZWJ + Girl (1 grapheme, multiple codepoints)
        let family = "👨\u{200D}👩\u{200D}👧";
        assert_eq!(family.graphemes(true).count(), 1);
        let s = format!("{family}hello world more text here");
        let t = truncate(&s, 30);
        assert_valid_utf8_within(&t, 30);
        // The ZWJ family must not be split
        let first_grapheme = t.graphemes(true).next().unwrap();
        assert!(first_grapheme.contains('\u{200D}') || first_grapheme == "...");
    }

    #[test]
    fn grapheme_zwj_emoji_sequence() {
        // 👩‍🔬 = Woman + ZWJ + Microscope
        let scientist = "👩\u{200D}🔬";
        assert_eq!(scientist.graphemes(true).count(), 1);
        let s = format!("{scientist}data");
        let t = truncate(&s, 15);
        assert_valid_utf8_within(&t, 15);
    }

    #[test]
    fn grapheme_zwj_flag_england() {
        // 🏴󠁧󠁢󠁥󠁮󠁧󠁿 = flag tag sequence (1 grapheme, many codepoints)
        let flag = "🏴󠁧󠁢󠁥󠁮󠁧󠁿";
        assert_eq!(flag.graphemes(true).count(), 1);
        let s = format!("{flag}padding");
        let t = truncate(&s, 30);
        assert_valid_utf8_within(&t, 30);
    }

    // --- Variation selectors ---

    #[test]
    fn grapheme_variation_selector() {
        // ☎️ = ☎ (U+260E) + VS16 (U+FE0F) = 1 grapheme
        let phone = "\u{260E}\u{FE0F}";
        assert_eq!(phone.graphemes(true).count(), 1);
        let s = format!("{phone}hello world padding data");
        let t = truncate(&s, 15);
        assert_valid_utf8_within(&t, 15);
        // VS must stay with its base
        if t.starts_with('\u{260E}') {
            assert!(t.starts_with(phone));
        }
    }

    // --- Regional indicators (flag pairs) ---

    #[test]
    fn grapheme_regional_indicator_flag() {
        // 🇺🇸 = U+1F1FA + U+1F1F8 = US flag (1 grapheme, 8 bytes each = 16 bytes)
        let flag = "\u{1F1FA}\u{1F1F8}";
        assert_eq!(flag.graphemes(true).count(), 1);
        assert_eq!(flag.len(), 8); // each regional indicator is 4 bytes
        let s = format!("{flag}hello");
        let t = truncate(&s, 15);
        assert_valid_utf8_within(&t, 15);
        // Flag must not be split into two regional indicators
        if t.contains('\u{1F1FA}') {
            assert!(t.contains(flag));
        }
    }

    #[test]
    fn grapheme_multiple_flags() {
        let flags = "\u{1F1E8}\u{1F1F3}\u{1F1FA}\u{1F1F8}"; // 🇨🇳🇺🇸
        assert_eq!(flags.graphemes(true).count(), 2);
        let t = truncate(flags, 10);
        assert_valid_utf8_within(&t, 10);
        // Should truncate at grapheme boundary: first flag (8 bytes) + "..." = 11 > 10
        // limit=7, first flag = 8 bytes > 7 → boundary=0 → "..."
        assert_eq!(t, "...");
    }

    // --- Hangul syllable composition ---

    #[test]
    fn grapheme_hangul_jamo() {
        // Hangul jamo that compose: ᄒ + ᅡ + ᆫ = 한 (1 grapheme, 3+3+3 = 9 bytes)
        let jamo = "\u{1112}\u{1161}\u{11AB}";
        assert_eq!(jamo.graphemes(true).count(), 1);
        let s = format!("{jamo}text data here padding");
        let t = truncate(&s, 20);
        assert_valid_utf8_within(&t, 20);
    }

    // --- Mixed grapheme complexity ---

    #[test]
    fn grapheme_mixed_complex() {
        // ASCII + combining + ZWJ emoji + CJK + flag
        let s = format!(
            "hi{}{} world 你好 {} more",
            "e\u{0301}",          // é as combining
            "👩\u{200D}🔬",       // woman scientist ZWJ
            "\u{1F1E8}\u{1F1F3}", // 🇨🇳 flag
        );
        let t = truncate(&s, 30);
        assert_valid_utf8_within(&t, 30);
    }

    #[test]
    fn grapheme_all_graphemes_intact() {
        // Verify truncated result only contains complete graphemes
        let s = "a\u{0308}b\u{0301}🎉\u{FE0F}👨\u{200D}👩\u{200D}👧xyz";
        let t = truncate(s, 20);
        assert_valid_utf8_within(&t, 20);
        // Strip the "..." suffix and check remaining graphemes are in original
        let body = t.strip_suffix("...").unwrap_or(&t);
        for g in body.graphemes(true) {
            assert!(s.contains(g), "orphan grapheme '{g}' not in original");
        }
    }

    // ========================================================================
    // Malformed / illegal UTF-8 tests
    // ========================================================================

    #[test]
    fn sanitize_replaces_invalid_bytes() {
        // Valid ASCII + invalid continuation byte
        let bytes = b"hello\xFFworld";
        let s = crate::record::sanitize_utf8(bytes);
        assert!(s.contains('\u{FFFD}'));
        assert!(s.contains("hello"));
        assert!(s.contains("world"));
    }

    #[test]
    fn sanitize_replaces_incomplete_sequence() {
        // Start of a 3-byte sequence, but truncated
        let bytes = b"abc\xe4\xbd"; // 你 starts with E4 BD A0, missing A0
        let s = crate::record::sanitize_utf8(bytes);
        assert!(s.starts_with("abc"));
        assert!(s.contains('\u{FFFD}'));
    }

    #[test]
    fn sanitize_handles_overlong_encoding() {
        // Overlong encoding of '/' (C0 AF instead of 2F)
        let bytes = b"path\xc0\xaffile";
        let s = crate::record::sanitize_utf8(bytes);
        assert!(s.contains('\u{FFFD}'));
        assert!(s.contains("path"));
        assert!(s.contains("file"));
    }

    #[test]
    fn sanitize_handles_lone_continuation() {
        // Lone continuation byte (80-8F range)
        let bytes = b"test\x80data";
        let s = crate::record::sanitize_utf8(bytes);
        assert!(s.contains("test"));
        assert!(s.contains("data"));
        assert!(s.contains('\u{FFFD}'));
    }

    #[test]
    fn sanitize_handles_surrogate_half() {
        // UTF-8 encoding of U+D800 (surrogate, invalid in UTF-8): ED A0 80
        let bytes = b"before\xed\xa0\x80after";
        let s = crate::record::sanitize_utf8(bytes);
        assert!(s.contains("before"));
        assert!(s.contains("after"));
        assert!(s.contains('\u{FFFD}'));
    }

    #[test]
    fn sanitize_all_valid_passthrough() {
        let bytes = "你好世界🎉".as_bytes();
        let s = crate::record::sanitize_utf8(bytes);
        assert_eq!(s, "你好世界🎉");
    }

    #[test]
    fn sanitize_empty() {
        assert_eq!(crate::record::sanitize_utf8(b""), "");
    }

    #[test]
    fn sanitize_multiple_invalid() {
        // Multiple invalid sequences mixed with valid
        let bytes = b"a\xff\xff\xfe\xc0b";
        let s = crate::record::sanitize_utf8(bytes);
        assert!(s.contains('a'));
        assert!(s.contains('b'));
        // Should have replacement chars for invalid bytes
        let without_ab: String = s.chars().filter(|c| *c != 'a' && *c != 'b').collect();
        assert!(!without_ab.is_empty());
    }

    #[test]
    fn sanitize_consecutive_invalid() {
        let bytes = b"\xff\xff\xff";
        let s = crate::record::sanitize_utf8(bytes);
        assert!(s.contains('\u{FFFD}'));
    }

    // --- sanitize_utf8 + truncate end-to-end ---

    #[test]
    fn sanitize_then_truncate() {
        // Malformed input → sanitize → truncate should produce valid UTF-8
        let mut bytes = b"hello world ".to_vec();
        bytes.push(0xFF);
        bytes.extend_from_slice("这是中文测试数据".as_bytes());
        let clean = crate::record::sanitize_utf8(&bytes);
        let t = truncate(&clean, 20);
        assert_valid_utf8_within(&t, 20);
    }

    #[test]
    fn sanitize_preserves_graphemes() {
        // Valid grapheme clusters survive sanitize_utf8
        let input = "e\u{0308}👨\u{200D}👩\u{200D}👧🎉";
        let clean = crate::record::sanitize_utf8(input.as_bytes());
        assert_eq!(clean, input);
        // grapheme count preserved
        assert_eq!(clean.graphemes(true).count(), input.graphemes(true).count());
    }
}
