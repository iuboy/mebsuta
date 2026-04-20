use std::io::Write;
use std::sync::Arc;

use crate::error::Error;
use crate::handler::{ErrorHandler, Handler, Terminal};
use crate::level::Level;
use crate::record::{Context, OwnedRecord};
use crate::value::Value;

/// Output format for StdoutHandler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Json,
    Text,
}

/// Handler that writes log records to stdout.
#[derive(Clone)]
pub struct StdoutHandler {
    level: Level,
    format: Format,
    error_handler: ErrorHandler,
}

impl StdoutHandler {
    pub fn new(level: Level, format: Format) -> Self {
        StdoutHandler {
            level,
            format,
            error_handler: Arc::new(std::sync::Mutex::new(None)),
        }
    }
}

impl Handler for StdoutHandler {
    fn enabled(&self, ctx: &Context<'_>) -> bool {
        ctx.level >= self.level
    }

    fn handle(&self, record: &Arc<OwnedRecord>) -> Result<(), Error> {
        let output = match self.format {
            Format::Json => format_json(record),
            Format::Text => format_text(record),
        };
        let stdout = std::io::stdout();
        let mut lock = stdout.lock();
        if let Err(e) = writeln!(lock, "{output}") {
            if let Some(ref eh) = *self.error_handler.lock().unwrap() {
                eh("stdout_handler", &Error::Io(e));
            }
            return Ok(());
        }
        Ok(())
    }

    fn clone_box(&self) -> Box<dyn Handler> {
        Box::new(self.clone())
    }

    fn set_error_handler(&self, handler: Option<Box<dyn Fn(&str, &Error) + Send + Sync>>) {
        *self.error_handler.lock().unwrap() = handler;
    }

    fn flush(&self) {
        let _ = std::io::stdout().flush();
    }
}

impl Terminal for StdoutHandler {}

pub(crate) fn format_json(r: &OwnedRecord) -> String {
    let mut parts = Vec::new();
    parts.push(format!("\"time\":\"{:?}\"", r.time));
    parts.push(format!("\"level\":\"{}\"", r.level));
    parts.push(format!("\"message\":\"{}\"", escape_json(&r.message)));
    if let Some(ref mp) = r.module_path {
        parts.push(format!("\"module\":\"{}\"", escape_json(mp)));
    }
    for (k, v) in &r.attrs {
        parts.push(format!(
            "\"{}\":{}",
            escape_json(k.as_str()),
            value_to_json(v)
        ));
    }
    format!("{{{}}}", parts.join(","))
}

pub(crate) fn format_text(r: &OwnedRecord) -> String {
    let level = format!("{:<5}", r.level);
    let mut base = format!(
        "{} {} {}",
        level,
        r.time.elapsed().unwrap_or_default().as_secs(),
        r.message
    );
    for (k, v) in &r.attrs {
        base.push_str(&format!(" {k}={v}"));
    }
    base
}

fn value_to_json(v: &Value) -> String {
    match v {
        Value::Str(s) => format!("\"{}\"", escape_json(s)),
        Value::Int(n) => n.to_string(),
        Value::Uint(n) => n.to_string(),
        Value::Float(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Bytes(_) => "\"<bytes>\"".to_owned(),
        Value::Null => "null".to_owned(),
    }
}

fn escape_json(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::RecordBuilder;

    #[test]
    fn json_format_basic() {
        let r = RecordBuilder::new(Level::Info, "hello").build();
        let json = format_json(&r);
        assert!(json.contains("\"level\":\"INFO\""));
        assert!(json.contains("\"message\":\"hello\""));
    }

    #[test]
    fn json_format_attrs() {
        let r = RecordBuilder::new(Level::Info, "test")
            .attr("key", "value")
            .attr("count", 42i64)
            .build();
        let json = format_json(&r);
        assert!(json.contains("\"key\":\"value\""));
        assert!(json.contains("\"count\":42"));
    }

    #[test]
    fn json_escape() {
        assert_eq!(escape_json("a\"b\nc"), "a\\\"b\\nc");
    }

    #[test]
    fn enabled_level_filter() {
        let handler = StdoutHandler::new(Level::Warn, Format::Json);
        let ctx_info = Context::new(Level::Info);
        let ctx_warn = Context::new(Level::Warn);
        let ctx_error = Context::new(Level::Error);
        assert!(!handler.enabled(&ctx_info));
        assert!(handler.enabled(&ctx_warn));
        assert!(handler.enabled(&ctx_error));
    }

    #[test]
    fn clone_preserves_config() {
        let h = StdoutHandler::new(Level::Debug, Format::Text);
        let cloned = h.clone_box();
        let ctx = Context::new(Level::Debug);
        assert!(cloned.enabled(&ctx));
    }
}
