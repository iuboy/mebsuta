use std::collections::HashMap;
use std::sync::Arc;
use std::time::SystemTime;

use serde::Serialize;

use crate::file::days_to_ymd;
use crate::level::Level;
use crate::value::{Key, Value};

/// Owned log record. Shared across the handler chain via `Arc<OwnedRecord>`.
#[derive(Debug, Clone)]
pub struct OwnedRecord {
    pub time: SystemTime,
    pub level: Level,
    pub message: String,
    pub module_path: Option<String>,
    pub file: Option<String>,
    pub line: Option<u32>,
    pub attrs: Vec<(Key, Value)>,
}

/// Helper struct for JSON serialization of OwnedRecord.
#[derive(Serialize)]
struct OwnedRecordJson<'a> {
    time: String,
    level: String,
    message: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    module: Option<&'a str>,
    attrs: HashMap<&'a str, &'a Value>,
}

impl OwnedRecord {
    pub fn to_json_string(&self) -> Result<String, serde_json::Error> {
        let attrs_map: HashMap<&str, &Value> =
            self.attrs.iter().map(|(k, v)| (k.as_str(), v)).collect();
        let json_rec = OwnedRecordJson {
            time: system_time_to_rfc3339(self.time),
            level: self.level.to_string(),
            message: &self.message,
            module: self.module_path.as_deref(),
            attrs: attrs_map,
        };
        serde_json::to_string(&json_rec)
    }
}

/// Convert SystemTime to RFC3339 UTC string (no chrono dependency).
pub(crate) fn system_time_to_rfc3339(t: SystemTime) -> String {
    let duration = t
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = duration.as_secs();
    let nsecs = duration.subsec_nanos();
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let (year, month, day) = days_to_ymd(days);
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;
    format!(
        "{year:04}-{month:02}-{day:02}T{hours:02}:{minutes:02}:{seconds:02}.{nsecs:09}Z"
    )
}

/// Lightweight context for `enabled()` checks. Cheap to construct.
#[derive(Debug, Clone)]
pub struct Context<'a> {
    pub level: Level,
    pub module_path: Option<&'a str>,
}

impl<'a> Context<'a> {
    pub fn new(level: Level) -> Self {
        Context {
            level,
            module_path: None,
        }
    }
}

/// Builder for `OwnedRecord`.
pub struct RecordBuilder {
    record: OwnedRecord,
}

impl RecordBuilder {
    pub fn new(level: Level, message: impl Into<String>) -> Self {
        RecordBuilder {
            record: OwnedRecord {
                time: SystemTime::now(),
                level,
                message: message.into(),
                module_path: None,
                file: None,
                line: None,
                attrs: Vec::new(),
            },
        }
    }

    pub fn module_path(mut self, v: impl Into<String>) -> Self {
        self.record.module_path = Some(v.into());
        self
    }

    pub fn file(mut self, v: impl Into<String>) -> Self {
        self.record.file = Some(v.into());
        self
    }

    pub fn line(mut self, v: u32) -> Self {
        self.record.line = Some(v);
        self
    }

    pub fn attr(mut self, key: impl Into<Key>, value: impl Into<Value>) -> Self {
        self.record.attrs.push((key.into(), value.into()));
        self
    }

    pub fn build(self) -> OwnedRecord {
        self.record
    }
}

/// Convenience: wrap an `OwnedRecord` in `Arc` for handler chain passing.
pub fn arc_record(level: Level, message: impl Into<String>) -> Arc<OwnedRecord> {
    Arc::new(RecordBuilder::new(level, message).build())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_json_basic() {
        let r = RecordBuilder::new(Level::Info, "hello").build();
        let json = r.to_json_string().unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["message"], "hello");
        assert_eq!(parsed["level"], "INFO");
        assert!(parsed["time"].is_string());
    }

    #[test]
    fn to_json_with_attrs() {
        let r = RecordBuilder::new(Level::Info, "test")
            .attr("key", "value")
            .attr("count", 42i64)
            .build();
        let json = r.to_json_string().unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["attrs"]["key"], "value");
        assert_eq!(parsed["attrs"]["count"], 42);
    }

    #[test]
    fn to_json_special_chars() {
        let r = RecordBuilder::new(Level::Info, "line1\nline2\t\"quoted\"")
            .attr("path", "C:\\Users\\test")
            .build();
        let json = r.to_json_string().unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["message"], "line1\nline2\t\"quoted\"");
        assert_eq!(parsed["attrs"]["path"], "C:\\Users\\test");
    }

    #[test]
    fn to_json_skip_none_module() {
        let r = RecordBuilder::new(Level::Info, "no module").build();
        let json = r.to_json_string().unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(parsed.get("module").is_none());
    }

    #[test]
    fn to_json_with_module() {
        let r = RecordBuilder::new(Level::Info, "msg")
            .module_path("myapp::handler")
            .build();
        let json = r.to_json_string().unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["module"], "myapp::handler");
    }

    #[test]
    fn rfc3339_format() {
        let now = SystemTime::now();
        let s = system_time_to_rfc3339(now);
        // Basic format check: YYYY-MM-DDTHH:MM:SS.NNNNNNNNNZ
        assert!(s.contains('T'));
        assert!(s.ends_with('Z'));
        assert_eq!(s.len(), 30); // "2026-04-20T12:34:56.123456789Z"
    }
}
