use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::time::SystemTime;

use serde::Serialize;

use crate::level::Level;
use crate::time::system_time_to_rfc3339;
use crate::value::{Key, Value};

/// Audit event type for compliance logging (等保2.0 GB/T 22239, 密评 GM/T 0054).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum EventType {
    Login,
    Logout,
    Query,
    Create,
    Update,
    Delete,
    PermissionChange,
    ConfigChange,
    KeyOperation,
    CryptoOperation,
    System,
    Custom(String),
}

impl fmt::Display for EventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EventType::Login => write!(f, "login"),
            EventType::Logout => write!(f, "logout"),
            EventType::Query => write!(f, "query"),
            EventType::Create => write!(f, "create"),
            EventType::Update => write!(f, "update"),
            EventType::Delete => write!(f, "delete"),
            EventType::PermissionChange => write!(f, "permission_change"),
            EventType::ConfigChange => write!(f, "config_change"),
            EventType::KeyOperation => write!(f, "key_operation"),
            EventType::CryptoOperation => write!(f, "crypto_operation"),
            EventType::System => write!(f, "system"),
            EventType::Custom(s) => write!(f, "custom:{s}"),
        }
    }
}

impl serde::Serialize for EventType {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

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
    pub actor: Option<String>,
    pub success: Option<bool>,
}

/// Helper struct for JSON serialization of OwnedRecord.
#[derive(Serialize)]
struct OwnedRecordJson<'a> {
    time: String,
    level: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    event_type: Option<String>,
    message: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    module: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    actor: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    success: Option<bool>,
    attrs: HashMap<&'a str, &'a Value>,
}

impl OwnedRecord {
    pub fn to_json_string(&self) -> Result<String, serde_json::Error> {
        let attrs_map: HashMap<&str, &Value> =
            self.attrs.iter().map(|(k, v)| (k.as_str(), v)).collect();
        let json_rec = OwnedRecordJson {
            time: system_time_to_rfc3339(self.time),
            level: self.level.to_string(),
            event_type: match &self.level {
                Level::Audit(et) => Some(et.to_string()),
                _ => None,
            },
            message: &self.message,
            module: self.module_path.as_deref(),
            actor: self.actor.as_deref(),
            success: self.success,
            attrs: attrs_map,
        };
        serde_json::to_string(&json_rec)
    }
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
                actor: None,
                success: None,
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

    pub fn actor(mut self, v: impl Into<String>) -> Self {
        self.record.actor = Some(v.into());
        self
    }

    pub fn success(mut self, v: bool) -> Self {
        self.record.success = Some(v);
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

/// Convenience: create an audit-level `Arc<OwnedRecord>` with the required event type.
pub fn audit_record(event_type: EventType, message: impl Into<String>) -> Arc<OwnedRecord> {
    Arc::new(RecordBuilder::new(Level::Audit(event_type), message).build())
}

/// Sanitize raw bytes into a valid UTF-8 string.
///
/// Invalid UTF-8 sequences are replaced with U+FFFD (�).
/// Use this when consuming data from external sources (FFI, network, files)
/// before passing it into the logging pipeline.
pub fn sanitize_utf8(bytes: &[u8]) -> String {
    std::string::String::from_utf8_lossy(bytes).into_owned()
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
        assert!(parsed.get("event_type").is_none());
        assert!(parsed.get("actor").is_none());
        assert!(parsed.get("success").is_none());
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
        let s = crate::time::system_time_to_rfc3339(now);
        assert!(s.contains('T'));
        assert!(s.ends_with('Z'));
        assert_eq!(s.len(), 30);
    }

    #[test]
    fn event_type_display() {
        assert_eq!(EventType::Login.to_string(), "login");
        assert_eq!(EventType::PermissionChange.to_string(), "permission_change");
        assert_eq!(EventType::Custom("data_export".into()).to_string(), "custom:data_export");
    }

    #[test]
    fn audit_record_convenience() {
        let r = audit_record(EventType::Login, "user logged in");
        assert!(matches!(r.level, Level::Audit(EventType::Login)));
        assert_eq!(r.message, "user logged in");
    }

    #[test]
    fn to_json_audit_fields() {
        let r = RecordBuilder::new(Level::Audit(EventType::Delete), "deleted order")
            .actor("user_id:10086")
            .success(true)
            .attr("target", "orders#12345")
            .build();
        let json = r.to_json_string().unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["level"], "AUDIT");
        assert_eq!(parsed["event_type"], "delete");
        assert_eq!(parsed["actor"], "user_id:10086");
        assert_eq!(parsed["success"], true);
        assert_eq!(parsed["attrs"]["target"], "orders#12345");
    }

    #[test]
    fn to_json_backward_compat() {
        let r = RecordBuilder::new(Level::Info, "normal log").build();
        let json = r.to_json_string().unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(parsed.get("event_type").is_none());
        assert!(parsed.get("actor").is_none());
        assert!(parsed.get("success").is_none());
    }

    #[test]
    fn builder_actor_and_success() {
        let r = RecordBuilder::new(Level::Audit(EventType::Query), "query")
            .actor("admin")
            .success(false)
            .build();
        assert_eq!(r.actor.as_deref(), Some("admin"));
        assert_eq!(r.success, Some(false));
    }
}
