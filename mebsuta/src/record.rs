use std::sync::Arc;
use std::time::SystemTime;

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
