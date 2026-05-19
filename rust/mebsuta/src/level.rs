use std::cmp::Ordering;
use std::fmt;

use crate::record::EventType;

/// Log level, ordered by severity: `Error > Warn > Audit > Info > Debug > Trace`.
///
/// `Audit(EventType)` carries the required operation type for compliance logging.
/// You cannot construct `Level::Audit` without an `EventType` — the compiler enforces it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Level {
    Trace,
    Debug,
    Info,
    Audit(EventType),
    Warn,
    Error,
}

impl Level {
    /// Numeric severity for threshold comparison. Ignores `EventType` payload.
    pub fn severity(&self) -> u8 {
        match self {
            Self::Trace => 0,
            Self::Debug => 1,
            Self::Info => 2,
            Self::Audit(_) => 3,
            Self::Warn => 4,
            Self::Error => 5,
        }
    }
}

impl Ord for Level {
    fn cmp(&self, other: &Self) -> Ordering {
        self.severity().cmp(&other.severity())
    }
}

impl PartialOrd for Level {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for Level {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Level::Trace => write!(f, "TRACE"),
            Level::Debug => write!(f, "DEBUG"),
            Level::Info => write!(f, "INFO"),
            Level::Audit(_) => write!(f, "AUDIT"),
            Level::Warn => write!(f, "WARN"),
            Level::Error => write!(f, "ERROR"),
        }
    }
}

impl serde::Serialize for Level {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordering() {
        assert!(Level::Error > Level::Warn);
        assert!(Level::Warn > Level::Audit(EventType::System));
        assert!(Level::Audit(EventType::Login) > Level::Info);
        assert!(Level::Info > Level::Debug);
        assert!(Level::Debug > Level::Trace);
    }

    #[test]
    fn severity_values() {
        assert_eq!(Level::Trace.severity(), 0);
        assert_eq!(Level::Debug.severity(), 1);
        assert_eq!(Level::Info.severity(), 2);
        assert_eq!(Level::Audit(EventType::System).severity(), 3);
        assert_eq!(Level::Warn.severity(), 4);
        assert_eq!(Level::Error.severity(), 5);
    }

    #[test]
    fn display() {
        assert_eq!(format!("{}", Level::Info), "INFO");
        assert_eq!(format!("{}", Level::Error), "ERROR");
        assert_eq!(format!("{}", Level::Audit(EventType::Login)), "AUDIT");
    }

    #[test]
    fn serialize() {
        assert_eq!(serde_json::to_string(&Level::Info).unwrap(), "\"INFO\"");
        assert_eq!(
            serde_json::to_string(&Level::Audit(EventType::Login)).unwrap(),
            "\"AUDIT\""
        );
    }

    #[test]
    fn audit_event_types_equal_severity() {
        assert_eq!(
            Level::Audit(EventType::Login).severity(),
            Level::Audit(EventType::Delete).severity()
        );
    }
}
