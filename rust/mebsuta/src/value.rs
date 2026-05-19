use std::fmt;

use serde::Serialize;

/// Attribute key.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct Key(String);

impl Key {
    pub fn new(k: impl Into<String>) -> Self {
        Key(k.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<&str> for Key {
    fn from(s: &str) -> Self {
        Key(s.to_owned())
    }
}

impl From<String> for Key {
    fn from(s: String) -> Self {
        Key(s)
    }
}

/// Attribute value.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Value {
    Str(String),
    Int(i64),
    Uint(u64),
    Float(f64),
    Bool(bool),
    Bytes(Vec<u8>),
    Null,
}

impl Serialize for Value {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Value::Str(s) => serializer.serialize_str(s),
            Value::Int(n) => serializer.serialize_i64(*n),
            Value::Uint(n) => serializer.serialize_u64(*n),
            Value::Float(n) => {
                if n.is_finite() {
                    serializer.serialize_f64(*n)
                } else {
                    serializer.serialize_none()
                }
            }
            Value::Bool(b) => serializer.serialize_bool(*b),
            Value::Bytes(_) => serializer.serialize_str("<bytes>"),
            Value::Null => serializer.serialize_none(),
        }
    }
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Value::Str(s) => write!(f, "{s}"),
            Value::Int(n) => write!(f, "{n}"),
            Value::Uint(n) => write!(f, "{n}"),
            Value::Float(n) => write!(f, "{n}"),
            Value::Bool(b) => write!(f, "{b}"),
            Value::Bytes(b) => write!(f, "{} bytes", b.len()),
            Value::Null => write!(f, "null"),
        }
    }
}

// Convenience From impls
impl From<String> for Value {
    fn from(s: String) -> Self {
        Value::Str(s)
    }
}

impl From<&str> for Value {
    fn from(s: &str) -> Self {
        Value::Str(s.to_owned())
    }
}

impl From<i64> for Value {
    fn from(n: i64) -> Self {
        Value::Int(n)
    }
}

impl From<u64> for Value {
    fn from(n: u64) -> Self {
        Value::Uint(n)
    }
}

impl From<f64> for Value {
    fn from(n: f64) -> Self {
        Value::Float(n)
    }
}

impl From<bool> for Value {
    fn from(b: bool) -> Self {
        Value::Bool(b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_conversions() {
        assert!(matches!(Value::from("hello"), Value::Str(_)));
        assert!(matches!(Value::from(42i64), Value::Int(42)));
        assert!(matches!(Value::from(42u64), Value::Uint(42)));
        assert!(matches!(Value::from(3.15f64), Value::Float(_)));
        assert!(matches!(Value::from(true), Value::Bool(true)));
    }

    #[test]
    fn display() {
        assert_eq!(format!("{}", Value::from("hello")), "hello");
        assert_eq!(format!("{}", Value::from(42i64)), "42");
        assert_eq!(format!("{}", Value::Null), "null");
    }

    #[test]
    fn json_str_escaping() {
        let v = Value::Str("a\"b\nc".to_owned());
        let json = serde_json::to_string(&v).unwrap();
        assert_eq!(json, r#""a\"b\nc""#);
    }

    #[test]
    fn float_finite_serializes_normally() {
        let v = Value::Float(3.14);
        let json = serde_json::to_string(&v).unwrap();
        assert!(json.contains("3.14"));
    }

    #[test]
    fn float_non_finite_serializes_as_null() {
        assert_eq!(
            serde_json::to_string(&Value::Float(f64::NAN)).unwrap(),
            "null"
        );
        assert_eq!(
            serde_json::to_string(&Value::Float(f64::INFINITY)).unwrap(),
            "null"
        );
        assert_eq!(
            serde_json::to_string(&Value::Float(f64::NEG_INFINITY)).unwrap(),
            "null"
        );
    }

    #[test]
    fn null_serializes_as_null() {
        assert_eq!(serde_json::to_string(&Value::Null).unwrap(), "null");
    }

    #[test]
    fn bytes_serializes_as_placeholder() {
        assert_eq!(
            serde_json::to_string(&Value::Bytes(vec![1, 2, 3])).unwrap(),
            r#""<bytes>""#
        );
    }
}
