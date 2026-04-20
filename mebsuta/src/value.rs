use std::fmt;

/// Attribute key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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
pub enum Value {
    Str(String),
    Int(i64),
    Uint(u64),
    Float(f64),
    Bool(bool),
    Bytes(Vec<u8>),
    Null,
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
}
