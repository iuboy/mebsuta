use thiserror::Error;

/// Error type for mebsuta operations.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// An I/O error occurred (file write, network, etc.)
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// A database error occurred.
    #[error("database error: {0}")]
    Database(String),
    /// A configuration error occurred.
    #[error("config error: {0}")]
    Config(String),
    /// A handler panicked during processing.
    #[error("handler panicked")]
    HandlerPanic,
    /// A handler-specific error with a description.
    #[error("handler error: {0}")]
    Handler(String),
}

impl From<rusqlite::Error> for Error {
    fn from(e: rusqlite::Error) -> Self {
        Error::Database(e.to_string())
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Config(e.to_string())
    }
}
