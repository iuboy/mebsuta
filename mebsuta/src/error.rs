use std::fmt;

/// Error type for mebsuta operations.
#[derive(Debug)]
pub enum Error {
    /// An I/O error occurred (file write, network, etc.)
    Io(std::io::Error),
    /// A handler panicked during processing.
    HandlerPanic,
    /// The async channel is full and the record was dropped.
    ChannelFull,
    /// A handler-specific error with a description.
    Handler(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "io error: {e}"),
            Error::HandlerPanic => write!(f, "handler panicked"),
            Error::ChannelFull => write!(f, "async channel full"),
            Error::Handler(msg) => write!(f, "handler error: {msg}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}
