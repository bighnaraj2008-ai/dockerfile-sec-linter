use std::path::PathBuf;
use thiserror::Error;

/// Top-level error type for dockerfile-sec-linter.
#[derive(Error, Debug)]
pub enum LinterError {
    #[error("I/O error reading file '{path}': {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("Failed to parse Dockerfile at line {line}: {message}")]
    Parse { line: usize, message: String },

    #[error("Configuration error in '{path}': {message}")]
    Config { path: PathBuf, message: String },

    #[error("Rule evaluation error: {0}")]
    Rule(String),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, LinterError>;
