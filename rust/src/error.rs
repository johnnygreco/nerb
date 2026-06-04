use pyo3::exceptions::PyValueError;
use pyo3::PyErr;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum BankError {
    #[error("unsupported source format {0:?}; expected json, yaml, jsonl, or canonical_json")]
    UnsupportedFormat(String),
    #[error("could not parse {format} source: {message}")]
    Parse {
        format: &'static str,
        message: String,
    },
    #[error("bank validation error at {path}: {message}")]
    Validation { path: String, message: String },
}

pub type Result<T> = std::result::Result<T, BankError>;

pub fn validation(path: impl Into<String>, message: impl Into<String>) -> BankError {
    BankError::Validation {
        path: path.into(),
        message: message.into(),
    }
}

impl From<BankError> for PyErr {
    fn from(error: BankError) -> Self {
        PyValueError::new_err(error.to_string())
    }
}
