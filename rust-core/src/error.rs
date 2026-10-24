use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CoreError {
    #[error("malformed input")]
    Malformed,
    #[error("authentication failed")]
    Auth,
    #[error("signature rejected")]
    BadSignature,
    #[error("key pin mismatch")]
    PinMismatch,
    #[error("memory lock failed")]
    Lock,
}
