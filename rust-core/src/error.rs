use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CoreError {
    #[error("malformed input")]
    Malformed,
    #[error("authentication failed")]
    Auth,
    #[error("signature rejected")]
    BadSignature,
    /// The signature is valid but the version is not strictly newer than the installed one.
    /// The message names no key or version content.
    #[error("update is not newer than the installed version")]
    Downgrade,
    #[error("key pin mismatch")]
    PinMismatch,
    #[error("identity already pinned")]
    DuplicatePin,
    #[error("memory lock failed")]
    Lock,
    #[error("network error")]
    Network,
}
