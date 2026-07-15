//! Error types for the Vitārit implementation.

use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("verification failed: {0}")]
    Verification(String),

    #[error("decryption failed: {0}")]
    Decryption(String),

    #[error("invalid input: {0}")]
    InvalidInput(String),

    #[error("protocol aborted: {0}")]
    ProtocolAbort(String),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("insufficient shares: need {need}, got {got}")]
    InsufficientShares { need: usize, got: usize },

    #[error("blockchain / ledger error: {0}")]
    Ledger(String),
}
