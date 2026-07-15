//! Shared errors for the Bitcoin transaction layer.

use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid parameter: {0}")]
    InvalidParam(String),

    #[error("bitcoin consensus / script error: {0}")]
    Bitcoin(String),

    #[error("ledger / UTXO error: {0}")]
    Ledger(String),

    #[error("missing prerequisite: {0}")]
    Prerequisite(String),

    #[error("serialization: {0}")]
    Serde(String),
}
