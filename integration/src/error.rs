use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("crypto: {0}")]
    Crypto(#[from] vitarit::Error),

    #[error("bitcoin layer: {0}")]
    Bitcoin(#[from] vitarit_bitcoin::Error),

    #[error("protocol: {0}")]
    Protocol(String),

    #[error("wire: {0}")]
    Wire(String),
}
