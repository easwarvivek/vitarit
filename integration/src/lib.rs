//! Full local Vitārit session: serialized Γ²ᵖᶜ + Bitcoin payment on a simulated
//! (or live regtest) ledger.
//!
//! secp256k1 ECDSA signs the Bitcoin witnesses; Ristretto adaptor / VNE run
//! off-chain and are bound to the consensus-serialized unsigned payment
//! template via [`vitarit_bitcoin::payment_adaptor_message`].

#![forbid(unsafe_code)]

pub mod error;
pub mod session;

pub use error::{Error, Result};
pub use session::{LocalSession, SessionReport, SessionParams};
