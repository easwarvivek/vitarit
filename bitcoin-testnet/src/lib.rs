//! Bitcoin transaction layer for Vitārit (ePrint 2025/174, Figures 2 & 7).
//!
//! This crate is independent of the cryptographic protocol in `../code`.
//! It models and builds the on-chain pieces: deposit 2-of-2 outputs, auxiliary
//! UTXOs (pay-at-most-once), setup and payment transactions, plus a capability
//! checklist for testnet/regtest deployment.

#![forbid(unsafe_code)]

pub mod checklist;
pub mod error;
pub mod keys;
pub mod ledger;
pub mod network;
pub mod policy;
pub mod protocol;
pub mod transactions;

pub use error::{Error, Result};
pub use network::BtcNetwork;
pub use protocol::{Fig7Params, Fig7Session};
pub use transactions::{PaymentPlan, SetupPlan};
