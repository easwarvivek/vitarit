//! # Vitārit — Paying for Threshold Services on Bitcoin and Friends
//!
//! Concrete Rust realization of ePrint 2025/174, Figures 5–9.
//!
//! ## Module map (paper figures)
//!
//! | Module        | Paper            |
//! |---------------|------------------|
//! | [`pkenc`]     | Figure 5 (PKEnc) |
//! | [`vne`]       | Figure 9 (VNE)  |
//! | [`gamma2pc`]  | Figure 8 (Γ₂ₚᶜ) |
//! | [`vitarit`]   | Figure 7        |
//!
//! Supporting primitives: [`dvrf`] (DVTS/DVRF), [`adaptor`] (AS),
//! [`schnorr`] (DS), [`nizk`] (Fiat–Shamir Schnorr for L′).

#![forbid(unsafe_code)]

pub mod adaptor;
pub mod dvrf;
pub mod error;
pub mod gamma2pc;
pub mod group;
pub mod hash;
pub mod nizk;
pub mod pkenc;
pub mod schnorr;
pub mod tx;
pub mod vitarit;
pub mod vne;

pub use error::{Error, Result};
pub use pkenc::PkEnc;
pub use vne::Vne;
pub use vitarit::VitaritProtocol;
