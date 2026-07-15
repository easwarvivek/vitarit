//! Group helpers: Gp (Ristretto / Ed25519-order) and Gq (BLS12-381 G1/G2).
//!
//! Per the paper (§7): PKEnc and adaptor signatures live in Gp; the
//! DVRF / BLS witness and Aj, Bj, Zj live in Gq (pairing groups).

pub mod bls;
pub mod ristretto;

pub use bls::{BlsG1, BlsG2, BlsScalar, G1_COMPRESSED_SIZE};
pub use ristretto::{RistrettoPoint, RistrettoScalar};
