//! Gp: Ristretto group over Curve25519 (prime order ≈ 2²⁵²).
//! Used for PKEnc (Figure 5) and Schnorr / adaptor signatures.

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint as DalekPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::{Identity, IsIdentity};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha512};
use zeroize::Zeroize;

pub type RistrettoPoint = DalekPoint;
pub type RistrettoScalar = Scalar;

/// Generator gp of Gp.
pub fn gp() -> RistrettoPoint {
    RISTRETTO_BASEPOINT_POINT
}

pub fn random_scalar<R: RngCore + CryptoRng>(rng: &mut R) -> RistrettoScalar {
    let mut bytes = [0u8; 64];
    rng.fill_bytes(&mut bytes);
    RistrettoScalar::from_bytes_mod_order_wide(&bytes)
}

pub fn hash_to_scalar(label: &[u8], data: &[u8]) -> RistrettoScalar {
    let mut h = Sha512::new();
    Digest::update(&mut h, label);
    Digest::update(&mut h, data);
    let out = h.finalize();
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&out);
    RistrettoScalar::from_bytes_mod_order_wide(&wide)
}

pub fn point_to_bytes(p: &RistrettoPoint) -> [u8; 32] {
    p.compress().to_bytes()
}

pub fn point_from_bytes(bytes: &[u8]) -> Option<RistrettoPoint> {
    if bytes.len() != 32 {
        return None;
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(bytes);
    CompressedRistretto(arr).decompress()
}

pub fn scalar_to_bytes(s: &RistrettoScalar) -> [u8; 32] {
    s.to_bytes()
}

pub fn scalar_from_bytes(bytes: &[u8]) -> Option<RistrettoScalar> {
    if bytes.len() != 32 {
        return None;
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(bytes);
    let s = Scalar::from_canonical_bytes(arr);
    // subtle::CtOption
    if bool::from(s.is_some()) {
        Some(s.unwrap())
    } else {
        None
    }
}

pub fn is_identity(p: &RistrettoPoint) -> bool {
    p.is_identity()
}

pub fn identity() -> RistrettoPoint {
    RistrettoPoint::identity()
}

/// Zeroize helper for secret scalars (copy then wipe source).
pub fn wipe_scalar(s: &mut RistrettoScalar) {
    s.zeroize();
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    #[test]
    fn point_serde_roundtrip() {
        let mut rng = thread_rng();
        let s = random_scalar(&mut rng);
        let p = gp() * s;
        let p2 = point_from_bytes(&point_to_bytes(&p)).unwrap();
        assert_eq!(p, p2);
    }

    #[test]
    fn point_from_bytes_rejects_bad_len() {
        assert!(point_from_bytes(&[0u8; 16]).is_none());
    }

    #[test]
    fn scalar_serde_roundtrip() {
        let mut rng = thread_rng();
        let s = random_scalar(&mut rng);
        let s2 = scalar_from_bytes(&scalar_to_bytes(&s)).unwrap();
        assert_eq!(s, s2);
    }

    #[test]
    fn hash_to_scalar_deterministic() {
        assert_eq!(
            hash_to_scalar(b"L", b"x"),
            hash_to_scalar(b"L", b"x")
        );
        assert_ne!(
            hash_to_scalar(b"L", b"x"),
            hash_to_scalar(b"L", b"y")
        );
    }

    #[test]
    fn identity_checks() {
        assert!(is_identity(&identity()));
        assert!(!is_identity(&gp()));
    }

    #[test]
    fn wipe_scalar_zeros() {
        let mut rng = thread_rng();
        let mut s = random_scalar(&mut rng);
        wipe_scalar(&mut s);
        assert_eq!(s, RistrettoScalar::ZERO);
    }
}
