//! Gq: BLS12-381 G1 / G2 / GT for the DVRF (threshold BLS) witness.

use bls12_381::{G1Affine, G1Projective, G2Affine, G2Projective, Gt, G2Prepared, Scalar};
use ff::Field;
use group::Curve;
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};

pub type BlsScalar = Scalar;
pub type BlsG1 = G1Projective;
pub type BlsG2 = G2Projective;

/// Compressed G1 size (48 bytes = 384 bits), matching paper message length.
pub const G1_COMPRESSED_SIZE: usize = 48;

pub fn g1_generator() -> BlsG1 {
    G1Projective::generator()
}

pub fn g2_generator() -> BlsG2 {
    G2Projective::generator()
}

pub fn random_scalar<R: RngCore + CryptoRng>(rng: &mut R) -> BlsScalar {
    BlsScalar::random(rng)
}

/// Hash message into G1: Hq : {0,1}* → Gq  (paper §7.1).
///
/// Implemented as `gq^{H(msg)}` (RO → scalar → group). Sufficient for the
/// protocol skeleton; a production build should swap in IETF hash-to-curve.
pub fn hash_to_g1(msg: &[u8]) -> BlsG1 {
    g1_generator() * hash_to_scalar(b"VITARIT-Hq-v1", msg)
}

pub fn hash_to_scalar(label: &[u8], data: &[u8]) -> BlsScalar {
    let mut h = Sha256::new();
    Digest::update(&mut h, label);
    Digest::update(&mut h, data);
    let dig = h.finalize();
    let mut h2 = Sha256::new();
    Digest::update(&mut h2, b"expand");
    Digest::update(&mut h2, dig);
    let dig2 = h2.finalize();
    let mut wide = [0u8; 64];
    wide[..32].copy_from_slice(&dig);
    wide[32..].copy_from_slice(&dig2);
    Scalar::from_bytes_wide(&wide)
}

pub fn g1_to_bytes(p: &BlsG1) -> [u8; G1_COMPRESSED_SIZE] {
    let aff: G1Affine = p.to_affine();
    let c = aff.to_compressed();
    let mut out = [0u8; G1_COMPRESSED_SIZE];
    out.copy_from_slice(&c);
    out
}

pub fn g1_from_bytes(bytes: &[u8]) -> Option<BlsG1> {
    if bytes.len() != G1_COMPRESSED_SIZE {
        return None;
    }
    let mut arr = [0u8; G1_COMPRESSED_SIZE];
    arr.copy_from_slice(bytes);
    let aff = G1Affine::from_compressed(&arr);
    if bool::from(aff.is_some()) {
        Some(G1Projective::from(aff.unwrap()))
    } else {
        None
    }
}

pub fn g2_to_bytes(p: &BlsG2) -> [u8; 96] {
    let aff: G2Affine = p.to_affine();
    aff.to_compressed()
}

pub fn g2_from_bytes(bytes: &[u8]) -> Option<BlsG2> {
    if bytes.len() != 96 {
        return None;
    }
    let mut arr = [0u8; 96];
    arr.copy_from_slice(bytes);
    let aff = G2Affine::from_compressed(&arr);
    if bool::from(aff.is_some()) {
        Some(G2Projective::from(aff.unwrap()))
    } else {
        None
    }
}

pub fn scalar_to_bytes(s: &BlsScalar) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&s.to_bytes());
    out
}

pub fn scalar_from_bytes(bytes: &[u8]) -> Option<BlsScalar> {
    if bytes.len() != 32 {
        return None;
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(bytes);
    let s = BlsScalar::from_bytes(&arr);
    if bool::from(s.is_some()) {
        Some(s.unwrap())
    } else {
        None
    }
}

/// Pairing check e(a, b) == e(c, d).
pub fn pairing_check_eq(a: &BlsG1, b: &BlsG2, c: &BlsG1, d: &BlsG2) -> bool {
    let a_aff = a.to_affine();
    let c_aff = (-*c).to_affine();
    let b_prep = G2Prepared::from(b.to_affine());
    let d_prep = G2Prepared::from(d.to_affine());
    let result =
        bls12_381::multi_miller_loop(&[(&a_aff, &b_prep), (&c_aff, &d_prep)]).final_exponentiation();
    result == Gt::identity()
}

/// Lagrange coefficient λ_i for reconstructing at 0 (1-indexed party ids).
pub fn lagrange_at_zero(i: u64, ids: &[u64]) -> BlsScalar {
    let xi = BlsScalar::from(i);
    let mut num = BlsScalar::ONE;
    let mut den = BlsScalar::ONE;
    for &j in ids {
        if j == i {
            continue;
        }
        let xj = BlsScalar::from(j);
        num *= xj;
        den *= xj - xi;
    }
    num * den.invert().unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ff::Field;
    use rand::thread_rng;

    #[test]
    fn g1_serde_roundtrip() {
        let mut rng = thread_rng();
        let p = g1_generator() * random_scalar(&mut rng);
        let p2 = g1_from_bytes(&g1_to_bytes(&p)).unwrap();
        assert_eq!(p, p2);
    }

    #[test]
    fn g2_serde_roundtrip() {
        let mut rng = thread_rng();
        let p = g2_generator() * random_scalar(&mut rng);
        let p2 = g2_from_bytes(&g2_to_bytes(&p)).unwrap();
        assert_eq!(p, p2);
    }

    #[test]
    fn g1_from_bytes_rejects_bad_len() {
        assert!(g1_from_bytes(&[0u8; 10]).is_none());
    }

    #[test]
    fn scalar_serde_roundtrip() {
        let mut rng = thread_rng();
        let s = random_scalar(&mut rng);
        let s2 = scalar_from_bytes(&scalar_to_bytes(&s)).unwrap();
        assert_eq!(s, s2);
    }

    #[test]
    fn hash_to_g1_deterministic() {
        assert_eq!(hash_to_g1(b"m"), hash_to_g1(b"m"));
        assert_ne!(hash_to_g1(b"m1"), hash_to_g1(b"m2"));
    }

    #[test]
    fn pairing_check_bls_relation() {
        let mut rng = thread_rng();
        let sk = random_scalar(&mut rng);
        let h = hash_to_g1(b"msg");
        let sigma = h * sk;
        let vk = g2_generator() * sk;
        assert!(pairing_check_eq(&sigma, &g2_generator(), &h, &vk));
        assert!(!pairing_check_eq(&sigma, &g2_generator(), &h, &g2_generator()));
    }

    #[test]
    fn lagrange_two_parties_sum_to_one_on_secret() {
        // Shares of secret s=7 at x=1,2 with degree-1 poly s + a1 x, a1=3
        // → y1=10, y2=13. Reconstruct with λ.
        let ids = [1u64, 2];
        let l1 = lagrange_at_zero(1, &ids);
        let l2 = lagrange_at_zero(2, &ids);
        let y1 = BlsScalar::from(10u64);
        let y2 = BlsScalar::from(13u64);
        let s = y1 * l1 + y2 * l2;
        assert_eq!(s, BlsScalar::from(7u64));
    }

    #[test]
    fn lagrange_three_parties() {
        // s=5, coeffs a1=2, a2=1 → y(x)=5+2x+x^2
        // y(1)=8, y(2)=13, y(3)=20
        let ids = [1u64, 2, 3];
        let recon = |ys: &[BlsScalar]| {
            let mut acc = BlsScalar::ZERO;
            for (i, y) in ids.iter().zip(ys.iter()) {
                acc += *y * lagrange_at_zero(*i, &ids);
            }
            acc
        };
        assert_eq!(
            recon(&[
                BlsScalar::from(8u64),
                BlsScalar::from(13u64),
                BlsScalar::from(20u64)
            ]),
            BlsScalar::from(5u64)
        );
    }
}
