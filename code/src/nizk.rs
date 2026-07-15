//! Fiat–Shamir Schnorr NIZK for language L′ of Figure 9.
//!
//! L′ statement:
//!   (i, A, B, Z, vk, {vk_j}, m*) with witness (b, sk_i, v_i) s.t.
//!     B = gq^b  ∧  Z = A^b · v_i  ∧  (v_i, ·) ← PartEval(sk_i, m*)
//!
//! We prove PoK{(b, sk) : B = g1^b ∧ Z = A^b · H(m)^sk ∧ vk_i = g2^{sk}}
//! via a multi-base Fiat–Shamir Schnorr (paper §7.1).

use crate::dvrf::PartialVk;
use crate::error::{Error, Result};
use crate::group::bls::{self, hash_to_g1, BlsG1, BlsG2, BlsScalar};
use bls12_381::Scalar;
use sha2::{Digest, Sha256};

/// Common reference string placeholder (RO model; empty for Fiat–Shamir).
#[derive(Clone, Debug, Default)]
pub struct CrsLPrime;

#[derive(Clone, Debug)]
pub struct StmtLPrime {
    pub server_index: usize,
    pub a: BlsG1,
    pub b_pt: BlsG1,
    pub z: BlsG1,
    pub vk_i: PartialVk,
    pub msg: Vec<u8>,
}

#[derive(Clone)]
pub struct WitLPrime {
    pub b: BlsScalar,
    pub sk_i: BlsScalar,
}

/// Proof π_j = (R_B, R_Z, R_vk, s_b, s_sk) in Fiat–Shamir form.
#[derive(Clone, Debug)]
pub struct ProofLPrime {
    pub r_b: BlsG1,
    pub r_z: BlsG1,
    pub r_vk: BlsG2,
    pub s_b: BlsScalar,
    pub s_sk: BlsScalar,
}

pub struct NizkLPrime;

impl NizkLPrime {
    pub fn setup() -> CrsLPrime {
        CrsLPrime
    }

    /// π ← Prove_{L′}(crs, stmt, wit)
    pub fn prove(_crs: &CrsLPrime, stmt: &StmtLPrime, wit: &WitLPrime) -> ProofLPrime {
        let h = hash_to_g1(&stmt.msg);
        // Deterministic nonce from witness + statement.
        let mut seed = Vec::new();
        seed.extend_from_slice(&bls::scalar_to_bytes(&wit.b));
        seed.extend_from_slice(&bls::scalar_to_bytes(&wit.sk_i));
        seed.extend_from_slice(&bls::g1_to_bytes(&stmt.a));
        seed.extend_from_slice(&bls::g1_to_bytes(&stmt.z));
        let r_b_sc = hash_to_scalar(b"VITARIT-Lprime-rb", &seed);
        let r_sk_sc = hash_to_scalar(b"VITARIT-Lprime-rsk", &seed);

        let r_b = bls::g1_generator() * r_b_sc;
        let r_z = stmt.a * r_b_sc + h * r_sk_sc;
        let r_vk = bls::g2_generator() * r_sk_sc;

        let c = challenge(stmt, &r_b, &r_z, &r_vk);
        let s_b = r_b_sc + c * wit.b;
        let s_sk = r_sk_sc + c * wit.sk_i;
        ProofLPrime {
            r_b,
            r_z,
            r_vk,
            s_b,
            s_sk,
        }
    }

    /// 0/1 ← Vf_{L′}(crs, stmt, π)
    pub fn verify(_crs: &CrsLPrime, stmt: &StmtLPrime, proof: &ProofLPrime) -> bool {
        let h = hash_to_g1(&stmt.msg);
        let c = challenge(stmt, &proof.r_b, &proof.r_z, &proof.r_vk);

        // g^{s_b} ≟ R_B · B^c
        let lhs_b = bls::g1_generator() * proof.s_b;
        let rhs_b = proof.r_b + stmt.b_pt * c;
        if lhs_b != rhs_b {
            return false;
        }

        // A^{s_b} · H^{s_sk} ≟ R_Z · Z^c
        let lhs_z = stmt.a * proof.s_b + h * proof.s_sk;
        let rhs_z = proof.r_z + stmt.z * c;
        if lhs_z != rhs_z {
            return false;
        }

        // g2^{s_sk} ≟ R_vk · vk_i^c
        let lhs_vk = bls::g2_generator() * proof.s_sk;
        let rhs_vk = proof.r_vk + stmt.vk_i.0 * c;
        lhs_vk == rhs_vk
    }

    /// Build stmt from Figure 9 fields.
    pub fn make_stmt(
        server_index: usize,
        a: BlsG1,
        b_pt: BlsG1,
        z: BlsG1,
        vk_i: &PartialVk,
        msg: &[u8],
    ) -> StmtLPrime {
        StmtLPrime {
            server_index,
            a,
            b_pt,
            z,
            vk_i: vk_i.clone(),
            msg: msg.to_vec(),
        }
    }
}

fn challenge(stmt: &StmtLPrime, r_b: &BlsG1, r_z: &BlsG1, r_vk: &BlsG2) -> BlsScalar {
    let mut data = Vec::new();
    data.extend_from_slice(&(stmt.server_index as u64).to_le_bytes());
    data.extend_from_slice(&bls::g1_to_bytes(&stmt.a));
    data.extend_from_slice(&bls::g1_to_bytes(&stmt.b_pt));
    data.extend_from_slice(&bls::g1_to_bytes(&stmt.z));
    data.extend_from_slice(&bls::g2_to_bytes(&stmt.vk_i.0));
    data.extend_from_slice(&stmt.msg);
    data.extend_from_slice(&bls::g1_to_bytes(r_b));
    data.extend_from_slice(&bls::g1_to_bytes(r_z));
    data.extend_from_slice(&bls::g2_to_bytes(r_vk));
    hash_to_scalar(b"VITARIT-Lprime-chal", &data)
}

fn hash_to_scalar(label: &[u8], data: &[u8]) -> BlsScalar {
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

/// Quick local check used by callers: Z ≟ A^b · v.
pub fn check_z_wellformed(a: &BlsG1, b: &BlsScalar, v: &BlsG1, z: &BlsG1) -> Result<()> {
    if *a * *b + *v == *z {
        Ok(())
    } else {
        Err(Error::Verification("Z ≠ A^b · v".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dvrf::Dvts;
    use crate::group::bls;
    use rand::thread_rng;

    #[test]
    fn lprime_prove_verify() {
        let mut rng = thread_rng();
        let keys = Dvts::dkgen(1, 3, &mut rng).unwrap();
        let i = 1usize;
        let m = b"m*";
        let (v_i, _) = Dvts::part_eval(&keys.partial_sks[i - 1], m);
        let b = bls::random_scalar(&mut rng);
        let a = bls::g1_generator() * bls::random_scalar(&mut rng);
        let b_pt = bls::g1_generator() * b;
        let z = a * b + v_i.0;
        let stmt = NizkLPrime::make_stmt(i, a, b_pt, z, &keys.partial_vks[i - 1], m);
        let wit = WitLPrime {
            b,
            sk_i: keys.partial_sks[i - 1].0,
        };
        let crs = NizkLPrime::setup();
        let proof = NizkLPrime::prove(&crs, &stmt, &wit);
        assert!(NizkLPrime::verify(&crs, &stmt, &proof));
    }

    #[test]
    fn lprime_rejects_wrong_z() {
        let mut rng = thread_rng();
        let keys = Dvts::dkgen(1, 3, &mut rng).unwrap();
        let i = 1usize;
        let m = b"m*";
        let (v_i, _) = Dvts::part_eval(&keys.partial_sks[i - 1], m);
        let b = bls::random_scalar(&mut rng);
        let a = bls::g1_generator() * bls::random_scalar(&mut rng);
        let b_pt = bls::g1_generator() * b;
        let z = a * b + v_i.0;
        let stmt = NizkLPrime::make_stmt(i, a, b_pt, z, &keys.partial_vks[i - 1], m);
        let wit = WitLPrime {
            b,
            sk_i: keys.partial_sks[i - 1].0,
        };
        let crs = NizkLPrime::setup();
        let proof = NizkLPrime::prove(&crs, &stmt, &wit);
        // Tamper Z in the statement.
        let mut bad = stmt.clone();
        bad.z = bls::g1_generator();
        assert!(!NizkLPrime::verify(&crs, &bad, &proof));
    }

    #[test]
    fn lprime_rejects_wrong_sk() {
        let mut rng = thread_rng();
        let keys = Dvts::dkgen(1, 3, &mut rng).unwrap();
        let i = 1usize;
        let m = b"m*";
        let (v_i, _) = Dvts::part_eval(&keys.partial_sks[i - 1], m);
        let b = bls::random_scalar(&mut rng);
        let a = bls::g1_generator() * bls::random_scalar(&mut rng);
        let b_pt = bls::g1_generator() * b;
        let z = a * b + v_i.0;
        let stmt = NizkLPrime::make_stmt(i, a, b_pt, z, &keys.partial_vks[i - 1], m);
        // Prove with server 2's sk against server 1's vk.
        let wit = WitLPrime {
            b,
            sk_i: keys.partial_sks[1].0,
        };
        let crs = NizkLPrime::setup();
        let proof = NizkLPrime::prove(&crs, &stmt, &wit);
        assert!(!NizkLPrime::verify(&crs, &stmt, &proof));
    }

    #[test]
    fn check_z_wellformed_ok_and_fail() {
        let mut rng = thread_rng();
        let a = bls::g1_generator() * bls::random_scalar(&mut rng);
        let b = bls::random_scalar(&mut rng);
        let v = bls::g1_generator() * bls::random_scalar(&mut rng);
        let z = a * b + v;
        assert!(check_z_wellformed(&a, &b, &v, &z).is_ok());
        assert!(check_z_wellformed(&a, &b, &v, &bls::g1_generator()).is_err());
    }
}
