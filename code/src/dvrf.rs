//! Distributed Verifiable Threshold Service (DVTS) instantiated as a
//! threshold BLS VRF (paper §7.1 / Galindo et al.).
//!
//! Exact interface (Definition 5):
//! ```text
//! DKgen(1λ, t, n) → (vk, {(vk_j, sk_j)}_{j∈[n]})
//! PartEval(sk_i, m) → (v_i, π_i)
//! PartVerify(i, vk, {vk_j}, m, v_i, π_i) → 0/1
//! Combine(vk, {vk_j}, m, {(k_i, v_{k_i}, π_{k_i})}) → (v, π)
//! Verify(vk, {vk_j}, m, v, π) → 0/1
//! ```

use crate::error::{Error, Result};
use crate::group::bls::{
    self, hash_to_g1, hash_to_scalar, lagrange_at_zero, pairing_check_eq, BlsG1, BlsG2, BlsScalar,
};
use ff::Field;
use rand_core::{CryptoRng, RngCore};

pub struct Dvts;

/// Global verification key vk ∈ G2.
#[derive(Clone, Debug)]
pub struct GlobalVk(pub BlsG2);

/// Partial verification key vk_i ∈ G2.
#[derive(Clone, Debug)]
pub struct PartialVk(pub BlsG2);

/// Secret key share sk_i ∈ Zq.
#[derive(Clone)]
pub struct PartialSk(pub BlsScalar);

/// Partial evaluation v_i ∈ G1.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PartialEval(pub BlsG1);

/// Chaum–Pedersen / DLEQ proof that log_{g2}(vk_i) = log_{H(m)}(v_i).
#[derive(Clone, Debug)]
pub struct PartialProof {
    pub c: BlsScalar,
    pub s: BlsScalar,
}

/// Aggregated VRF value / proof (same shape as a BLS signature + membership).
#[derive(Clone, Debug)]
pub struct FullEval(pub BlsG1);

#[derive(Clone, Debug)]
pub struct FullProof(pub BlsG1); // for uniqueness we re-use the eval; pairing-checkable

/// Key material produced by DKgen.
#[derive(Clone)]
pub struct KeySet {
    pub t: usize,
    pub n: usize,
    pub vk: GlobalVk,
    pub partial_vks: Vec<PartialVk>,
    pub partial_sks: Vec<PartialSk>,
}

impl Dvts {
    /// (vk, {(vk_j, sk_j)}) ← DKgen(1λ, t, n)
    ///
    /// Shamir sharing of a random master secret (trusted-dealer realization of
    /// the possibly-interactive DKgen; sufficient for the concrete protocol).
    pub fn dkgen<R: RngCore + CryptoRng>(t: usize, n: usize, rng: &mut R) -> Result<KeySet> {
        if n == 0 || t >= n {
            return Err(Error::InvalidInput(format!(
                "need 0 ≤ t < n, got t={t}, n={n}"
            )));
        }
        // Threshold in the paper is t-out-of-n meaning t+1 shares reconstruct.
        let threshold = t + 1;
        let master = bls::random_scalar(rng);
        // Degree-t polynomial; a0 = master.
        let mut coeffs = vec![master];
        for _ in 1..threshold {
            coeffs.push(bls::random_scalar(rng));
        }

        let mut partial_sks = Vec::with_capacity(n);
        let mut partial_vks = Vec::with_capacity(n);
        for i in 1..=n as u64 {
            let x = BlsScalar::from(i);
            let mut y = BlsScalar::ZERO;
            let mut x_pow = BlsScalar::ONE;
            for c in &coeffs {
                y += *c * x_pow;
                x_pow *= x;
            }
            let sk = PartialSk(y);
            let vk = PartialVk(bls::g2_generator() * y);
            partial_sks.push(sk);
            partial_vks.push(vk);
        }
        let vk = GlobalVk(bls::g2_generator() * master);
        Ok(KeySet {
            t,
            n,
            vk,
            partial_vks,
            partial_sks,
        })
    }

    /// (v_i, π_i) ← PartEval(sk_i, m)
    pub fn part_eval(sk_i: &PartialSk, m: &[u8]) -> (PartialEval, PartialProof) {
        let h = hash_to_g1(m);
        let v = PartialEval(h * sk_i.0);
        let proof = dleq_prove(sk_i.0, &bls::g2_generator(), &(bls::g2_generator() * sk_i.0), &h, &v.0);
        (v, proof)
    }

    /// 0/1 ← PartVerify(i, vk, {vk_j}, m, v_i, π_i)
    pub fn part_verify(
        i: usize,
        _vk: &GlobalVk,
        partial_vks: &[PartialVk],
        m: &[u8],
        v_i: &PartialEval,
        pi_i: &PartialProof,
    ) -> bool {
        if i == 0 || i > partial_vks.len() {
            return false;
        }
        let vk_i = &partial_vks[i - 1];
        let h = hash_to_g1(m);
        dleq_verify(pi_i, &bls::g2_generator(), &vk_i.0, &h, &v_i.0)
    }

    /// (v, π) ← Combine(vk, {vk_j}, m, {(k, v_k, π_k)})
    pub fn combine(
        vk: &GlobalVk,
        partial_vks: &[PartialVk],
        m: &[u8],
        shares: &[(usize, PartialEval, PartialProof)],
    ) -> Result<(FullEval, FullProof)> {
        let threshold = /* t+1 inferred from share count expectation */ shares.len();
        if shares.is_empty() {
            return Err(Error::InsufficientShares { need: 1, got: 0 });
        }
        // Verify each share first (robustness).
        for (k, v, pi) in shares {
            if !Self::part_verify(*k, vk, partial_vks, m, v, pi) {
                return Err(Error::Verification(format!("share {k} failed PartVerify")));
            }
        }
        let ids: Vec<u64> = shares.iter().map(|(k, _, _)| *k as u64).collect();
        let mut acc = BlsG1::identity();
        for (k, v, _) in shares {
            let lambda = lagrange_at_zero(*k as u64, &ids);
            acc += v.0 * lambda;
        }
        let _ = threshold;
        let full = FullEval(acc);
        // Proof is the value itself; Verify uses the pairing against vk.
        Ok((full.clone(), FullProof(full.0)))
    }

    /// 0/1 ← Verify(vk, {vk_j}, m, v, π)
    pub fn verify(
        vk: &GlobalVk,
        _partial_vks: &[PartialVk],
        m: &[u8],
        v: &FullEval,
        _pi: &FullProof,
    ) -> bool {
        let h = hash_to_g1(m);
        // e(v, g2) = e(H(m), vk)
        pairing_check_eq(&v.0, &bls::g2_generator(), &h, &vk.0)
    }
}

impl PartialEval {
    pub fn to_bytes(&self) -> [u8; bls::G1_COMPRESSED_SIZE] {
        bls::g1_to_bytes(&self.0)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        bls::g1_from_bytes(bytes)
            .map(PartialEval)
            .ok_or_else(|| Error::Serialization("bad PartialEval".into()))
    }
}

impl FullEval {
    pub fn to_bytes(&self) -> [u8; bls::G1_COMPRESSED_SIZE] {
        bls::g1_to_bytes(&self.0)
    }
}

/// Fiat–Shamir DLEQ proof: PoK{ sk : vk = g2^{sk} ∧ v = h^{sk} }.
fn dleq_prove(
    sk: BlsScalar,
    g2: &BlsG2,
    vk: &BlsG2,
    h: &BlsG1,
    v: &BlsG1,
) -> PartialProof {
    // Non-interactive: r derived from sk||vk||v for determinism in tests.
    let mut seed = Vec::new();
    seed.extend_from_slice(&bls::scalar_to_bytes(&sk));
    seed.extend_from_slice(&bls::g2_to_bytes(vk));
    seed.extend_from_slice(&bls::g1_to_bytes(v));
    let r = hash_to_scalar(b"VITARIT-DLEQ-nonce", &seed);
    let a2 = *g2 * r;
    let a1 = *h * r;
    let c = dleq_challenge(g2, vk, h, v, &a2, &a1);
    let s = r + c * sk;
    PartialProof { c, s }
}

fn dleq_verify(proof: &PartialProof, g2: &BlsG2, vk: &BlsG2, h: &BlsG1, v: &BlsG1) -> bool {
    // A2 = g2^s · vk^{-c}, A1 = h^s · v^{-c}
    let a2 = *g2 * proof.s + (-*vk) * proof.c;
    let a1 = *h * proof.s + (-*v) * proof.c;
    let c = dleq_challenge(g2, vk, h, v, &a2, &a1);
    c == proof.c
}

fn dleq_challenge(
    g2: &BlsG2,
    vk: &BlsG2,
    h: &BlsG1,
    v: &BlsG1,
    a2: &BlsG2,
    a1: &BlsG1,
) -> BlsScalar {
    let mut data = Vec::new();
    data.extend_from_slice(&bls::g2_to_bytes(g2));
    data.extend_from_slice(&bls::g2_to_bytes(vk));
    data.extend_from_slice(&bls::g1_to_bytes(h));
    data.extend_from_slice(&bls::g1_to_bytes(v));
    data.extend_from_slice(&bls::g2_to_bytes(a2));
    data.extend_from_slice(&bls::g1_to_bytes(a1));
    hash_to_scalar(b"VITARIT-DLEQ-chal", &data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    fn collect_shares(keys: &KeySet, m: &[u8], ids: &[usize]) -> Vec<(usize, PartialEval, PartialProof)> {
        ids.iter()
            .map(|&i| {
                let (v, pi) = Dvts::part_eval(&keys.partial_sks[i - 1], m);
                assert!(Dvts::part_verify(i, &keys.vk, &keys.partial_vks, m, &v, &pi));
                (i, v, pi)
            })
            .collect()
    }

    #[test]
    fn dvrf_threshold_roundtrip() {
        let mut rng = thread_rng();
        let keys = Dvts::dkgen(1, 3, &mut rng).unwrap();
        let m = b"request-m*";
        let shares = collect_shares(&keys, m, &[1, 2]);
        let (full, proof) = Dvts::combine(&keys.vk, &keys.partial_vks, m, &shares).unwrap();
        assert!(Dvts::verify(&keys.vk, &keys.partial_vks, m, &full, &proof));
    }

    #[test]
    fn dvrf_any_threshold_subset_reconstructs_same_value() {
        let mut rng = thread_rng();
        let t = 2;
        let n = 5;
        let keys = Dvts::dkgen(t, n, &mut rng).unwrap();
        let m = b"same-m";
        let a = collect_shares(&keys, m, &[1, 2, 3]);
        let b = collect_shares(&keys, m, &[2, 4, 5]);
        let (va, _) = Dvts::combine(&keys.vk, &keys.partial_vks, m, &a).unwrap();
        let (vb, _) = Dvts::combine(&keys.vk, &keys.partial_vks, m, &b).unwrap();
        assert_eq!(va.to_bytes(), vb.to_bytes());
    }

    #[test]
    fn dvrf_part_verify_rejects_wrong_index() {
        let mut rng = thread_rng();
        let keys = Dvts::dkgen(1, 3, &mut rng).unwrap();
        let m = b"m";
        let (v, pi) = Dvts::part_eval(&keys.partial_sks[0], m);
        assert!(!Dvts::part_verify(2, &keys.vk, &keys.partial_vks, m, &v, &pi));
        assert!(!Dvts::part_verify(0, &keys.vk, &keys.partial_vks, m, &v, &pi));
    }

    #[test]
    fn dvrf_part_verify_rejects_wrong_message() {
        let mut rng = thread_rng();
        let keys = Dvts::dkgen(1, 3, &mut rng).unwrap();
        let (v, pi) = Dvts::part_eval(&keys.partial_sks[0], b"good");
        assert!(!Dvts::part_verify(1, &keys.vk, &keys.partial_vks, b"bad", &v, &pi));
    }

    #[test]
    fn dvrf_combine_rejects_bad_share() {
        let mut rng = thread_rng();
        let keys = Dvts::dkgen(1, 3, &mut rng).unwrap();
        let m = b"m";
        let (v1, pi1) = Dvts::part_eval(&keys.partial_sks[0], m);
        let (v2, _) = Dvts::part_eval(&keys.partial_sks[1], m);
        // Pair v2 with pi1 — should fail PartVerify inside Combine.
        let shares = vec![(1, v1, pi1.clone()), (2, v2, pi1)];
        assert!(Dvts::combine(&keys.vk, &keys.partial_vks, m, &shares).is_err());
    }

    #[test]
    fn dvrf_dkgen_rejects_invalid_params() {
        let mut rng = thread_rng();
        assert!(Dvts::dkgen(0, 0, &mut rng).is_err());
        assert!(Dvts::dkgen(3, 3, &mut rng).is_err()); // t must be < n
        assert!(Dvts::dkgen(5, 3, &mut rng).is_err());
    }

    #[test]
    fn dvrf_verify_rejects_wrong_message() {
        let mut rng = thread_rng();
        let keys = Dvts::dkgen(1, 3, &mut rng).unwrap();
        let shares = collect_shares(&keys, b"orig", &[1, 2]);
        let (full, proof) = Dvts::combine(&keys.vk, &keys.partial_vks, b"orig", &shares).unwrap();
        assert!(!Dvts::verify(&keys.vk, &keys.partial_vks, b"other", &full, &proof));
    }

    #[test]
    fn dvrf_partial_eval_serde() {
        let mut rng = thread_rng();
        let keys = Dvts::dkgen(1, 3, &mut rng).unwrap();
        let (v, _) = Dvts::part_eval(&keys.partial_sks[0], b"m");
        let v2 = PartialEval::from_bytes(&v.to_bytes()).unwrap();
        assert_eq!(v, v2);
    }

    #[test]
    fn dvrf_t0_n1_degenerate() {
        let mut rng = thread_rng();
        let keys = Dvts::dkgen(0, 1, &mut rng).unwrap();
        let m = b"solo";
        let shares = collect_shares(&keys, m, &[1]);
        let (full, proof) = Dvts::combine(&keys.vk, &keys.partial_vks, m, &shares).unwrap();
        assert!(Dvts::verify(&keys.vk, &keys.partial_vks, m, &full, &proof));
    }
}
