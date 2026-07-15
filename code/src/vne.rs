//! Figure 9 — Concrete verifiable non-committing encryption (VNE).
//!
//! Exact signatures (Definition 6 / Figure 9):
//! ```text
//! KGen(1λ) → (ek, dk)           // same as PKEnc.KGen
//! Enc(ek, inst, wit, z) → ct
//! VfEnc(ek, inst, ct) → 0/1
//! Dec(dk, inst, ct) → wit
//! ```
//!
//! Cut-and-choose over 2λ_s PKEnc ciphertexts; unopened slots carry
//! Z_j := A_j^{b_j} · wit with a Schnorr NIZK for L′.

use crate::dvrf::{GlobalVk, PartialEval, PartialSk, PartialVk};
use crate::error::{Error, Result};
use crate::group::bls::{self, BlsG1, BlsScalar};
use crate::hash::hc_challenge_set;
use crate::nizk::{CrsLPrime, NizkLPrime, ProofLPrime, StmtLPrime, WitLPrime};
use crate::pkenc::{Ciphertext as PkCiphertext, DecryptionKey, EncRandomness, EncryptionKey, PkEnc};
use rand_core::{CryptoRng, RngCore};

/// Paper default: 2λ_s = 64 ⇒ λ_s = 32. Tests may use a smaller λ_s.
pub const DEFAULT_LAMBDA_S: usize = 32;

pub struct Vne;

/// Instance inst := (vk^{DVRF}, {vk_ℓ^{DVRF}}_ℓ, m*).
#[derive(Clone, Debug)]
pub struct Instance {
    pub server_index: usize,
    pub vk: GlobalVk,
    pub partial_vks: Vec<PartialVk>,
    pub msg: Vec<u8>,
}

/// Witness wit := v_i^{DVRF} ∈ G1.
pub type Witness = PartialEval;

/// Auxiliary z := sk_i^{DVRF}.
pub type Auxiliary = PartialSk;

/// Opened slot material (a_j, b_j, r_j) for j ∉ J.
#[derive(Clone)]
pub struct OpenedSlot {
    pub a: BlsScalar,
    pub b: BlsScalar,
    pub r: EncRandomness,
}

/// Unopened slot material (Z_j, stmt_j, π_j) for j ∈ J.
#[derive(Clone)]
pub struct UnopenedSlot {
    pub z: BlsG1,
    pub stmt: StmtLPrime,
    pub proof: ProofLPrime,
}

/// Ciphertext of Figure 9:
///   ct := ( (ct_j, A_j, B_j)_{j∈[2λs]}, S_op, S_unop )
#[derive(Clone)]
pub struct VneCiphertext {
    pub lambda_s: usize,
    pub cts: Vec<PkCiphertext>,
    pub a_pts: Vec<BlsG1>,
    pub b_pts: Vec<BlsG1>,
    pub opened: Vec<(usize, OpenedSlot)>,   // indices j ∉ J
    pub unopened: Vec<(usize, UnopenedSlot)>, // indices j ∈ J
}

impl Vne {
    /// (ek, dk) ← KGen(1λ)  — delegates to PKEnc.KGen (Figure 5 / Figure 9).
    pub fn kgen<R: RngCore + CryptoRng>(rng: &mut R) -> (EncryptionKey, DecryptionKey) {
        PkEnc::kgen(rng)
    }

    /// ct ← Enc(ek, inst, wit, z)
    pub fn enc<R: RngCore + CryptoRng>(
        ek: &EncryptionKey,
        inst: &Instance,
        wit: &Witness,
        z_aux: &Auxiliary,
        lambda_s: usize,
        crs: &CrsLPrime,
        rng: &mut R,
    ) -> Result<VneCiphertext> {
        if lambda_s == 0 {
            return Err(Error::InvalidInput("λ_s must be > 0".into()));
        }
        let total = 2 * lambda_s;
        let mut cts = Vec::with_capacity(total);
        let mut a_pts = Vec::with_capacity(total);
        let mut b_pts = Vec::with_capacity(total);
        let mut a_sc = Vec::with_capacity(total);
        let mut b_sc = Vec::with_capacity(total);
        let mut rands = Vec::with_capacity(total);
        let mut a_pow_b = Vec::with_capacity(total);

        for _ in 0..total {
            let aj = bls::random_scalar(rng);
            let bj = bls::random_scalar(rng);
            let aj_pt = bls::g1_generator() * aj;
            let bj_pt = bls::g1_generator() * bj;
            let ab = aj_pt * bj; // A_j^{b_j}
            let msg = bls::g1_to_bytes(&ab);
            let (ct_j, rand_j) = PkEnc::enc(ek, &msg, rng);
            a_sc.push(aj);
            b_sc.push(bj);
            a_pts.push(aj_pt);
            b_pts.push(bj_pt);
            a_pow_b.push(ab);
            cts.push(ct_j);
            rands.push(rand_j);
        }

        // J := Hc( (A_j, B_j, ct_j)_j ) with |J| = λ_s
        let challenge_bytes = challenge_bytes(&a_pts, &b_pts, &cts);
        let j_set = hc_challenge_set(&challenge_bytes, lambda_s);
        let j_is: Vec<bool> = {
            let mut v = vec![false; total];
            for &idx in &j_set {
                v[idx] = true;
            }
            v
        };

        let mut opened = Vec::new();
        let mut unopened = Vec::new();

        for j in 0..total {
            if !j_is[j] {
                // Opened: reveal (a_j, b_j, r_j)
                opened.push((
                    j,
                    OpenedSlot {
                        a: a_sc[j],
                        b: b_sc[j],
                        r: EncRandomness {
                            r: rands[j].r,
                            s: rands[j].s,
                        },
                    },
                ));
            } else {
                // Unopened: Z_j := A_j^{b_j} · v_i , prove L′
                let z_j = a_pow_b[j] + wit.0;
                let vk_i = inst
                    .partial_vks
                    .get(inst.server_index.wrapping_sub(1))
                    .ok_or_else(|| Error::InvalidInput("server_index out of range".into()))?;
                let stmt = NizkLPrime::make_stmt(
                    inst.server_index,
                    a_pts[j],
                    b_pts[j],
                    z_j,
                    vk_i,
                    &inst.msg,
                );
                let wit_j = WitLPrime {
                    b: b_sc[j],
                    sk_i: z_aux.0,
                };
                let proof = NizkLPrime::prove(crs, &stmt, &wit_j);
                unopened.push((
                    j,
                    UnopenedSlot {
                        z: z_j,
                        stmt,
                        proof,
                    },
                ));
            }
        }

        Ok(VneCiphertext {
            lambda_s,
            cts,
            a_pts,
            b_pts,
            opened,
            unopened,
        })
    }

    /// 0/1 ← VfEnc(ek, inst, ct)
    pub fn vf_enc(ek: &EncryptionKey, inst: &Instance, ct: &VneCiphertext, crs: &CrsLPrime) -> bool {
        let total = 2 * ct.lambda_s;
        if ct.cts.len() != total || ct.a_pts.len() != total || ct.b_pts.len() != total {
            return false;
        }
        // Recompute J
        let challenge_bytes = challenge_bytes(&ct.a_pts, &ct.b_pts, &ct.cts);
        let j_set = hc_challenge_set(&challenge_bytes, ct.lambda_s);
        let mut j_is = vec![false; total];
        for &idx in &j_set {
            j_is[idx] = true;
        }

        // Opened checks for j ∉ J
        if ct.opened.len() != ct.lambda_s {
            return false;
        }
        for (j, slot) in &ct.opened {
            if *j >= total || j_is[*j] {
                return false;
            }
            let aj_pt = bls::g1_generator() * slot.a;
            let bj_pt = bls::g1_generator() * slot.b;
            if aj_pt != ct.a_pts[*j] || bj_pt != ct.b_pts[*j] {
                return false;
            }
            let ab = aj_pt * slot.b;
            let msg = bls::g1_to_bytes(&ab);
            if !PkEnc::enc_equals(ek, &msg, &slot.r, &ct.cts[*j]) {
                return false;
            }
        }

        // Unopened checks for j ∈ J
        if ct.unopened.len() != ct.lambda_s {
            return false;
        }
        for (j, slot) in &ct.unopened {
            if *j >= total || !j_is[*j] {
                return false;
            }
            // stmt must match ciphertext components
            if slot.stmt.a != ct.a_pts[*j]
                || slot.stmt.b_pt != ct.b_pts[*j]
                || slot.stmt.z != slot.z
                || slot.stmt.server_index != inst.server_index
                || slot.stmt.msg != inst.msg
            {
                return false;
            }
            if slot.stmt.vk_i.0
                != inst
                    .partial_vks
                    .get(inst.server_index.wrapping_sub(1))
                    .map(|v| v.0)
                    .unwrap_or(bls::g2_generator())
            {
                return false;
            }
            if !NizkLPrime::verify(crs, &slot.stmt, &slot.proof) {
                return false;
            }
        }
        true
    }

    /// wit ← Dec(dk, inst, ct)
    ///
    /// By cut-and-choose, ∃ k ∈ J s.t. ct_k decrypts to A_k^{b_k}; then
    /// wit := Z_k · C_k^{-1}. We try every unopened slot and return the
    /// unique value consistent with PartVerify when possible.
    pub fn dec(dk: &DecryptionKey, inst: &Instance, ct: &VneCiphertext) -> Result<Witness> {
        let mut candidate: Option<BlsG1> = None;
        for (j, slot) in &ct.unopened {
            let bytes = PkEnc::dec(dk, &ct.cts[*j])?;
            let c_k = bls::g1_from_bytes(&bytes).ok_or_else(|| {
                Error::Decryption(format!("slot {j}: decrypted bytes not a G1 point"))
            })?;
            // wit = Z · C^{-1}
            let wit = slot.z - c_k;
            // Prefer a witness that verifies under the instance relation.
            if relation_holds(inst, &wit) {
                return Ok(PartialEval(wit));
            }
            candidate.get_or_insert(wit);
        }
        candidate
            .map(PartialEval)
            .ok_or_else(|| Error::Decryption("no unopened slot".into()))
    }
}

fn relation_holds(inst: &Instance, wit: &BlsG1) -> bool {
    use crate::group::bls::pairing_check_eq;
    let h = bls::hash_to_g1(&inst.msg);
    let Some(vk_i) = inst.partial_vks.get(inst.server_index.wrapping_sub(1)) else {
        return false;
    };
    // e(wit, g2) = e(H(m), vk_i)
    pairing_check_eq(wit, &bls::g2_generator(), &h, &vk_i.0)
}

fn challenge_bytes(a_pts: &[BlsG1], b_pts: &[BlsG1], cts: &[PkCiphertext]) -> Vec<u8> {
    let mut data = Vec::new();
    for i in 0..a_pts.len() {
        data.extend_from_slice(&bls::g1_to_bytes(&a_pts[i]));
        data.extend_from_slice(&bls::g1_to_bytes(&b_pts[i]));
        data.extend_from_slice(&cts[i].to_bytes());
    }
    data
}

/// Bind witness / aux helpers for callers.
impl Instance {
    pub fn new(
        server_index: usize,
        vk: GlobalVk,
        partial_vks: Vec<PartialVk>,
        msg: &[u8],
    ) -> Self {
        Self {
            server_index,
            vk,
            partial_vks,
            msg: msg.to_vec(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dvrf::Dvts;
    use crate::group::bls;
    use crate::nizk::NizkLPrime;
    use rand::thread_rng;
    use rand_core::{CryptoRng, RngCore};

    fn setup_inst(rng: &mut (impl RngCore + CryptoRng)) -> (Instance, Witness, Auxiliary) {
        let keys = Dvts::dkgen(1, 3, rng).unwrap();
        let i = 1usize;
        let m = b"m-star";
        let (wit, _) = Dvts::part_eval(&keys.partial_sks[i - 1], m);
        let inst = Instance::new(i, keys.vk.clone(), keys.partial_vks.clone(), m);
        let z_aux = keys.partial_sks[i - 1].clone();
        (inst, wit, z_aux)
    }

    #[test]
    fn vne_fig9_roundtrip() {
        let mut rng = thread_rng();
        let (inst, wit, z_aux) = setup_inst(&mut rng);
        let (ek, dk) = Vne::kgen(&mut rng);
        let crs = NizkLPrime::setup();
        let lambda_s = 4;
        let ct = Vne::enc(&ek, &inst, &wit, &z_aux, lambda_s, &crs, &mut rng).unwrap();
        assert!(Vne::vf_enc(&ek, &inst, &ct, &crs));
        let got = Vne::dec(&dk, &inst, &ct).unwrap();
        assert_eq!(got.to_bytes(), wit.to_bytes());
    }

    #[test]
    fn vne_rejects_lambda_s_zero() {
        let mut rng = thread_rng();
        let (inst, wit, z_aux) = setup_inst(&mut rng);
        let (ek, _) = Vne::kgen(&mut rng);
        let crs = NizkLPrime::setup();
        assert!(Vne::enc(&ek, &inst, &wit, &z_aux, 0, &crs, &mut rng).is_err());
    }

    #[test]
    fn vne_vf_enc_rejects_tampered_opened_slot() {
        let mut rng = thread_rng();
        let (inst, wit, z_aux) = setup_inst(&mut rng);
        let (ek, _) = Vne::kgen(&mut rng);
        let crs = NizkLPrime::setup();
        let mut ct = Vne::enc(&ek, &inst, &wit, &z_aux, 4, &crs, &mut rng).unwrap();
        // Flip a byte in the first opened ciphertext.
        let j = ct.opened[0].0;
        ct.cts[j].c3[0] ^= 0xff;
        assert!(!Vne::vf_enc(&ek, &inst, &ct, &crs));
    }

    #[test]
    fn vne_vf_enc_rejects_tampered_unopened_proof() {
        let mut rng = thread_rng();
        let (inst, wit, z_aux) = setup_inst(&mut rng);
        let (ek, _) = Vne::kgen(&mut rng);
        let crs = NizkLPrime::setup();
        let mut ct = Vne::enc(&ek, &inst, &wit, &z_aux, 4, &crs, &mut rng).unwrap();
        ct.unopened[0].1.z = bls::g1_generator();
        ct.unopened[0].1.stmt.z = bls::g1_generator();
        assert!(!Vne::vf_enc(&ek, &inst, &ct, &crs));
    }

    #[test]
    fn vne_wrong_dk_yields_invalid_witness() {
        let mut rng = thread_rng();
        let (inst, wit, z_aux) = setup_inst(&mut rng);
        let (ek, _) = Vne::kgen(&mut rng);
        let (_ek2, dk2) = Vne::kgen(&mut rng);
        let crs = NizkLPrime::setup();
        let ct = Vne::enc(&ek, &inst, &wit, &z_aux, 4, &crs, &mut rng).unwrap();
        // Dec may return Some garbage point, but it must not equal the real witness.
        match Vne::dec(&dk2, &inst, &ct) {
            Ok(got) => assert_ne!(got.to_bytes(), wit.to_bytes()),
            Err(_) => {} // also acceptable if G1 parse fails
        }
    }

    #[test]
    fn vne_cut_and_choose_slot_counts() {
        let mut rng = thread_rng();
        let (inst, wit, z_aux) = setup_inst(&mut rng);
        let (ek, _) = Vne::kgen(&mut rng);
        let crs = NizkLPrime::setup();
        for lambda_s in [2usize, 4, 8] {
            let ct = Vne::enc(&ek, &inst, &wit, &z_aux, lambda_s, &crs, &mut rng).unwrap();
            assert_eq!(ct.cts.len(), 2 * lambda_s);
            assert_eq!(ct.opened.len(), lambda_s);
            assert_eq!(ct.unopened.len(), lambda_s);
            assert!(Vne::vf_enc(&ek, &inst, &ct, &crs));
        }
    }

    #[test]
    fn vne_vf_enc_rejects_wrong_ek() {
        let mut rng = thread_rng();
        let (inst, wit, z_aux) = setup_inst(&mut rng);
        let (ek, _) = Vne::kgen(&mut rng);
        let (ek2, _) = Vne::kgen(&mut rng);
        let crs = NizkLPrime::setup();
        let ct = Vne::enc(&ek, &inst, &wit, &z_aux, 4, &crs, &mut rng).unwrap();
        assert!(!Vne::vf_enc(&ek2, &inst, &ct, &crs));
    }
}
