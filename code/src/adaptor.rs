//! Adaptor signatures AS := (KGen, pSign, Adapt, pVf, Ext) w.r.t. R_DL
//! over Gp, as used in Figure 8.
//!
//! Pre-signature is bound to adaptor statement Y = gp^y (the VNE encryption
//! key). Adapting with witness y yields a Schnorr signature whose nonce
//! absorbs Y; extraction recovers y from (pre-sig, adapted-sig).

use crate::error::{Error, Result};
use crate::group::ristretto::{self, RistrettoPoint, RistrettoScalar};
use crate::schnorr::{Signature, SigningKey, VerificationKey};
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroize;

pub struct AdaptorSig;

/// Adaptor statement Y ∈ L_DL.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Statement(pub RistrettoPoint);

/// Adaptor witness y with Y = gp^y.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct Witness(pub RistrettoScalar);

/// Pre-signature σ̃ = (R, ŝ).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreSignature {
    pub r: RistrettoPoint,
    pub s_hat: RistrettoScalar,
}

impl AdaptorSig {
    /// KGen reuses the underlying Schnorr key generation.
    pub fn kgen<R: RngCore + CryptoRng>(rng: &mut R) -> (SigningKey, VerificationKey) {
        crate::schnorr::Ds::kgen(rng)
    }

    /// Sample (Y, y) ← Gen_R for R_DL.
    pub fn gen_statement<R: RngCore + CryptoRng>(rng: &mut R) -> (Statement, Witness) {
        let y = ristretto::random_scalar(rng);
        (Statement(ristretto::gp() * y), Witness(y))
    }

    /// σ̃ ← pSign(sk, m, Y)
    ///
    /// Pre-signature nonce is R; the adapted signature will use R·Y with the
    /// ordinary Schnorr challenge on (pk, R·Y, m). Adaptation adds the witness
    /// y so that s = ŝ + y verifies under DS.Vf.
    pub fn p_sign(sk: &SigningKey, msg: &[u8], y_stmt: &Statement) -> PreSignature {
        let mut seed = Vec::new();
        seed.extend_from_slice(&ristretto::scalar_to_bytes(&sk.0));
        seed.extend_from_slice(&ristretto::point_to_bytes(&y_stmt.0));
        seed.extend_from_slice(msg);
        let r_scalar = ristretto::hash_to_scalar(b"VITARIT-AS-nonce", &seed);
        let r = ristretto::gp() * r_scalar;
        let r_full = r + y_stmt.0;
        let pk = VerificationKey(ristretto::gp() * sk.0);
        // Same challenge as DS so Adapt(σ̃, y) yields a DS-verifiable signature.
        let c = schnorr_challenge(&pk, &r_full, msg);
        let s_hat = r_scalar + c * sk.0;
        PreSignature { r, s_hat }
    }

    /// 0/1 ← pVf(vk, m, Y, σ̃)
    pub fn p_vf(vk: &VerificationKey, msg: &[u8], y_stmt: &Statement, pre: &PreSignature) -> bool {
        let r_full = pre.r + y_stmt.0;
        let c = schnorr_challenge(vk, &r_full, msg);
        // g^{ŝ} ≟ R · pk^c
        ristretto::gp() * pre.s_hat == pre.r + vk.0 * c
    }

    /// σ ← Adapt(σ̃, y)
    pub fn adapt(
        vk: &VerificationKey,
        msg: &[u8],
        y_stmt: &Statement,
        pre: &PreSignature,
        wit: &Witness,
    ) -> Result<Signature> {
        if !Self::p_vf(vk, msg, y_stmt, pre) {
            return Err(Error::Verification("invalid pre-signature".into()));
        }
        let r_full = pre.r + y_stmt.0;
        // s = ŝ + y  (nonce absorbs Y as R·Y)
        let s = pre.s_hat + wit.0;
        let sig = Signature { r: r_full, s };
        if !crate::schnorr::Ds::vf(vk, msg, &sig) {
            return Err(Error::Verification("adapted signature does not verify".into()));
        }
        Ok(sig)
    }

    /// y ← Ext(σ̃, σ, Y)
    pub fn ext(
        vk: &VerificationKey,
        msg: &[u8],
        y_stmt: &Statement,
        pre: &PreSignature,
        sig: &Signature,
    ) -> Result<Witness> {
        if !crate::schnorr::Ds::vf(vk, msg, sig) {
            return Err(Error::Verification("invalid adapted signature".into()));
        }
        let r_full = pre.r + y_stmt.0;
        if sig.r != r_full {
            return Err(Error::Verification("adapted R mismatch".into()));
        }
        // s = ŝ + y  ⇒  y = s − ŝ
        let y = sig.s - pre.s_hat;
        if ristretto::gp() * y != y_stmt.0 {
            return Err(Error::Verification("extracted witness does not match Y".into()));
        }
        Ok(Witness(y))
    }
}

/// Shared with DS so adapted signatures verify under `Ds::vf`.
fn schnorr_challenge(vk: &VerificationKey, r: &RistrettoPoint, msg: &[u8]) -> RistrettoScalar {
    let mut data = Vec::new();
    data.extend_from_slice(&ristretto::point_to_bytes(&vk.0));
    data.extend_from_slice(&ristretto::point_to_bytes(r));
    data.extend_from_slice(msg);
    ristretto::hash_to_scalar(b"VITARIT-Schnorr-chal", &data)
}

impl Statement {
    pub fn from_encryption_key(ek: &crate::pkenc::EncryptionKey) -> Self {
        Statement(ek.as_point())
    }
}

impl Witness {
    pub fn from_decryption_key(dk: &crate::pkenc::DecryptionKey) -> Self {
        Witness(dk.as_scalar())
    }

    pub fn as_decryption_key(&self) -> crate::pkenc::DecryptionKey {
        crate::pkenc::DecryptionKey(self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pkenc::PkEnc;
    use rand::thread_rng;

    #[test]
    fn adaptor_flow() {
        let mut rng = thread_rng();
        let (sk, vk) = AdaptorSig::kgen(&mut rng);
        let (y_stmt, wit) = AdaptorSig::gen_statement(&mut rng);
        let msg = b"tx_pay";
        let pre = AdaptorSig::p_sign(&sk, msg, &y_stmt);
        assert!(AdaptorSig::p_vf(&vk, msg, &y_stmt, &pre));
        let sig = AdaptorSig::adapt(&vk, msg, &y_stmt, &pre, &wit).unwrap();
        assert!(crate::schnorr::Ds::vf(&vk, msg, &sig));
        let extracted = AdaptorSig::ext(&vk, msg, &y_stmt, &pre, &sig).unwrap();
        assert_eq!(
            ristretto::scalar_to_bytes(&extracted.0),
            ristretto::scalar_to_bytes(&wit.0)
        );
    }

    #[test]
    fn adaptor_pvf_rejects_wrong_statement() {
        let mut rng = thread_rng();
        let (sk, vk) = AdaptorSig::kgen(&mut rng);
        let (y1, _) = AdaptorSig::gen_statement(&mut rng);
        let (y2, _) = AdaptorSig::gen_statement(&mut rng);
        let pre = AdaptorSig::p_sign(&sk, b"m", &y1);
        assert!(AdaptorSig::p_vf(&vk, b"m", &y1, &pre));
        assert!(!AdaptorSig::p_vf(&vk, b"m", &y2, &pre));
    }

    #[test]
    fn adaptor_adapt_rejects_wrong_witness() {
        let mut rng = thread_rng();
        let (sk, vk) = AdaptorSig::kgen(&mut rng);
        let (y, _) = AdaptorSig::gen_statement(&mut rng);
        let (_, wrong_wit) = AdaptorSig::gen_statement(&mut rng);
        let pre = AdaptorSig::p_sign(&sk, b"m", &y);
        assert!(AdaptorSig::adapt(&vk, b"m", &y, &pre, &wrong_wit).is_err());
    }

    #[test]
    fn adaptor_from_pkenc_keys() {
        let mut rng = thread_rng();
        let (sk, vk) = AdaptorSig::kgen(&mut rng);
        let (ek, dk) = PkEnc::kgen(&mut rng);
        let y = Statement::from_encryption_key(&ek);
        let wit = Witness::from_decryption_key(&dk);
        let msg = b"payment";
        let pre = AdaptorSig::p_sign(&sk, msg, &y);
        let sig = AdaptorSig::adapt(&vk, msg, &y, &pre, &wit).unwrap();
        let extracted = AdaptorSig::ext(&vk, msg, &y, &pre, &sig).unwrap();
        assert_eq!(
            ristretto::scalar_to_bytes(&extracted.as_decryption_key().0),
            ristretto::scalar_to_bytes(&dk.0)
        );
    }

    #[test]
    fn adaptor_ext_rejects_unrelated_signature() {
        let mut rng = thread_rng();
        let (sk, vk) = AdaptorSig::kgen(&mut rng);
        let (y, wit) = AdaptorSig::gen_statement(&mut rng);
        let pre = AdaptorSig::p_sign(&sk, b"m", &y);
        let _sig = AdaptorSig::adapt(&vk, b"m", &y, &pre, &wit).unwrap();
        let ordinary = crate::schnorr::Ds::sign(&sk, b"m");
        assert!(AdaptorSig::ext(&vk, b"m", &y, &pre, &ordinary).is_err());
    }

    #[test]
    fn adaptor_pvf_rejects_wrong_message() {
        let mut rng = thread_rng();
        let (sk, vk) = AdaptorSig::kgen(&mut rng);
        let (y, _) = AdaptorSig::gen_statement(&mut rng);
        let pre = AdaptorSig::p_sign(&sk, b"good", &y);
        assert!(!AdaptorSig::p_vf(&vk, b"bad", &y, &pre));
    }
}
