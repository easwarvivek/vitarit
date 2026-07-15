//! Schnorr digital signatures over Gp (paper DS := (KGen, Sign, Vf)).

use crate::error::{Error, Result};
use crate::group::ristretto::{self, RistrettoPoint, RistrettoScalar};
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroize;

pub struct Ds;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerificationKey(pub RistrettoPoint);

#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct SigningKey(pub RistrettoScalar);

// Note: Clone copies the secret; callers should treat clones as sensitive.

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature {
    pub r: RistrettoPoint,
    pub s: RistrettoScalar,
}

impl Ds {
    pub fn kgen<R: RngCore + CryptoRng>(rng: &mut R) -> (SigningKey, VerificationKey) {
        let sk = ristretto::random_scalar(rng);
        let vk = VerificationKey(ristretto::gp() * sk);
        (SigningKey(sk), vk)
    }

    pub fn sign(sk: &SigningKey, msg: &[u8]) -> Signature {
        // Deterministic nonce from sk || msg for simplicity of testing.
        let mut seed = Vec::with_capacity(32 + msg.len());
        seed.extend_from_slice(&ristretto::scalar_to_bytes(&sk.0));
        seed.extend_from_slice(msg);
        let k = ristretto::hash_to_scalar(b"VITARIT-Schnorr-nonce", &seed);
        let r = ristretto::gp() * k;
        let c = challenge(&VerificationKey(ristretto::gp() * sk.0), &r, msg);
        let s = k + c * sk.0;
        Signature { r, s }
    }

    pub fn vf(vk: &VerificationKey, msg: &[u8], sig: &Signature) -> bool {
        let c = challenge(vk, &sig.r, msg);
        // g^s ≟ R · pk^c
        ristretto::gp() * sig.s == sig.r + vk.0 * c
    }
}

fn challenge(vk: &VerificationKey, r: &RistrettoPoint, msg: &[u8]) -> RistrettoScalar {
    let mut data = Vec::new();
    data.extend_from_slice(&ristretto::point_to_bytes(&vk.0));
    data.extend_from_slice(&ristretto::point_to_bytes(r));
    data.extend_from_slice(msg);
    ristretto::hash_to_scalar(b"VITARIT-Schnorr-chal", &data)
}

impl VerificationKey {
    pub fn to_bytes(&self) -> [u8; 32] {
        ristretto::point_to_bytes(&self.0)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        ristretto::point_from_bytes(bytes)
            .map(VerificationKey)
            .ok_or_else(|| Error::Serialization("invalid Schnorr vk".into()))
    }
}

impl SigningKey {
    pub fn to_bytes(&self) -> [u8; 32] {
        ristretto::scalar_to_bytes(&self.0)
    }
}

impl Signature {
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&ristretto::point_to_bytes(&self.r));
        out[32..].copy_from_slice(&ristretto::scalar_to_bytes(&self.s));
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 64 {
            return Err(Error::Serialization("bad signature length".into()));
        }
        let r = ristretto::point_from_bytes(&bytes[..32])
            .ok_or_else(|| Error::Serialization("bad R".into()))?;
        let s = ristretto::scalar_from_bytes(&bytes[32..])
            .ok_or_else(|| Error::Serialization("bad s".into()))?;
        Ok(Signature { r, s })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    #[test]
    fn schnorr_sign_verify() {
        let mut rng = thread_rng();
        let (sk, vk) = Ds::kgen(&mut rng);
        let msg = b"pay tx";
        let sig = Ds::sign(&sk, msg);
        assert!(Ds::vf(&vk, msg, &sig));
        assert!(!Ds::vf(&vk, b"other", &sig));
    }

    #[test]
    fn schnorr_wrong_key_rejects() {
        let mut rng = thread_rng();
        let (sk, _vk) = Ds::kgen(&mut rng);
        let (_sk2, vk2) = Ds::kgen(&mut rng);
        let sig = Ds::sign(&sk, b"m");
        assert!(!Ds::vf(&vk2, b"m", &sig));
    }

    #[test]
    fn schnorr_deterministic_for_same_inputs() {
        let mut rng = thread_rng();
        let (sk, vk) = Ds::kgen(&mut rng);
        let msg = b"same";
        let s1 = Ds::sign(&sk, msg);
        let s2 = Ds::sign(&sk, msg);
        assert_eq!(s1, s2);
        assert!(Ds::vf(&vk, msg, &s1));
    }

    #[test]
    fn schnorr_signature_serde_roundtrip() {
        let mut rng = thread_rng();
        let (sk, vk) = Ds::kgen(&mut rng);
        let sig = Ds::sign(&sk, b"serde");
        let sig2 = Signature::from_bytes(&sig.to_bytes()).unwrap();
        assert_eq!(sig, sig2);
        assert!(Ds::vf(&vk, b"serde", &sig2));
    }

    #[test]
    fn schnorr_signature_from_bytes_rejects_bad_len() {
        assert!(Signature::from_bytes(&[0u8; 10]).is_err());
    }

    #[test]
    fn schnorr_vk_serde_roundtrip() {
        let mut rng = thread_rng();
        let (_, vk) = Ds::kgen(&mut rng);
        let vk2 = VerificationKey::from_bytes(&vk.to_bytes()).unwrap();
        assert_eq!(vk, vk2);
    }

    #[test]
    fn schnorr_empty_message() {
        let mut rng = thread_rng();
        let (sk, vk) = Ds::kgen(&mut rng);
        let sig = Ds::sign(&sk, b"");
        assert!(Ds::vf(&vk, b"", &sig));
    }
}
