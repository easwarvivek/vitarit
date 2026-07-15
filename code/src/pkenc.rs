//! Figure 5 — Concrete non-committing public-key encryption (PKEnc).
//!
//! Hashed ElGamal over Gp with random-oracle Hm.
//!
//! Exact signatures from the paper:
//! ```text
//! KGen(1λ) → (ek, dk)
//! Enc(ek, m) → c = (c1, c2, c3)
//! Dec(dk, c) → m
//! ```

use crate::error::{Error, Result};
use crate::group::ristretto::{self, RistrettoPoint, RistrettoScalar};
use crate::hash::{hm, xor_bytes};
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroize;

/// Marker module so call sites read `PKE.KGen` / `PKE.Enc` / `PKE.Dec`
/// exactly as in Figures 5 / 6 / 9 (`PKE^{nc}` / `PKEnc`).
pub struct PkEnc;

/// Encryption key ek := gp^x ∈ Gp.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncryptionKey(pub RistrettoPoint);

/// Decryption key dk := x ∈ Zp.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct DecryptionKey(pub RistrettoScalar);

/// Ciphertext c := (c1, c2, c3) of Figure 5.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ciphertext {
    pub c1: RistrettoPoint,
    pub c2: RistrettoPoint,
    /// c3 := Hm(gp^s) ⊕ m
    pub c3: Vec<u8>,
}

/// Explicit encryption randomness (r, s) ∈ Zp² — used by VNE opened-set checks.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct EncRandomness {
    pub r: RistrettoScalar,
    pub s: RistrettoScalar,
}

impl PkEnc {
    /// KGen(1λ): sample x ← Zp; set ek := gp^x, dk := x.
    pub fn kgen<R: RngCore + CryptoRng>(rng: &mut R) -> (EncryptionKey, DecryptionKey) {
        let x = ristretto::random_scalar(rng);
        let ek = EncryptionKey(ristretto::gp() * x);
        let dk = DecryptionKey(x);
        (ek, dk)
    }

    /// Enc(ek, m): sample r, s ← Zp;
    /// c1 := gp^r,  c2 := ek^r · gp^s,  c3 := Hm(gp^s) ⊕ m.
    ///
    /// Returns the ciphertext together with the encryption randomness
    /// (needed by VNE opened-set checks in Figure 9).
    pub fn enc<R: RngCore + CryptoRng>(
        ek: &EncryptionKey,
        m: &[u8],
        rng: &mut R,
    ) -> (Ciphertext, EncRandomness) {
        let rand = EncRandomness {
            r: ristretto::random_scalar(rng),
            s: ristretto::random_scalar(rng),
        };
        let ct = Self::enc_with_randomness(ek, m, &rand);
        (ct, rand)
    }

    /// Enc with caller-supplied randomness `(r, s)`.
    pub fn enc_with_randomness(
        ek: &EncryptionKey,
        m: &[u8],
        rand: &EncRandomness,
    ) -> Ciphertext {
        let c1 = ristretto::gp() * rand.r;
        let c2 = ek.0 * rand.r + ristretto::gp() * rand.s;
        let gp_s = ristretto::gp() * rand.s;
        let mask = hm(&ristretto::point_to_bytes(&gp_s), m.len());
        let c3 = xor_bytes(m, &mask);
        Ciphertext { c1, c2, c3 }
    }

    /// Dec(dk, c): return m := c3 ⊕ Hm( c2 / c1^{dk} ).
    pub fn dec(dk: &DecryptionKey, c: &Ciphertext) -> Result<Vec<u8>> {
        // gps := c2 / c1^{dk} = c2 · c1^{-dk}
        let c1_dk = c.c1 * dk.0;
        let gp_s = c.c2 - c1_dk;
        let mask = hm(&ristretto::point_to_bytes(&gp_s), c.c3.len());
        Ok(xor_bytes(&c.c3, &mask))
    }

    /// Deterministic re-encryption check used by VNE.VfEnc on the opened set:
    /// ct ≟ PKEnc.Enc(ek, m; r).
    pub fn enc_equals(ek: &EncryptionKey, m: &[u8], rand: &EncRandomness, ct: &Ciphertext) -> bool {
        let expected = Self::enc_with_randomness(ek, m, rand);
        expected.c1 == ct.c1 && expected.c2 == ct.c2 && expected.c3 == ct.c3
    }
}

impl EncryptionKey {
    pub fn to_bytes(&self) -> [u8; 32] {
        ristretto::point_to_bytes(&self.0)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        ristretto::point_from_bytes(bytes)
            .map(EncryptionKey)
            .ok_or_else(|| Error::Serialization("invalid PKEnc encryption key".into()))
    }

    /// As adaptor statement Y ∈ L_DL (Y = gp^{dk}).
    pub fn as_point(&self) -> RistrettoPoint {
        self.0
    }
}

impl DecryptionKey {
    pub fn to_bytes(&self) -> [u8; 32] {
        ristretto::scalar_to_bytes(&self.0)
    }

    pub fn as_scalar(&self) -> RistrettoScalar {
        self.0
    }
}

impl Ciphertext {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64 + 8 + self.c3.len());
        out.extend_from_slice(&ristretto::point_to_bytes(&self.c1));
        out.extend_from_slice(&ristretto::point_to_bytes(&self.c2));
        out.extend_from_slice(&(self.c3.len() as u64).to_le_bytes());
        out.extend_from_slice(&self.c3);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 72 {
            return Err(Error::Serialization("PKEnc ciphertext too short".into()));
        }
        let c1 = ristretto::point_from_bytes(&bytes[0..32])
            .ok_or_else(|| Error::Serialization("bad c1".into()))?;
        let c2 = ristretto::point_from_bytes(&bytes[32..64])
            .ok_or_else(|| Error::Serialization("bad c2".into()))?;
        let len = u64::from_le_bytes(bytes[64..72].try_into().unwrap()) as usize;
        if bytes.len() != 72 + len {
            return Err(Error::Serialization("bad c3 length".into()));
        }
        Ok(Ciphertext {
            c1,
            c2,
            c3: bytes[72..].to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    #[test]
    fn pkenc_roundtrip() {
        let mut rng = thread_rng();
        let (ek, dk) = PkEnc::kgen(&mut rng);
        let msg = [7u8; 48];
        let (ct, _) = PkEnc::enc(&ek, &msg, &mut rng);
        let pt = PkEnc::dec(&dk, &ct).unwrap();
        assert_eq!(pt, msg);
    }

    #[test]
    fn pkenc_enc_equals_check() {
        let mut rng = thread_rng();
        let (ek, _) = PkEnc::kgen(&mut rng);
        let msg = vec![7u8; 48];
        let (ct, rand) = PkEnc::enc(&ek, &msg, &mut rng);
        assert!(PkEnc::enc_equals(&ek, &msg, &rand, &ct));
    }

    #[test]
    fn pkenc_wrong_key_fails_to_recover() {
        let mut rng = thread_rng();
        let (ek, _dk) = PkEnc::kgen(&mut rng);
        let (_ek2, dk2) = PkEnc::kgen(&mut rng);
        let msg = [9u8; 48];
        let (ct, _) = PkEnc::enc(&ek, &msg, &mut rng);
        let pt = PkEnc::dec(&dk2, &ct).unwrap();
        assert_ne!(pt, msg);
    }

    #[test]
    fn pkenc_enc_equals_rejects_tampered_ciphertext() {
        let mut rng = thread_rng();
        let (ek, _) = PkEnc::kgen(&mut rng);
        let msg = vec![1u8; 32];
        let (mut ct, rand) = PkEnc::enc(&ek, &msg, &mut rng);
        ct.c3[0] ^= 0xff;
        assert!(!PkEnc::enc_equals(&ek, &msg, &rand, &ct));
    }

    #[test]
    fn pkenc_enc_equals_rejects_wrong_message() {
        let mut rng = thread_rng();
        let (ek, _) = PkEnc::kgen(&mut rng);
        let msg = vec![1u8; 32];
        let (ct, rand) = PkEnc::enc(&ek, &msg, &mut rng);
        let wrong = vec![2u8; 32];
        assert!(!PkEnc::enc_equals(&ek, &wrong, &rand, &ct));
    }

    #[test]
    fn pkenc_ciphertext_serde_roundtrip() {
        let mut rng = thread_rng();
        let (ek, dk) = PkEnc::kgen(&mut rng);
        let msg = [3u8; 48];
        let (ct, _) = PkEnc::enc(&ek, &msg, &mut rng);
        let bytes = ct.to_bytes();
        let ct2 = Ciphertext::from_bytes(&bytes).unwrap();
        assert_eq!(ct, ct2);
        assert_eq!(PkEnc::dec(&dk, &ct2).unwrap(), msg);
    }

    #[test]
    fn pkenc_ciphertext_from_bytes_rejects_short() {
        assert!(Ciphertext::from_bytes(&[0u8; 10]).is_err());
    }

    #[test]
    fn pkenc_ek_serde_roundtrip() {
        let mut rng = thread_rng();
        let (ek, _) = PkEnc::kgen(&mut rng);
        let ek2 = EncryptionKey::from_bytes(&ek.to_bytes()).unwrap();
        assert_eq!(ek, ek2);
    }

    #[test]
    fn pkenc_empty_message() {
        let mut rng = thread_rng();
        let (ek, dk) = PkEnc::kgen(&mut rng);
        let msg: &[u8] = b"";
        let (ct, _) = PkEnc::enc(&ek, msg, &mut rng);
        assert!(ct.c3.is_empty());
        assert_eq!(PkEnc::dec(&dk, &ct).unwrap(), msg);
    }

    #[test]
    fn pkenc_variable_message_lengths() {
        let mut rng = thread_rng();
        let (ek, dk) = PkEnc::kgen(&mut rng);
        for len in [1usize, 16, 48, 64, 128] {
            let msg = vec![0xab; len];
            let (ct, rand) = PkEnc::enc(&ek, &msg, &mut rng);
            assert!(PkEnc::enc_equals(&ek, &msg, &rand, &ct));
            assert_eq!(PkEnc::dec(&dk, &ct).unwrap(), msg);
        }
    }
}
