//! Length-prefixed wire encoding for Γ²ᵖᶜ / VNE messages (off-chain channel).
//!
//! Format: `VIT1` magic || u32 BE length || payload.
//! Payloads are self-describing tagged structs (see `MsgTag`).

use crate::adaptor::{PreSignature, Statement};
use crate::dvrf::{GlobalVk, PartialEval, PartialProof, PartialVk};
use crate::error::{Error, Result};
use crate::group::bls::{self, BlsG1, BlsG2, BlsScalar};
use crate::group::ristretto::{self, RistrettoPoint, RistrettoScalar};
use crate::nizk::{ProofLPrime, StmtLPrime};
use crate::pkenc::{Ciphertext as PkCiphertext, EncryptionKey, EncRandomness};
use crate::schnorr::{Signature, VerificationKey};
use crate::vne::{Instance, OpenedSlot, UnopenedSlot, VneCiphertext};

const MAGIC: &[u8; 4] = b"VIT1";

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MsgTag {
    ServerOffer = 1,
    ClientPresig = 2,
    ServerFinal = 3,
}

/// Server → client: encryption key + VNE ciphertext (+ instance metadata).
#[derive(Clone)]
pub struct WireServerOffer {
    pub ek: EncryptionKey,
    pub ct: VneCiphertext,
    pub inst: Instance,
}

/// Client → server: adaptor statement + pre-signature.
#[derive(Clone, Debug)]
pub struct WireClientPresig {
    pub y: Statement,
    pub pre: PreSignature,
    /// BIP143/sighash (or abstract tx bytes) that was pre-signed.
    pub sighash_msg: Vec<u8>,
}

/// Server → client after Adapt + on-chain publish:
/// adapted adaptor signature (for Ext) and raw Bitcoin payment tx (if any).
#[derive(Clone, Debug)]
pub struct WireServerFinal {
    pub adapted: Signature,
    pub bitcoin_tx_hex: String,
    pub server_index: usize,
    pub deposit_index: usize,
}

impl WireServerOffer {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut body = Vec::new();
        body.push(MsgTag::ServerOffer as u8);
        write_bytes32(&mut body, &self.ek.to_bytes());
        write_vne_ct(&mut body, &self.ct)?;
        write_instance(&mut body, &self.inst)?;
        frame(&body)
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        let body = unframe(data)?;
        let mut r = Reader::new(&body);
        let tag = r.u8()?;
        if tag != MsgTag::ServerOffer as u8 {
            return Err(Error::Serialization(format!("expected ServerOffer tag, got {tag}")));
        }
        let ek = EncryptionKey::from_bytes(&r.bytes32()?)?;
        let ct = read_vne_ct(&mut r)?;
        let inst = read_instance(&mut r)?;
        Ok(Self { ek, ct, inst })
    }
}

impl WireClientPresig {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut body = Vec::new();
        body.push(MsgTag::ClientPresig as u8);
        write_point(&mut body, &self.y.0);
        write_point(&mut body, &self.pre.r);
        write_scalar_r(&mut body, &self.pre.s_hat);
        write_varbytes(&mut body, &self.sighash_msg);
        frame(&body)
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        let body = unframe(data)?;
        let mut r = Reader::new(&body);
        let tag = r.u8()?;
        if tag != MsgTag::ClientPresig as u8 {
            return Err(Error::Serialization(format!("expected ClientPresig tag, got {tag}")));
        }
        let y = Statement(read_point(&mut r)?);
        let pre = PreSignature {
            r: read_point(&mut r)?,
            s_hat: read_scalar_r(&mut r)?,
        };
        let sighash_msg = read_varbytes(&mut r)?;
        Ok(Self { y, pre, sighash_msg })
    }
}

impl WireServerFinal {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut body = Vec::new();
        body.push(MsgTag::ServerFinal as u8);
        write_point(&mut body, &self.adapted.r);
        write_scalar_r(&mut body, &self.adapted.s);
        write_varbytes(&mut body, self.bitcoin_tx_hex.as_bytes());
        write_u64(&mut body, self.server_index as u64);
        write_u64(&mut body, self.deposit_index as u64);
        frame(&body)
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        let body = unframe(data)?;
        let mut r = Reader::new(&body);
        let tag = r.u8()?;
        if tag != MsgTag::ServerFinal as u8 {
            return Err(Error::Serialization(format!("expected ServerFinal tag, got {tag}")));
        }
        let adapted = Signature {
            r: read_point(&mut r)?,
            s: read_scalar_r(&mut r)?,
        };
        let bitcoin_tx_hex = String::from_utf8(read_varbytes(&mut r)?)
            .map_err(|e| Error::Serialization(e.to_string()))?;
        let server_index = r.u64()? as usize;
        let deposit_index = r.u64()? as usize;
        Ok(Self {
            adapted,
            bitcoin_tx_hex,
            server_index,
            deposit_index,
        })
    }
}

fn frame(body: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(8 + body.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(body);
    Ok(out)
}

fn unframe(data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < 8 || &data[0..4] != MAGIC {
        return Err(Error::Serialization("bad magic".into()));
    }
    let len = u32::from_be_bytes(data[4..8].try_into().unwrap()) as usize;
    if data.len() != 8 + len {
        return Err(Error::Serialization(format!(
            "length mismatch: header {len}, got {}",
            data.len() - 8
        )));
    }
    Ok(data[8..].to_vec())
}

struct Reader<'a> {
    buf: &'a [u8],
    i: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, i: 0 }
    }
    fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.i)
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.remaining() < n {
            return Err(Error::Serialization("unexpected EOF".into()));
        }
        let s = &self.buf[self.i..self.i + n];
        self.i += n;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn u64(&mut self) -> Result<u64> {
        let b = self.take(8)?;
        Ok(u64::from_be_bytes(b.try_into().unwrap()))
    }
    fn bytes32(&mut self) -> Result<[u8; 32]> {
        let b = self.take(32)?;
        let mut a = [0u8; 32];
        a.copy_from_slice(b);
        Ok(a)
    }
}

fn write_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_be_bytes());
}
fn write_bytes32(out: &mut Vec<u8>, b: &[u8; 32]) {
    out.extend_from_slice(b);
}
fn write_varbytes(out: &mut Vec<u8>, b: &[u8]) {
    write_u64(out, b.len() as u64);
    out.extend_from_slice(b);
}
fn read_varbytes(r: &mut Reader<'_>) -> Result<Vec<u8>> {
    let n = r.u64()? as usize;
    Ok(r.take(n)?.to_vec())
}

fn write_point(out: &mut Vec<u8>, p: &RistrettoPoint) {
    write_bytes32(out, &ristretto::point_to_bytes(p));
}
fn read_point(r: &mut Reader<'_>) -> Result<RistrettoPoint> {
    ristretto::point_from_bytes(&r.bytes32()?)
        .ok_or_else(|| Error::Serialization("bad ristretto point".into()))
}
fn write_scalar_r(out: &mut Vec<u8>, s: &RistrettoScalar) {
    write_bytes32(out, &ristretto::scalar_to_bytes(s));
}
fn read_scalar_r(r: &mut Reader<'_>) -> Result<RistrettoScalar> {
    ristretto::scalar_from_bytes(&r.bytes32()?)
        .ok_or_else(|| Error::Serialization("bad ristretto scalar".into()))
}

fn write_g1(out: &mut Vec<u8>, p: &BlsG1) {
    out.extend_from_slice(&bls::g1_to_bytes(p));
}
fn read_g1(r: &mut Reader<'_>) -> Result<BlsG1> {
    let b = r.take(48)?;
    bls::g1_from_bytes(b).ok_or_else(|| Error::Serialization("bad G1".into()))
}
fn write_g2(out: &mut Vec<u8>, p: &BlsG2) {
    out.extend_from_slice(&bls::g2_to_bytes(p));
}
fn read_g2(r: &mut Reader<'_>) -> Result<BlsG2> {
    let b = r.take(96)?;
    bls::g2_from_bytes(b).ok_or_else(|| Error::Serialization("bad G2".into()))
}
fn write_bls_scalar(out: &mut Vec<u8>, s: &BlsScalar) {
    write_bytes32(out, &bls::scalar_to_bytes(s));
}
fn read_bls_scalar(r: &mut Reader<'_>) -> Result<BlsScalar> {
    bls::scalar_from_bytes(&r.bytes32()?)
        .ok_or_else(|| Error::Serialization("bad bls scalar".into()))
}

fn write_pk_ct(out: &mut Vec<u8>, ct: &PkCiphertext) {
    let bytes = ct.to_bytes();
    write_varbytes(out, &bytes);
}
fn read_pk_ct(r: &mut Reader<'_>) -> Result<PkCiphertext> {
    PkCiphertext::from_bytes(&read_varbytes(r)?)
}

fn write_instance(out: &mut Vec<u8>, inst: &Instance) -> Result<()> {
    write_u64(out, inst.server_index as u64);
    write_g2(out, &inst.vk.0);
    write_u64(out, inst.partial_vks.len() as u64);
    for vk in &inst.partial_vks {
        write_g2(out, &vk.0);
    }
    write_varbytes(out, &inst.msg);
    Ok(())
}

fn read_instance(r: &mut Reader<'_>) -> Result<Instance> {
    let server_index = r.u64()? as usize;
    let vk = GlobalVk(read_g2(r)?);
    let n = r.u64()? as usize;
    let mut partial_vks = Vec::with_capacity(n);
    for _ in 0..n {
        partial_vks.push(PartialVk(read_g2(r)?));
    }
    let msg = read_varbytes(r)?;
    Ok(Instance {
        server_index,
        vk,
        partial_vks,
        msg,
    })
}

fn write_vne_ct(out: &mut Vec<u8>, ct: &VneCiphertext) -> Result<()> {
    write_u64(out, ct.lambda_s as u64);
    let total = ct.cts.len();
    write_u64(out, total as u64);
    for i in 0..total {
        write_pk_ct(out, &ct.cts[i]);
        write_g1(out, &ct.a_pts[i]);
        write_g1(out, &ct.b_pts[i]);
    }
    write_u64(out, ct.opened.len() as u64);
    for (j, slot) in &ct.opened {
        write_u64(out, *j as u64);
        write_bls_scalar(out, &slot.a);
        write_bls_scalar(out, &slot.b);
        write_scalar_r(out, &slot.r.r);
        write_scalar_r(out, &slot.r.s);
    }
    write_u64(out, ct.unopened.len() as u64);
    for (j, slot) in &ct.unopened {
        write_u64(out, *j as u64);
        write_g1(out, &slot.z);
        write_stmt(out, &slot.stmt)?;
        write_proof(out, &slot.proof)?;
    }
    Ok(())
}

fn read_vne_ct(r: &mut Reader<'_>) -> Result<VneCiphertext> {
    let lambda_s = r.u64()? as usize;
    let total = r.u64()? as usize;
    let mut cts = Vec::with_capacity(total);
    let mut a_pts = Vec::with_capacity(total);
    let mut b_pts = Vec::with_capacity(total);
    for _ in 0..total {
        cts.push(read_pk_ct(r)?);
        a_pts.push(read_g1(r)?);
        b_pts.push(read_g1(r)?);
    }
    let n_op = r.u64()? as usize;
    let mut opened = Vec::with_capacity(n_op);
    for _ in 0..n_op {
        let j = r.u64()? as usize;
        opened.push((
            j,
            OpenedSlot {
                a: read_bls_scalar(r)?,
                b: read_bls_scalar(r)?,
                r: EncRandomness {
                    r: read_scalar_r(r)?,
                    s: read_scalar_r(r)?,
                },
            },
        ));
    }
    let n_un = r.u64()? as usize;
    let mut unopened = Vec::with_capacity(n_un);
    for _ in 0..n_un {
        let j = r.u64()? as usize;
        let z = read_g1(r)?;
        let stmt = read_stmt(r)?;
        let proof = read_proof(r)?;
        unopened.push((j, UnopenedSlot { z, stmt, proof }));
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

fn write_stmt(out: &mut Vec<u8>, s: &StmtLPrime) -> Result<()> {
    write_u64(out, s.server_index as u64);
    write_g1(out, &s.a);
    write_g1(out, &s.b_pt);
    write_g1(out, &s.z);
    write_g2(out, &s.vk_i.0);
    write_varbytes(out, &s.msg);
    Ok(())
}

fn read_stmt(r: &mut Reader<'_>) -> Result<StmtLPrime> {
    Ok(StmtLPrime {
        server_index: r.u64()? as usize,
        a: read_g1(r)?,
        b_pt: read_g1(r)?,
        z: read_g1(r)?,
        vk_i: PartialVk(read_g2(r)?),
        msg: read_varbytes(r)?,
    })
}

fn write_proof(out: &mut Vec<u8>, p: &ProofLPrime) -> Result<()> {
    write_g1(out, &p.r_b);
    write_g1(out, &p.r_z);
    write_g2(out, &p.r_vk);
    write_bls_scalar(out, &p.s_b);
    write_bls_scalar(out, &p.s_sk);
    Ok(())
}

fn read_proof(r: &mut Reader<'_>) -> Result<ProofLPrime> {
    Ok(ProofLPrime {
        r_b: read_g1(r)?,
        r_z: read_g1(r)?,
        r_vk: read_g2(r)?,
        s_b: read_bls_scalar(r)?,
        s_sk: read_bls_scalar(r)?,
    })
}

/// Serialize a verification key (Ristretto) for session setup bundles.
pub fn encode_vk(vk: &VerificationKey) -> [u8; 32] {
    vk.to_bytes()
}

pub fn decode_vk(bytes: &[u8]) -> Result<VerificationKey> {
    VerificationKey::from_bytes(bytes)
}

pub fn encode_partial_eval(v: &PartialEval) -> [u8; 48] {
    v.to_bytes()
}

pub fn encode_partial_proof(p: &PartialProof) -> Vec<u8> {
    let mut out = Vec::new();
    write_bls_scalar(&mut out, &p.c);
    write_bls_scalar(&mut out, &p.s);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dvrf::Dvts;
    use crate::nizk::NizkLPrime;
    use crate::vne::Vne;
    use rand::thread_rng;

    #[test]
    fn roundtrip_server_offer() {
        let mut rng = thread_rng();
        let keys = Dvts::dkgen(1, 3, &mut rng).unwrap();
        let m = b"wire-test";
        let (wit, _) = Dvts::part_eval(&keys.partial_sks[0], m);
        let inst = Instance::new(1, keys.vk.clone(), keys.partial_vks.clone(), m);
        let (ek, _) = Vne::kgen(&mut rng);
        let crs = NizkLPrime::setup();
        let ct = Vne::enc(&ek, &inst, &wit, &keys.partial_sks[0], 2, &crs, &mut rng).unwrap();
        let msg = WireServerOffer {
            ek: ek.clone(),
            ct,
            inst,
        };
        let bytes = msg.encode().unwrap();
        let back = WireServerOffer::decode(&bytes).unwrap();
        assert_eq!(back.ek.to_bytes(), ek.to_bytes());
        assert_eq!(back.ct.lambda_s, 2);
        assert_eq!(back.inst.msg, m);
    }

    #[test]
    fn roundtrip_presig_and_final() {
        use crate::adaptor::AdaptorSig;
        use crate::schnorr::Ds;
        let mut rng = thread_rng();
        let (sk, vk) = Ds::kgen(&mut rng);
        let (y, wit) = AdaptorSig::gen_statement(&mut rng);
        let msg = b"sighash";
        let pre = AdaptorSig::p_sign(&sk, msg, &y);
        let wire = WireClientPresig {
            y: y.clone(),
            pre: pre.clone(),
            sighash_msg: msg.to_vec(),
        };
        let back = WireClientPresig::decode(&wire.encode().unwrap()).unwrap();
        assert_eq!(back.sighash_msg, msg);
        assert!(AdaptorSig::p_vf(&vk, &back.sighash_msg, &back.y, &back.pre));

        let adapted = AdaptorSig::adapt(&vk, msg, &y, &pre, &wit).unwrap();
        let fin = WireServerFinal {
            adapted,
            bitcoin_tx_hex: "deadbeef".into(),
            server_index: 1,
            deposit_index: 1,
        };
        let fin2 = WireServerFinal::decode(&fin.encode().unwrap()).unwrap();
        assert_eq!(fin2.bitcoin_tx_hex, "deadbeef");
        assert_eq!(fin2.server_index, 1);
    }
}
