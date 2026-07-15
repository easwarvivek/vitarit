//! Figure 8 — Two-party sub-protocol Γ²ᵖᶜ_{DVTS,DS}.
//!
//! Exchanges the client's adaptor-adapted signature on `tx^j_pay,i` for the
//! server's partial DVTS evaluation, using VNE (Figure 9) + adaptor signatures.

use crate::adaptor::{AdaptorSig, PreSignature, Statement, Witness as AdaptorWitness};
use crate::dvrf::{PartialEval, PartialProof, PartialSk};
use crate::error::{Error, Result};
use crate::nizk::{CrsLPrime, NizkLPrime};
use crate::pkenc::{DecryptionKey, EncryptionKey};
use crate::schnorr::{SigningKey, VerificationKey};
use crate::tx::{self, Ledger, PostedPayment, Transaction};
use crate::vne::{Instance, Vne, VneCiphertext, DEFAULT_LAMBDA_S};
use rand_core::{CryptoRng, RngCore};

/// Common input `cinp := (pk_{A,j}, vk^{DVTS}, vk_i^{DVTS}, m*, tx^j_pay,i)`.
#[derive(Clone)]
pub struct CommonInput {
    pub pk_a_j: VerificationKey,
    pub inst: Instance,
    pub tx_pay: Transaction,
}

/// Party A's private input: `inp_A := sk_{A,j}`.
pub struct ClientInput {
    pub sk_a_j: SigningKey,
}

/// Server Si's private input:
/// `inp_{S,i} := (sk_i^{DVTS}, v_i, π_i, sk_{S,j}, sk_aux,i)`.
pub struct ServerInput {
    pub sk_dvts_i: PartialSk,
    pub v_i: PartialEval,
    pub pi_i: PartialProof,
    pub sk_s_j: SigningKey,
    pub sk_aux_i: SigningKey,
    pub server_index: usize,
    pub deposit_index: usize,
}

/// Server → client: `(ek, ct, inst)` (inst is in `cinp`).
#[derive(Clone)]
pub struct ServerVneMessage {
    pub ek: EncryptionKey,
    pub ct: VneCiphertext,
    /// Kept so the server can later Adapt without re-deriving.
    pub dk: DecryptionKey,
}

/// Client → server: `(Y, σ̃_{A,j})`.
#[derive(Clone)]
pub struct ClientPresigMessage {
    pub y: Statement,
    pub pre: PreSignature,
}

pub struct ClientOutput {
    pub v_i: PartialEval,
}

pub struct ServerOutput {
    pub posted: PostedPayment,
}

pub struct Gamma2pc {
    pub lambda_s: usize,
    pub crs: CrsLPrime,
}

impl Default for Gamma2pc {
    fn default() -> Self {
        Self {
            lambda_s: DEFAULT_LAMBDA_S,
            crs: NizkLPrime::setup(),
        }
    }
}

impl Gamma2pc {
    pub fn new(lambda_s: usize) -> Self {
        Self {
            lambda_s,
            crs: NizkLPrime::setup(),
        }
    }

    /// Figure 8 steps 3–20 as a single synchronous run.
    pub fn run<R: RngCore + CryptoRng>(
        &self,
        cinp: &CommonInput,
        client: &ClientInput,
        server: &ServerInput,
        pk_s_j: &VerificationKey,
        pk_aux_i: &VerificationKey,
        ledger: &Ledger,
        rng: &mut R,
    ) -> Result<(ClientOutput, ServerOutput)> {
        let server_msg = self.server_encrypt(cinp, server, rng)?;
        let client_msg = self.client_presign(cinp, client, &server_msg)?;
        let posted = self.server_adapt_and_publish(
            cinp,
            server,
            pk_s_j,
            pk_aux_i,
            &server_msg,
            &client_msg,
            ledger,
        )?;
        let v_i = self.client_extract(cinp, &server_msg, &client_msg, &posted)?;
        Ok((ClientOutput { v_i }, ServerOutput { posted }))
    }

    /// Server steps 3–7: `(ek, dk) ← VNE.KGen`; `ct ← VNE.Enc(...)`.
    pub fn server_encrypt<R: RngCore + CryptoRng>(
        &self,
        cinp: &CommonInput,
        server: &ServerInput,
        rng: &mut R,
    ) -> Result<ServerVneMessage> {
        let (ek, dk) = Vne::kgen(rng);
        let ct = Vne::enc(
            &ek,
            &cinp.inst,
            &server.v_i,
            &server.sk_dvts_i,
            self.lambda_s,
            &self.crs,
            rng,
        )?;
        Ok(ServerVneMessage { ek, ct, dk })
    }

    /// Client steps 9–11: `VfEnc`; `Y := ek`; `σ̃ ← AS.pSign`.
    pub fn client_presign(
        &self,
        cinp: &CommonInput,
        client: &ClientInput,
        server_msg: &ServerVneMessage,
    ) -> Result<ClientPresigMessage> {
        if !Vne::vf_enc(&server_msg.ek, &cinp.inst, &server_msg.ct, &self.crs) {
            return Err(Error::Verification("VNE.VfEnc failed".into()));
        }
        let y = Statement::from_encryption_key(&server_msg.ek);
        let pre = AdaptorSig::p_sign(&client.sk_a_j, &cinp.tx_pay.to_bytes(), &y);
        Ok(ClientPresigMessage { y, pre })
    }

    /// Server steps 13–17: check `Y = ek` and `pVf`, Adapt, Sign, Publish.
    pub fn server_adapt_and_publish(
        &self,
        cinp: &CommonInput,
        server: &ServerInput,
        pk_s_j: &VerificationKey,
        pk_aux_i: &VerificationKey,
        server_msg: &ServerVneMessage,
        client_msg: &ClientPresigMessage,
        ledger: &Ledger,
    ) -> Result<PostedPayment> {
        // Check Y ≟ ek
        let y_expected = Statement::from_encryption_key(&server_msg.ek);
        if client_msg.y != y_expected {
            return Err(Error::Verification("Y ≠ ek".into()));
        }
        if !AdaptorSig::p_vf(
            &cinp.pk_a_j,
            &cinp.tx_pay.to_bytes(),
            &client_msg.y,
            &client_msg.pre,
        ) {
            return Err(Error::Verification("AS.pVf failed".into()));
        }

        let wit = AdaptorWitness::from_decryption_key(&server_msg.dk);
        let sigma_a = AdaptorSig::adapt(
            &cinp.pk_a_j,
            &cinp.tx_pay.to_bytes(),
            &client_msg.y,
            &client_msg.pre,
            &wit,
        )?;
        let sigma_s = tx::sign_tx(&server.sk_s_j, &cinp.tx_pay);
        let sigma_aux = tx::sign_tx(&server.sk_aux_i, &cinp.tx_pay);

        if !tx::verify_tx_sig(pk_s_j, &cinp.tx_pay, &sigma_s)
            || !tx::verify_tx_sig(pk_aux_i, &cinp.tx_pay, &sigma_aux)
        {
            return Err(Error::Verification("server/aux signature invalid".into()));
        }

        let posted = PostedPayment {
            tx: cinp.tx_pay.clone(),
            sigma_a,
            sigma_s,
            sigma_aux,
            server_index: server.server_index,
            deposit_index: server.deposit_index,
        };
        ledger.publish_payment(posted.clone())?;
        Ok(posted)
    }

    /// Client steps 18–20: `dk ← AS.Ext`; `v_i ← VNE.Dec`.
    pub fn client_extract(
        &self,
        cinp: &CommonInput,
        server_msg: &ServerVneMessage,
        client_msg: &ClientPresigMessage,
        posted: &PostedPayment,
    ) -> Result<PartialEval> {
        let dk_wit = AdaptorSig::ext(
            &cinp.pk_a_j,
            &cinp.tx_pay.to_bytes(),
            &client_msg.y,
            &client_msg.pre,
            &posted.sigma_a,
        )?;
        Vne::dec(&dk_wit.as_decryption_key(), &cinp.inst, &server_msg.ct)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dvrf::Dvts;
    use crate::schnorr;
    use crate::tx::{make_payment_tx, Address};
    use rand::thread_rng;

    fn fixture(rng: &mut (impl RngCore + CryptoRng)) -> (
        CommonInput,
        ClientInput,
        ServerInput,
        VerificationKey,
        VerificationKey,
        Ledger,
    ) {
        let keys = Dvts::dkgen(1, 3, rng).unwrap();
        let i = 1usize;
        let m = b"gamma-msg";
        let (v_i, pi_i) = Dvts::part_eval(&keys.partial_sks[i - 1], m);
        let (sk_a, pk_a) = schnorr::Ds::kgen(rng);
        let (sk_s, pk_s) = schnorr::Ds::kgen(rng);
        let (sk_aux, pk_aux) = schnorr::Ds::kgen(rng);
        let deposit = Address::from_multisig(&pk_a, &pk_s);
        let aux = Address::from_vk(&pk_aux);
        let server_addr = Address::from_vk(&pk_s);
        let ledger = Ledger::new();
        ledger.credit(&deposit, 100);
        ledger.credit(&aux, 1);
        // Publish a dummy setup spending a fresh address so deposit is "created".
        let funding = Address([0xab; 32]);
        ledger.credit(&funding, 100);
        let setup = crate::tx::make_setup_tx(&funding, 100, &[(deposit.clone(), 100)]);
        ledger.publish_setup(&setup).unwrap();

        let tx_pay = make_payment_tx(&deposit, 100, &aux, 1, &server_addr);
        let inst = Instance::new(i, keys.vk.clone(), keys.partial_vks.clone(), m);
        let cinp = CommonInput {
            pk_a_j: pk_a,
            inst,
            tx_pay,
        };
        let client = ClientInput { sk_a_j: sk_a };
        let server = ServerInput {
            sk_dvts_i: keys.partial_sks[i - 1].clone(),
            v_i: v_i.clone(),
            pi_i,
            sk_s_j: sk_s,
            sk_aux_i: sk_aux,
            server_index: i,
            deposit_index: 1,
        };
        (cinp, client, server, pk_s, pk_aux, ledger)
    }

    #[test]
    fn gamma2pc_end_to_end() {
        let mut rng = thread_rng();
        let (cinp, client, server, pk_s, pk_aux, ledger) = fixture(&mut rng);
        let expected = server.v_i.to_bytes();
        let gamma = Gamma2pc::new(4);
        let (cout, sout) = gamma
            .run(&cinp, &client, &server, &pk_s, &pk_aux, &ledger, &mut rng)
            .unwrap();
        assert_eq!(cout.v_i.to_bytes(), expected);
        assert_eq!(ledger.payments().len(), 1);
        assert_eq!(sout.posted.server_index, 1);
    }

    #[test]
    fn gamma2pc_presign_rejects_bad_ct() {
        let mut rng = thread_rng();
        let (cinp, client, server, _pk_s, _pk_aux, _ledger) = fixture(&mut rng);
        let gamma = Gamma2pc::new(4);
        let mut server_msg = gamma.server_encrypt(&cinp, &server, &mut rng).unwrap();
        server_msg.ct.cts[0].c3[0] ^= 0xff;
        assert!(gamma.client_presign(&cinp, &client, &server_msg).is_err());
    }

    #[test]
    fn gamma2pc_rejects_wrong_y() {
        let mut rng = thread_rng();
        let (cinp, client, server, pk_s, pk_aux, ledger) = fixture(&mut rng);
        let gamma = Gamma2pc::new(4);
        let server_msg = gamma.server_encrypt(&cinp, &server, &mut rng).unwrap();
        let mut client_msg = gamma.client_presign(&cinp, &client, &server_msg).unwrap();
        // Replace Y with an unrelated statement.
        let (y_wrong, _) = AdaptorSig::gen_statement(&mut rng);
        client_msg.y = y_wrong;
        assert!(gamma
            .server_adapt_and_publish(
                &cinp,
                &server,
                &pk_s,
                &pk_aux,
                &server_msg,
                &client_msg,
                &ledger
            )
            .is_err());
    }

    #[test]
    fn gamma2pc_default_uses_paper_lambda() {
        let g = Gamma2pc::default();
        assert_eq!(g.lambda_s, DEFAULT_LAMBDA_S);
    }
}
