//! Orchestrates Figure 7 payment against one server with wire serialization.

use crate::error::{Error, Result};
use bitcoin::{Amount, Transaction, TxOut};
use rand::rngs::OsRng;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use vitarit::adaptor::{AdaptorSig, Statement, Witness as AdaptorWitness};
use vitarit::dvrf::{Dvts, KeySet, PartialEval};
use vitarit::nizk::NizkLPrime;
use vitarit::schnorr::Ds;
use vitarit::vne::{Instance, Vne, DEFAULT_LAMBDA_S};
use vitarit::wire::{WireClientPresig, WireServerFinal, WireServerOffer};
use vitarit_bitcoin::keys::SessionKeys;
use vitarit_bitcoin::ledger::SimulatedLedger;
use vitarit_bitcoin::network::BtcNetwork;
use vitarit_bitcoin::signing::{payment_adaptor_message, sign_payment_2of2_plus_aux};
use vitarit_bitcoin::transactions::{fake_outpoint, tx_hex, AuxPlan, PaymentPlan, SetupPlan};

#[derive(Clone, Debug)]
pub struct SessionParams {
    pub network: BtcNetwork,
    pub t: usize,
    pub n: usize,
    pub lambda_s: usize,
    pub deposit_sats: u64,
    pub fee_sats: u64,
    /// Server index (1-based) contacted in this payment.
    pub server_index: usize,
    /// Deposit index (1-based) spent in this payment.
    pub deposit_index: usize,
    pub service_msg: Vec<u8>,
}

impl Default for SessionParams {
    fn default() -> Self {
        Self {
            network: BtcNetwork::Regtest,
            t: 1,
            n: 3,
            lambda_s: 4, // small for local tests; use DEFAULT_LAMBDA_S in production
            deposit_sats: 10_000,
            fee_sats: 200,
            server_index: 1,
            deposit_index: 1,
            service_msg: b"vitarit-local-testnet".to_vec(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionReport {
    pub network: String,
    pub lambda_s: usize,
    pub server_index: usize,
    pub deposit_index: usize,
    pub wire_offer_bytes: usize,
    pub wire_presig_bytes: usize,
    pub wire_final_bytes: usize,
    pub payment_txid: String,
    pub payment_tx_hex: String,
    pub partial_eval_hex: String,
    pub simulated_confirmed_txs: usize,
    pub notes: Vec<String>,
}

/// One client ↔ one server payment with framed wire messages + Bitcoin signing.
pub struct LocalSession {
    pub params: SessionParams,
    pub btc_keys: SessionKeys,
    pub dvts: KeySet,
}

impl LocalSession {
    pub fn new(params: SessionParams) -> Result<Self> {
        let btc_keys = SessionKeys::generate(params.network, params.t, params.n)?;
        let mut rng = OsRng;
        let dvts = Dvts::dkgen(params.t, params.n, &mut rng)?;
        Ok(Self {
            params,
            btc_keys,
            dvts,
        })
    }

    /// Full happy path on a [`SimulatedLedger`] (no bitcoind required).
    pub fn run_simulated(&self) -> Result<SessionReport> {
        let mut rng = OsRng;
        self.run_on_ledger(&mut SimulatedLedger::new(), &mut rng)
    }

    pub fn run_on_ledger<R: RngCore + CryptoRng>(
        &self,
        ledger: &mut SimulatedLedger,
        rng: &mut R,
    ) -> Result<SessionReport> {
        let p = &self.params;
        let i = p.server_index;
        let j = p.deposit_index;
        if i == 0 || i > p.n || j == 0 || j > (p.t + 1) {
            return Err(Error::Protocol("bad server/deposit index".into()));
        }

        let setup = SetupPlan::from_keys(&self.btc_keys, p.deposit_sats, p.fee_sats)?;
        let aux_plan = AuxPlan::from_keys(&self.btc_keys, i, 1)?;
        let aux_value = aux_plan.value_sats;

        // Fund deposit + aux UTXOs on the simulated ledger.
        let dep_op = fake_outpoint(10 + j as u8);
        let aux_op = fake_outpoint(20 + i as u8);
        ledger.credit(
            dep_op,
            TxOut {
                value: Amount::from_sat(p.deposit_sats),
                script_pubkey: setup.deposits[j - 1].script_pubkey.clone(),
            },
        );
        ledger.credit(
            aux_op,
            TxOut {
                value: Amount::from_sat(aux_value),
                script_pubkey: self.btc_keys.server_aux[i - 1].p2wpkh.script_pubkey(),
            },
        );

        let pay = PaymentPlan::from_session(
            &self.btc_keys,
            &setup,
            i,
            j,
            aux_value,
            p.fee_sats,
        )?;
        let mut unsigned = pay.build_unsigned(dep_op, aux_op)?;
        let sighash_msg = payment_adaptor_message(&unsigned);

        // --- Off-chain DVTS partial + VNE ---
        let (v_i, _pi) = Dvts::part_eval(&self.dvts.partial_sks[i - 1], &p.service_msg);
        let inst = Instance::new(
            i,
            self.dvts.vk.clone(),
            self.dvts.partial_vks.clone(),
            &p.service_msg,
        );
        let crs = NizkLPrime::setup();

        // Ristretto signing keys for adaptor (paper AS); independent of secp ECDSA.
        let (sk_a_ristretto, vk_a_ristretto) = Ds::kgen(rng);

        // Server: VNE.Enc → WireServerOffer
        let (ek, dk) = Vne::kgen(rng);
        let ct = Vne::enc(
            &ek,
            &inst,
            &v_i,
            &self.dvts.partial_sks[i - 1],
            p.lambda_s,
            &crs,
            rng,
        )?;
        let offer = WireServerOffer {
            ek: ek.clone(),
            ct: ct.clone(),
            inst: inst.clone(),
        };
        let offer_bytes = offer.encode()?;
        let offer = WireServerOffer::decode(&offer_bytes)?;

        // Client: VfEnc + pSign on bitcoin-bound message → WireClientPresig
        if !Vne::vf_enc(&offer.ek, &offer.inst, &offer.ct, &crs) {
            return Err(Error::Protocol("VNE.VfEnc failed after wire decode".into()));
        }
        let y = Statement::from_encryption_key(&offer.ek);
        let pre = AdaptorSig::p_sign(&sk_a_ristretto, &sighash_msg, &y);
        let prestig = WireClientPresig {
            y: y.clone(),
            pre: pre.clone(),
            sighash_msg: sighash_msg.clone(),
        };
        let prestig_bytes = prestig.encode()?;
        let prestig = WireClientPresig::decode(&prestig_bytes)?;

        // Server: Adapt + ECDSA-sign Bitcoin payment → WireServerFinal
        let y_expected = Statement::from_encryption_key(&offer.ek);
        if prestig.y != y_expected {
            return Err(Error::Protocol("Y ≠ ek".into()));
        }
        if !AdaptorSig::p_vf(
            &vk_a_ristretto,
            &prestig.sighash_msg,
            &prestig.y,
            &prestig.pre,
        ) {
            return Err(Error::Protocol("AS.pVf failed".into()));
        }
        let wit = AdaptorWitness::from_decryption_key(&dk);
        let adapted = AdaptorSig::adapt(
            &vk_a_ristretto,
            &prestig.sighash_msg,
            &prestig.y,
            &prestig.pre,
            &wit,
        )?;

        sign_payment_2of2_plus_aux(
            &mut unsigned,
            &pay.deposit,
            Amount::from_sat(p.deposit_sats),
            &self.btc_keys.server_aux[i - 1].p2wpkh.script_pubkey(),
            Amount::from_sat(aux_value),
            &self.btc_keys.server_aux[i - 1].public,
            &self.btc_keys.client_deposit[j - 1].secret,
            &self.btc_keys.service_deposit[j - 1].secret,
            &self.btc_keys.server_aux[i - 1].secret,
        )?;
        let payment_tx_hex = tx_hex(&unsigned);
        ledger.apply(&unsigned)?;

        let fin = WireServerFinal {
            adapted: adapted.clone(),
            bitcoin_tx_hex: payment_tx_hex.clone(),
            server_index: i,
            deposit_index: j,
        };
        let fin_bytes = fin.encode()?;
        let fin = WireServerFinal::decode(&fin_bytes)?;

        // Client: Ext + VNE.Dec
        let dk_wit = AdaptorSig::ext(
            &vk_a_ristretto,
            &prestig.sighash_msg,
            &prestig.y,
            &prestig.pre,
            &fin.adapted,
        )?;
        let recovered: PartialEval =
            Vne::dec(&dk_wit.as_decryption_key(), &offer.inst, &offer.ct)?;
        if recovered.to_bytes() != v_i.to_bytes() {
            return Err(Error::Protocol("recovered partial eval mismatch".into()));
        }

        // Sanity: payment hex round-trips.
        let raw = hex::decode(&fin.bitcoin_tx_hex)
            .map_err(|e| Error::Wire(format!("bad tx hex: {e}")))?;
        let _: Transaction = bitcoin::consensus::deserialize(&raw)
            .map_err(|e| Error::Wire(format!("tx decode: {e}")))?;

        Ok(SessionReport {
            network: p.network.name().to_string(),
            lambda_s: p.lambda_s,
            server_index: i,
            deposit_index: j,
            wire_offer_bytes: offer_bytes.len(),
            wire_presig_bytes: prestig_bytes.len(),
            wire_final_bytes: fin_bytes.len(),
            payment_txid: unsigned.compute_txid().to_string(),
            payment_tx_hex,
            partial_eval_hex: hex::encode(recovered.to_bytes()),
            simulated_confirmed_txs: ledger.confirmed_count(),
            notes: vec![
                "ECDSA P2WSH/P2WPKH witnesses on chain; Ristretto adaptor off-chain".into(),
                format!(
                    "paper DEFAULT_LAMBDA_S={DEFAULT_LAMBDA_S}; this run uses {}",
                    p.lambda_s
                ),
                "SimulatedLedger used — install bitcoind for live regtest broadcast".into(),
            ],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn e2e_simulated_regtest() {
        let session = LocalSession::new(SessionParams::default()).unwrap();
        let report = session.run_simulated().unwrap();
        assert_eq!(report.simulated_confirmed_txs, 1);
        assert!(report.wire_offer_bytes > 100);
        assert!(!report.payment_txid.is_empty());
        assert!(!report.partial_eval_hex.is_empty());
    }

    #[test]
    fn wire_roundtrip_sizes_reported() {
        let session = LocalSession::new(SessionParams {
            lambda_s: 2,
            ..SessionParams::default()
        })
        .unwrap();
        let r = session.run_simulated().unwrap();
        assert!(r.wire_final_bytes > 8);
        assert!(r.wire_presig_bytes > 8);
    }
}
