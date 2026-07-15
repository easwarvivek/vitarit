//! Figure 7 Bitcoin transactions: setup (`tx_stp`), aux funding, payment (`tx^j_pay,i`).

use crate::error::{Error, Result};
use crate::keys::SessionKeys;
use crate::network::BtcNetwork;
use crate::policy::{DepositOutput, RelayLimits, SingleKeyOutput};
use bitcoin::absolute::LockTime;
use bitcoin::transaction::{OutPoint, Transaction, TxIn, TxOut, Version};
use bitcoin::{Address, Amount, ScriptBuf, Sequence, Txid, Witness};
use serde::{Deserialize, Serialize};

/// Concrete plan for the setup phase (paper Fig 7).
#[derive(Clone, Debug)]
pub struct SetupPlan {
    pub network: BtcNetwork,
    pub deposit_value_sats: u64,
    pub deposits: Vec<DepositOutput>,
    /// Outputs that will appear on `tx_stp`.
    pub deposit_addresses: Vec<Address>,
    pub fee_sats: u64,
}

impl SetupPlan {
    pub fn from_keys(
        keys: &SessionKeys,
        deposit_value_sats: u64,
        fee_sats: u64,
    ) -> Result<Self> {
        let lim = RelayLimits::default();
        if deposit_value_sats < lim.p2wsh_dust_sats {
            return Err(Error::InvalidParam(format!(
                "deposit_value {deposit_value_sats} below P2WSH dust {}",
                lim.p2wsh_dust_sats
            )));
        }
        let mut deposits = Vec::new();
        let mut deposit_addresses = Vec::new();
        for j in 0..keys.client_deposit.len() {
            let d = DepositOutput::p2wsh_2of2(
                &keys.client_deposit[j].public,
                &keys.service_deposit[j].public,
                keys.network,
            )?;
            deposit_addresses.push(d.address.clone());
            deposits.push(d);
        }
        Ok(Self {
            network: keys.network,
            deposit_value_sats,
            deposits,
            deposit_addresses,
            fee_sats,
        })
    }

    /// Total client value that must enter the setup transaction.
    pub fn total_funded_sats(&self) -> u64 {
        self.deposit_value_sats * self.deposits.len() as u64 + self.fee_sats
    }

    /// Build unsigned `tx_stp` spending `funding_outpoint` of value `funding_value`.
    /// Extra sats return as change to `change_spk`.
    pub fn build_unsigned(
        &self,
        funding_outpoint: OutPoint,
        funding_value: u64,
        change_spk: ScriptBuf,
    ) -> Result<Transaction> {
        let needed = self.total_funded_sats();
        if funding_value < needed {
            return Err(Error::InvalidParam(format!(
                "funding {funding_value} < required {needed}"
            )));
        }
        let mut outputs: Vec<TxOut> = self
            .deposits
            .iter()
            .map(|d| TxOut {
                value: Amount::from_sat(self.deposit_value_sats),
                script_pubkey: d.script_pubkey.clone(),
            })
            .collect();
        let change = funding_value - needed;
        if change > 0 {
            let lim = RelayLimits::default();
            if change >= lim.p2wpkh_dust_sats {
                outputs.push(TxOut {
                    value: Amount::from_sat(change),
                    script_pubkey: change_spk,
                });
            }
        }
        Ok(Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: funding_outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: outputs,
        })
    }
}

/// Auxiliary lock for server `i` (paper `tx_aux,i`).
#[derive(Clone, Debug)]
pub struct AuxPlan {
    pub server_index: usize, // 1-indexed
    pub value_sats: u64,
    pub output: SingleKeyOutput,
}

impl AuxPlan {
    pub fn from_keys(keys: &SessionKeys, server_index: usize, paper_epsilon: u64) -> Result<Self> {
        if server_index == 0 || server_index > keys.server_aux.len() {
            return Err(Error::InvalidParam("server_index out of range".into()));
        }
        let lim = RelayLimits::default();
        let (value_sats, _) = lim.recommend_aux_value(paper_epsilon);
        let output = SingleKeyOutput::p2wpkh(
            &keys.server_aux[server_index - 1].public,
            keys.network,
        )?;
        Ok(Self {
            server_index,
            value_sats,
            output,
        })
    }

    pub fn build_unsigned(
        &self,
        funding_outpoint: OutPoint,
        funding_value: u64,
        change_spk: ScriptBuf,
        fee_sats: u64,
    ) -> Result<Transaction> {
        let needed = self.value_sats + fee_sats;
        if funding_value < needed {
            return Err(Error::InvalidParam(format!(
                "aux funding {funding_value} < {needed}"
            )));
        }
        let mut outputs = vec![TxOut {
            value: Amount::from_sat(self.value_sats),
            script_pubkey: self.output.script_pubkey.clone(),
        }];
        let change = funding_value - needed;
        if change >= RelayLimits::default().p2wpkh_dust_sats {
            outputs.push(TxOut {
                value: Amount::from_sat(change),
                script_pubkey: change_spk,
            });
        }
        Ok(Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: funding_outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::default(),
            }],
            output: outputs,
        })
    }
}

/// Payment `tx^j_pay,i` — spends deposit `j` and aux of server `i` into server receive.
#[derive(Clone, Debug)]
pub struct PaymentPlan {
    pub server_index: usize,
    pub deposit_index: usize, // 1-indexed j
    pub deposit: DepositOutput,
    pub aux: SingleKeyOutput,
    pub receive: SingleKeyOutput,
    pub deposit_value_sats: u64,
    pub aux_value_sats: u64,
    pub fee_sats: u64,
}

impl PaymentPlan {
    pub fn from_session(
        keys: &SessionKeys,
        setup: &SetupPlan,
        server_index: usize,
        deposit_index: usize,
        aux_value_sats: u64,
        fee_sats: u64,
    ) -> Result<Self> {
        if server_index == 0 || server_index > keys.server_aux.len() {
            return Err(Error::InvalidParam("bad server_index".into()));
        }
        if deposit_index == 0 || deposit_index > setup.deposits.len() {
            return Err(Error::InvalidParam("bad deposit_index".into()));
        }
        let receive = SingleKeyOutput::p2wpkh(
            &keys.server_receive[server_index - 1].public,
            keys.network,
        )?;
        let aux = SingleKeyOutput::p2wpkh(
            &keys.server_aux[server_index - 1].public,
            keys.network,
        )?;
        Ok(Self {
            server_index,
            deposit_index,
            deposit: setup.deposits[deposit_index - 1].clone(),
            aux,
            receive,
            deposit_value_sats: setup.deposit_value_sats,
            aux_value_sats,
            fee_sats,
        })
    }

    /// Payout amount after fee (must cover dust).
    pub fn payout_sats(&self) -> Result<u64> {
        let sum = self
            .deposit_value_sats
            .checked_add(self.aux_value_sats)
            .ok_or_else(|| Error::InvalidParam("value overflow".into()))?;
        sum.checked_sub(self.fee_sats)
            .ok_or_else(|| Error::InvalidParam("fee exceeds inputs".into()))
    }

    /// Unsigned payment: two inputs (deposit UTXO, aux UTXO).
    pub fn build_unsigned(
        &self,
        deposit_outpoint: OutPoint,
        aux_outpoint: OutPoint,
    ) -> Result<Transaction> {
        let payout = self.payout_sats()?;
        if payout < RelayLimits::default().p2wpkh_dust_sats {
            return Err(Error::InvalidParam("payout below dust".into()));
        }
        Ok(Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![
                TxIn {
                    previous_output: deposit_outpoint,
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                    witness: Witness::new(),
                },
                TxIn {
                    previous_output: aux_outpoint,
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                    witness: Witness::new(),
                },
            ],
            output: vec![TxOut {
                value: Amount::from_sat(payout),
                script_pubkey: self.receive.script_pubkey.clone(),
            }],
        })
    }

    /// Human-readable summary for operators / scripts.
    pub fn summary(&self) -> PaymentSummary {
        PaymentSummary {
            server_index: self.server_index,
            deposit_index: self.deposit_index,
            deposit_address: self.deposit.address.to_string(),
            deposit_descriptor: self.deposit.descriptor_wsh_multi(),
            aux_address: self.aux.address.to_string(),
            receive_address: self.receive.address.to_string(),
            deposit_value_sats: self.deposit_value_sats,
            aux_value_sats: self.aux_value_sats,
            fee_sats: self.fee_sats,
            payout_sats: self.payout_sats().unwrap_or(0),
            required_signatures: vec![
                "sigma_A (client; paper: adaptor-adapted Schnorr)".into(),
                "sigma_S (service key for deposit j)".into(),
                "sigma_aux (server auxiliary key)".into(),
            ],
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PaymentSummary {
    pub server_index: usize,
    pub deposit_index: usize,
    pub deposit_address: String,
    pub deposit_descriptor: String,
    pub aux_address: String,
    pub receive_address: String,
    pub deposit_value_sats: u64,
    pub aux_value_sats: u64,
    pub fee_sats: u64,
    pub payout_sats: u64,
    pub required_signatures: Vec<String>,
}

/// Encode a transaction as hex (for bitcoin-cli `sendrawtransaction` / inspection).
pub fn tx_hex(tx: &Transaction) -> String {
    use bitcoin::consensus::Encodable;
    let mut buf = Vec::new();
    tx.consensus_encode(&mut buf).expect("encode");
    hex::encode(buf)
}

pub fn txid_of(tx: &Transaction) -> Txid {
    tx.compute_txid()
}

/// Dummy outpoint for offline structure tests.
pub fn fake_outpoint(seed: u8) -> OutPoint {
    use bitcoin::hashes::Hash;
    let mut h = [0u8; 32];
    h[0] = seed;
    OutPoint {
        txid: Txid::from_byte_array(h),
        vout: seed as u32,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::SessionKeys;

    #[test]
    fn setup_and_payment_shapes() {
        let keys = SessionKeys::generate(BtcNetwork::Regtest, 1, 3).unwrap();
        let setup = SetupPlan::from_keys(&keys, 10_000, 500).unwrap();
        assert_eq!(setup.deposits.len(), 2);
        let fund = fake_outpoint(1);
        let tx = setup
            .build_unsigned(
                fund,
                setup.total_funded_sats() + 1_000,
                keys.client_funding.p2wpkh.script_pubkey(),
            )
            .unwrap();
        assert_eq!(tx.input.len(), 1);
        assert!(tx.output.len() >= 2);

        let pay = PaymentPlan::from_session(&keys, &setup, 1, 1, 294, 200).unwrap();
        let ptx = pay
            .build_unsigned(fake_outpoint(2), fake_outpoint(3))
            .unwrap();
        assert_eq!(ptx.input.len(), 2);
        assert_eq!(ptx.output.len(), 1);
        let s = pay.summary();
        assert_eq!(s.required_signatures.len(), 3);
    }
}
