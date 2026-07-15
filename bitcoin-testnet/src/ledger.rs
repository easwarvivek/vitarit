//! In-memory UTXO ledger used to test pay-at-most-once without a bitcoind.

use crate::error::{Error, Result};
use bitcoin::{OutPoint, Transaction, TxOut, Txid};
use std::collections::{HashMap, HashSet};

#[derive(Clone, Debug, Default)]
pub struct SimulatedLedger {
    utxos: HashMap<OutPoint, TxOut>,
    spent: HashSet<OutPoint>,
    txs: Vec<Txid>,
}

impl SimulatedLedger {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn credit(&mut self, outpoint: OutPoint, txout: TxOut) {
        self.utxos.insert(outpoint, txout);
    }

    pub fn is_spent(&self, op: &OutPoint) -> bool {
        self.spent.contains(op)
    }

    pub fn get(&self, op: &OutPoint) -> Option<&TxOut> {
        if self.spent.contains(op) {
            None
        } else {
            self.utxos.get(op)
        }
    }

    /// Apply a fully formed transaction: spend inputs, create outputs.
    /// Enforces that **no input is already spent** — this is exactly the
    /// UTXO property the paper relies on for auxiliary-address uniqueness.
    pub fn apply(&mut self, tx: &Transaction) -> Result<Txid> {
        for tin in &tx.input {
            if self.spent.contains(&tin.previous_output) {
                return Err(Error::Ledger(format!(
                    "input {} already spent (pay-at-most-once)",
                    tin.previous_output
                )));
            }
            if !self.utxos.contains_key(&tin.previous_output) {
                return Err(Error::Ledger(format!(
                    "unknown input {}",
                    tin.previous_output
                )));
            }
        }
        for tin in &tx.input {
            self.spent.insert(tin.previous_output);
        }
        let txid = tx.compute_txid();
        for (vout, tout) in tx.output.iter().enumerate() {
            self.utxos.insert(
                OutPoint {
                    txid,
                    vout: vout as u32,
                },
                tout.clone(),
            );
        }
        self.txs.push(txid);
        Ok(txid)
    }

    pub fn confirmed_count(&self) -> usize {
        self.txs.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::SessionKeys;
    use crate::network::BtcNetwork;
    use crate::transactions::{fake_outpoint, PaymentPlan, SetupPlan};
    use bitcoin::{Amount, ScriptBuf};

    #[test]
    fn aux_double_spend_rejected() {
        let keys = SessionKeys::generate(BtcNetwork::Regtest, 1, 3).unwrap();
        let setup = SetupPlan::from_keys(&keys, 10_000, 200).unwrap();
        let mut led = SimulatedLedger::new();

        // Pretend setup outputs and aux exist.
        let dep_op = fake_outpoint(10);
        let aux_op = fake_outpoint(11);
        led.credit(
            dep_op,
            TxOut {
                value: Amount::from_sat(10_000),
                script_pubkey: setup.deposits[0].script_pubkey.clone(),
            },
        );
        led.credit(
            aux_op,
            TxOut {
                value: Amount::from_sat(294),
                script_pubkey: ScriptBuf::new(),
            },
        );

        let pay = PaymentPlan::from_session(&keys, &setup, 1, 1, 294, 200).unwrap();
        let tx1 = pay.build_unsigned(dep_op, aux_op).unwrap();
        led.apply(&tx1).unwrap();

        // Same aux, different deposit — must fail.
        let dep2 = fake_outpoint(12);
        led.credit(
            dep2,
            TxOut {
                value: Amount::from_sat(10_000),
                script_pubkey: setup.deposits[1].script_pubkey.clone(),
            },
        );
        let pay2 = PaymentPlan::from_session(&keys, &setup, 1, 2, 294, 200).unwrap();
        let tx2 = pay2.build_unsigned(dep2, aux_op).unwrap();
        let err = led.apply(&tx2).unwrap_err();
        assert!(format!("{err}").contains("already spent"));
    }
}
