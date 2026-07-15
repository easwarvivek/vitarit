//! Abstract UTXO transaction model used by Figures 7–8.
//!
//! We do not talk to a real blockchain; a local [`Ledger`] records posted
//! transactions so the client can extract adaptor witnesses as in Figure 8.

use crate::error::{Error, Result};
use crate::schnorr::{self, Signature, SigningKey, VerificationKey};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

/// Opaque address = hash of the controlling public key(s).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Address(pub [u8; 32]);

impl Address {
    pub fn from_vk(vk: &VerificationKey) -> Self {
        let mut h = Sha256::new();
        Digest::update(&mut h, b"addr-single");
        Digest::update(&mut h, vk.to_bytes());
        let d = h.finalize();
        let mut a = [0u8; 32];
        a.copy_from_slice(&d);
        Address(a)
    }

    /// 2-of-2 multisig address (pk_A, pk_S) as in the deposit outputs.
    pub fn from_multisig(pk_a: &VerificationKey, pk_s: &VerificationKey) -> Self {
        let mut h = Sha256::new();
        Digest::update(&mut h, b"addr-2of2");
        Digest::update(&mut h, pk_a.to_bytes());
        Digest::update(&mut h, pk_s.to_bytes());
        let d = h.finalize();
        let mut a = [0u8; 32];
        a.copy_from_slice(&d);
        Address(a)
    }
}

#[derive(Clone, Debug)]
pub struct TxInput {
    pub addr: Address,
    pub value: u64,
}

#[derive(Clone, Debug)]
pub struct TxOutput {
    pub addr: Address,
    pub value: u64,
}

/// A transaction as in the paper notation
/// `tx[(in...), (out...)]`.
#[derive(Clone, Debug)]
pub struct Transaction {
    pub inputs: Vec<TxInput>,
    pub outputs: Vec<TxOutput>,
}

impl Transaction {
    /// Canonical byte encoding used as the Schnorr / adaptor message.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(self.inputs.len() as u64).to_le_bytes());
        for i in &self.inputs {
            out.extend_from_slice(&i.addr.0);
            out.extend_from_slice(&i.value.to_le_bytes());
        }
        out.extend_from_slice(&(self.outputs.len() as u64).to_le_bytes());
        for o in &self.outputs {
            out.extend_from_slice(&o.addr.0);
            out.extend_from_slice(&o.value.to_le_bytes());
        }
        out
    }

    pub fn id(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        Digest::update(&mut h, b"txid");
        Digest::update(&mut h, self.to_bytes());
        let d = h.finalize();
        let mut id = [0u8; 32];
        id.copy_from_slice(&d);
        id
    }
}

/// Payment transaction of Figure 7 step 1 of the payment phase:
/// spends deposit j and server i's auxiliary UTXO into server i's address.
pub fn make_payment_tx(
    deposit_addr: &Address,
    deposit_value: u64,
    aux_addr: &Address,
    aux_value: u64,
    server_addr: &Address,
) -> Transaction {
    Transaction {
        inputs: vec![
            TxInput {
                addr: deposit_addr.clone(),
                value: deposit_value,
            },
            TxInput {
                addr: aux_addr.clone(),
                value: aux_value,
            },
        ],
        outputs: vec![TxOutput {
            addr: server_addr.clone(),
            value: deposit_value + aux_value,
        }],
    }
}

/// Setup transaction depositing `(t+1)` outputs of value `x` each.
pub fn make_setup_tx(
    funding_addr: &Address,
    funding_value: u64,
    deposit_addrs: &[(Address, u64)],
) -> Transaction {
    Transaction {
        inputs: vec![TxInput {
            addr: funding_addr.clone(),
            value: funding_value,
        }],
        outputs: deposit_addrs
            .iter()
            .map(|(a, v)| TxOutput {
                addr: a.clone(),
                value: *v,
            })
            .collect(),
    }
}

/// Posted payment on the ledger (Figure 8 step 17).
#[derive(Clone, Debug)]
pub struct PostedPayment {
    pub tx: Transaction,
    pub sigma_a: Signature,
    pub sigma_s: Signature,
    pub sigma_aux: Signature,
    pub server_index: usize,
    pub deposit_index: usize,
}

/// In-memory ledger used by the protocol simulation.
#[derive(Clone, Default)]
pub struct Ledger {
    inner: Arc<Mutex<LedgerState>>,
}

#[derive(Default)]
struct LedgerState {
    spent: HashSet<Address>,
    payments: Vec<PostedPayment>,
    balances: HashMap<Address, u64>,
}

impl Ledger {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn credit(&self, addr: &Address, value: u64) {
        let mut st = self.inner.lock().unwrap();
        *st.balances.entry(addr.clone()).or_insert(0) += value;
    }

    pub fn publish_setup(&self, tx: &Transaction) -> Result<()> {
        let mut st = self.inner.lock().unwrap();
        for i in &tx.inputs {
            if st.spent.contains(&i.addr) {
                return Err(Error::Ledger("setup input already spent".into()));
            }
            st.spent.insert(i.addr.clone());
        }
        for o in &tx.outputs {
            *st.balances.entry(o.addr.clone()).or_insert(0) += o.value;
        }
        Ok(())
    }

    /// Publish a payment; fails if either input address is already spent
    /// (enforces the auxiliary-address "pay at most once" property).
    pub fn publish_payment(&self, payment: PostedPayment) -> Result<()> {
        let mut st = self.inner.lock().unwrap();
        for i in &payment.tx.inputs {
            if st.spent.contains(&i.addr) {
                return Err(Error::Ledger(format!(
                    "input {:?} already spent (pay-at-most-once)",
                    hex::encode(i.addr.0)
                )));
            }
        }
        for i in &payment.tx.inputs {
            st.spent.insert(i.addr.clone());
        }
        for o in &payment.tx.outputs {
            *st.balances.entry(o.addr.clone()).or_insert(0) += o.value;
        }
        st.payments.push(payment);
        Ok(())
    }

    pub fn payments(&self) -> Vec<PostedPayment> {
        self.inner.lock().unwrap().payments.clone()
    }

    pub fn is_spent(&self, addr: &Address) -> bool {
        self.inner.lock().unwrap().spent.contains(addr)
    }
}

/// Helper: sign a transaction under a Schnorr key.
pub fn sign_tx(sk: &SigningKey, tx: &Transaction) -> Signature {
    schnorr::Ds::sign(sk, &tx.to_bytes())
}

pub fn verify_tx_sig(vk: &VerificationKey, tx: &Transaction, sig: &Signature) -> bool {
    schnorr::Ds::vf(vk, &tx.to_bytes(), sig)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    #[test]
    fn address_from_vk_deterministic() {
        let mut rng = thread_rng();
        let (_, vk) = schnorr::Ds::kgen(&mut rng);
        assert_eq!(Address::from_vk(&vk), Address::from_vk(&vk));
    }

    #[test]
    fn address_multisig_order_matters() {
        let mut rng = thread_rng();
        let (_, a) = schnorr::Ds::kgen(&mut rng);
        let (_, b) = schnorr::Ds::kgen(&mut rng);
        assert_ne!(Address::from_multisig(&a, &b), Address::from_multisig(&b, &a));
    }

    #[test]
    fn tx_encoding_and_id_stable() {
        let deposit = Address([1u8; 32]);
        let aux = Address([2u8; 32]);
        let server = Address([3u8; 32]);
        let tx = make_payment_tx(&deposit, 100, &aux, 1, &server);
        assert_eq!(tx.to_bytes(), tx.to_bytes());
        assert_eq!(tx.id(), tx.id());
        assert_eq!(tx.inputs.len(), 2);
        assert_eq!(tx.outputs.len(), 1);
        assert_eq!(tx.outputs[0].value, 101);
    }

    #[test]
    fn setup_tx_shapes() {
        let funding = Address([9u8; 32]);
        let deps = vec![(Address([1u8; 32]), 10u64), (Address([2u8; 32]), 10u64)];
        let tx = make_setup_tx(&funding, 20, &deps);
        assert_eq!(tx.inputs.len(), 1);
        assert_eq!(tx.outputs.len(), 2);
    }

    #[test]
    fn ledger_publish_setup_and_payment() {
        let mut rng = thread_rng();
        let ledger = Ledger::new();
        let (sk_a, pk_a) = schnorr::Ds::kgen(&mut rng);
        let (sk_s, pk_s) = schnorr::Ds::kgen(&mut rng);
        let (sk_aux, pk_aux) = schnorr::Ds::kgen(&mut rng);
        let funding = Address::from_vk(&pk_a);
        ledger.credit(&funding, 200);

        let deposit = Address::from_multisig(&pk_a, &pk_s);
        let aux = Address::from_vk(&pk_aux);
        let server = Address([7u8; 32]);
        ledger.credit(&aux, 1);

        let setup = make_setup_tx(&funding, 100, &[(deposit.clone(), 100)]);
        ledger.publish_setup(&setup).unwrap();

        let pay = make_payment_tx(&deposit, 100, &aux, 1, &server);
        let posted = PostedPayment {
            tx: pay.clone(),
            sigma_a: sign_tx(&sk_a, &pay),
            sigma_s: sign_tx(&sk_s, &pay),
            sigma_aux: sign_tx(&sk_aux, &pay),
            server_index: 1,
            deposit_index: 1,
        };
        assert!(verify_tx_sig(&pk_a, &pay, &posted.sigma_a));
        ledger.publish_payment(posted).unwrap();
        assert!(ledger.is_spent(&deposit));
        assert!(ledger.is_spent(&aux));
        assert_eq!(ledger.payments().len(), 1);
    }

    #[test]
    fn ledger_rejects_double_spend() {
        let mut rng = thread_rng();
        let ledger = Ledger::new();
        let (sk_a, pk_a) = schnorr::Ds::kgen(&mut rng);
        let (sk_s, pk_s) = schnorr::Ds::kgen(&mut rng);
        let (sk_aux, pk_aux) = schnorr::Ds::kgen(&mut rng);
        let deposit = Address::from_multisig(&pk_a, &pk_s);
        let aux = Address::from_vk(&pk_aux);
        let server = Address([7u8; 32]);
        ledger.credit(&deposit, 100);
        ledger.credit(&aux, 1);

        // Mark deposit as created via a faux setup.
        let setup = make_setup_tx(&Address([0u8; 32]), 100, &[(deposit.clone(), 100)]);
        // Setup spends Address([0..]) which was never credited — still marks spent/outputs.
        // Crediting deposit already done; publish_setup will spend [0..] and credit deposit again.
        let _ = ledger.publish_setup(&setup);

        let pay = make_payment_tx(&deposit, 100, &aux, 1, &server);
        let mk = || PostedPayment {
            tx: pay.clone(),
            sigma_a: sign_tx(&sk_a, &pay),
            sigma_s: sign_tx(&sk_s, &pay),
            sigma_aux: sign_tx(&sk_aux, &pay),
            server_index: 1,
            deposit_index: 1,
        };
        ledger.publish_payment(mk()).unwrap();
        assert!(ledger.publish_payment(mk()).is_err());
    }

    #[test]
    fn sign_verify_tx() {
        let mut rng = thread_rng();
        let (sk, vk) = schnorr::Ds::kgen(&mut rng);
        let tx = make_payment_tx(
            &Address([1u8; 32]),
            1,
            &Address([2u8; 32]),
            1,
            &Address([3u8; 32]),
        );
        let sig = sign_tx(&sk, &tx);
        assert!(verify_tx_sig(&vk, &tx, &sig));
        assert!(!verify_tx_sig(&vk, &make_payment_tx(
            &Address([1u8; 32]),
            2,
            &Address([2u8; 32]),
            1,
            &Address([3u8; 32]),
        ), &sig));
    }
}
