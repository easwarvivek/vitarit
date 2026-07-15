//! ECDSA witnesses for P2WSH 2-of-2 deposits and P2WPKH aux inputs.
//!
//! Paper Fig 8 uses Schnorr adaptor signatures (Taproot). This module signs the
//! SegWit-v0 payment path used on Bitcoin testnet/regtest; the Ristretto
//! adaptor from `vitarit` remains an off-chain fairness channel.

use crate::error::{Error, Result};
use crate::policy::DepositOutput;
use bitcoin::ecdsa::Signature as EcdsaSig;
use bitcoin::key::PrivateKey;
use bitcoin::secp256k1::{Message, Secp256k1};
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::{Amount, ScriptBuf, Transaction, TxOut, Witness};

/// Complete witnesses on a two-input payment: deposit (P2WSH 2-of-2) + aux (P2WPKH).
pub fn sign_payment_2of2_plus_aux(
    tx: &mut Transaction,
    deposit: &DepositOutput,
    deposit_value: Amount,
    aux_spk: &ScriptBuf,
    aux_value: Amount,
    aux_pubkey: &bitcoin::PublicKey,
    sk_client: &PrivateKey,
    sk_service: &PrivateKey,
    sk_aux: &PrivateKey,
) -> Result<()> {
    if tx.input.len() != 2 {
        return Err(Error::InvalidParam(
            "payment must have exactly 2 inputs (deposit, aux)".into(),
        ));
    }

    let prevouts = [
        TxOut {
            value: deposit_value,
            script_pubkey: deposit.script_pubkey.clone(),
        },
        TxOut {
            value: aux_value,
            script_pubkey: aux_spk.clone(),
        },
    ];

    // Deposit input 0: P2WSH 2-of-2.
    let sig_a = sign_p2wsh_input(tx, 0, &prevouts, &deposit.witness_script, sk_client)?;
    let sig_s = sign_p2wsh_input(tx, 0, &prevouts, &deposit.witness_script, sk_service)?;
    let mut dep_wit = Witness::new();
    dep_wit.push([]); // OP_CHECKMULTISIG dummy
    dep_wit.push(sig_a.to_vec());
    dep_wit.push(sig_s.to_vec());
    dep_wit.push(deposit.witness_script.as_bytes());
    tx.input[0].witness = dep_wit;

    // Aux input 1: P2WPKH — rust-bitcoin wants the *script_pubkey*, not BIP143 scriptCode.
    let sig_aux = sign_p2wpkh_input(tx, 1, &prevouts, aux_spk, sk_aux)?;
    let mut aux_wit = Witness::new();
    aux_wit.push(sig_aux.to_vec());
    aux_wit.push(aux_pubkey.to_bytes());
    tx.input[1].witness = aux_wit;

    Ok(())
}

fn sign_p2wsh_input(
    tx: &Transaction,
    input_index: usize,
    prevouts: &[TxOut],
    witness_script: &ScriptBuf,
    sk: &PrivateKey,
) -> Result<EcdsaSig> {
    let secp = Secp256k1::new();
    let mut cache = SighashCache::new(tx);
    let sighash = cache
        .p2wsh_signature_hash(
            input_index,
            witness_script,
            prevouts[input_index].value,
            EcdsaSighashType::All,
        )
        .map_err(|e| Error::Bitcoin(format!("p2wsh sighash: {e}")))?;
    let msg = Message::from_digest_slice(sighash.as_ref())
        .map_err(|e| Error::Bitcoin(format!("sighash message: {e}")))?;
    let sig = secp.sign_ecdsa(&msg, &sk.inner);
    Ok(EcdsaSig {
        signature: sig,
        sighash_type: EcdsaSighashType::All,
    })
}

fn sign_p2wpkh_input(
    tx: &Transaction,
    input_index: usize,
    prevouts: &[TxOut],
    script_pubkey: &ScriptBuf,
    sk: &PrivateKey,
) -> Result<EcdsaSig> {
    let secp = Secp256k1::new();
    let mut cache = SighashCache::new(tx);
    let sighash = cache
        .p2wpkh_signature_hash(
            input_index,
            script_pubkey,
            prevouts[input_index].value,
            EcdsaSighashType::All,
        )
        .map_err(|e| Error::Bitcoin(format!("p2wpkh sighash: {e}")))?;
    let msg = Message::from_digest_slice(sighash.as_ref())
        .map_err(|e| Error::Bitcoin(format!("sighash message: {e}")))?;
    let sig = secp.sign_ecdsa(&msg, &sk.inner);
    Ok(EcdsaSig {
        signature: sig,
        sighash_type: EcdsaSighashType::All,
    })
}

/// Consensus-serialized unsigned tx bytes — bind Ristretto adaptor to this.
pub fn payment_adaptor_message(tx: &Transaction) -> Vec<u8> {
    use bitcoin::consensus::Encodable;
    let mut buf = Vec::new();
    let mut unsigned = tx.clone();
    for tin in &mut unsigned.input {
        tin.witness = Witness::new();
        tin.script_sig = ScriptBuf::new();
    }
    unsigned.consensus_encode(&mut buf).expect("encode");
    buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::SessionKeys;
    use crate::ledger::SimulatedLedger;
    use crate::network::BtcNetwork;
    use crate::transactions::{fake_outpoint, tx_hex, PaymentPlan, SetupPlan};
    use bitcoin::TxOut;

    #[test]
    fn signed_payment_applies_on_simulated_ledger() {
        let keys = SessionKeys::generate(BtcNetwork::Regtest, 1, 3).unwrap();
        let setup = SetupPlan::from_keys(&keys, 10_000, 200).unwrap();
        let aux_value = 294u64;
        let fee = 200u64;
        let pay = PaymentPlan::from_session(&keys, &setup, 1, 1, aux_value, fee).unwrap();

        let dep_op = fake_outpoint(1);
        let aux_op = fake_outpoint(2);
        let mut led = SimulatedLedger::new();
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
                value: Amount::from_sat(aux_value),
                script_pubkey: keys.server_aux[0].p2wpkh.script_pubkey(),
            },
        );

        let mut tx = pay.build_unsigned(dep_op, aux_op).unwrap();
        sign_payment_2of2_plus_aux(
            &mut tx,
            &pay.deposit,
            Amount::from_sat(10_000),
            &keys.server_aux[0].p2wpkh.script_pubkey(),
            Amount::from_sat(aux_value),
            &keys.server_aux[0].public,
            &keys.client_deposit[0].secret,
            &keys.service_deposit[0].secret,
            &keys.server_aux[0].secret,
        )
        .unwrap();

        assert_eq!(tx.input[0].witness.len(), 4);
        assert_eq!(tx.input[1].witness.len(), 2);
        assert!(!tx_hex(&tx).is_empty());
        led.apply(&tx).unwrap();
        assert_eq!(led.confirmed_count(), 1);

        let msg = payment_adaptor_message(&tx);
        assert!(!msg.is_empty());
    }
}
