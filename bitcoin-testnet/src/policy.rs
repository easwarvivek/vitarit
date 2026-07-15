//! Script / output policies matching the paper’s Φ conditions.
//!
//! Paper requirements (minimal Bitcoin scripts):
//! - Deposit `ϕ_j`: spendable only with signatures under `pk_{A,j}` **and** `pk_{S,j}`
//! - Auxiliary `ϕ_aux,i`: spendable with signature under `pk_aux,i`
//! - Optional timeout refund (Section 3 overview): client recovery after relative locktime `T`
//!
//! Concrete encodings used here:
//! - **Deposit**: P2WSH 2-of-2 CHECKMULTISIG (widely supportable on testnet/regtest today)
//! - **Aux / receive**: P2WPKH
//! - **Optional refund**: CSV-timelocked branch documented; primary path remains 2-of-2

use crate::error::Result;
use crate::network::BtcNetwork;
use bitcoin::blockdata::opcodes::all::{OP_CHECKMULTISIG, OP_CHECKSIG, OP_CSV, OP_DROP};
use bitcoin::blockdata::script::Builder;
use bitcoin::key::PublicKey;
use bitcoin::{Address, ScriptBuf};
use serde::{Deserialize, Serialize};

/// How deposits are encoded on chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DepositEncoding {
    /// `OP_2 <pk_A> <pk_S> OP_2 OP_CHECKMULTISIG` wrapped in P2WSH.
    P2wsh2of2,
}

/// Deposit address jointly controlled by client and service keys.
#[derive(Clone, Debug)]
pub struct DepositOutput {
    pub witness_script: ScriptBuf,
    pub script_pubkey: ScriptBuf,
    pub address: Address,
    pub pk_a: PublicKey,
    pub pk_s: PublicKey,
}

impl DepositOutput {
    pub fn p2wsh_2of2(
        pk_a: &PublicKey,
        pk_s: &PublicKey,
        network: BtcNetwork,
    ) -> Result<Self> {
        // ORDERED 2-of-2: pk_A then pk_S (paper client, then service).
        let witness_script = Builder::new()
            .push_int(2)
            .push_key(pk_a)
            .push_key(pk_s)
            .push_int(2)
            .push_opcode(OP_CHECKMULTISIG)
            .into_script();

        let address = Address::p2wsh(&witness_script, network.to_bitcoin());
        let script_pubkey = address.script_pubkey();
        Ok(Self {
            witness_script,
            script_pubkey,
            address,
            pk_a: *pk_a,
            pk_s: *pk_s,
        })
    }

    /// Descriptor string usable with bitcoin-cli `deriveaddresses` / `importdescriptors`.
    pub fn descriptor_wsh_multi(&self) -> String {
        format!(
            "wsh(multi(2,{},{}))",
            self.pk_a, self.pk_s
        )
    }
}

/// Single-key auxiliary / receive output (P2WPKH).
#[derive(Clone, Debug)]
pub struct SingleKeyOutput {
    pub address: Address,
    pub script_pubkey: ScriptBuf,
    pub pubkey: PublicKey,
}

impl SingleKeyOutput {
    pub fn p2wpkh(pk: &PublicKey, network: BtcNetwork) -> Result<Self> {
        let compressed = bitcoin::CompressedPublicKey(pk.inner);
        let address = Address::p2wpkh(&compressed, network.to_bitcoin());
        Ok(Self {
            script_pubkey: address.script_pubkey(),
            address,
            pubkey: *pk,
        })
    }

    pub fn descriptor_wpkh(&self) -> String {
        format!("wpkh({})", self.pubkey)
    }
}

/// Optional client refund path after `T` blocks (relative CSV), for deposits that
/// were never claimed. Encoded as a separate P2WSH policy operators may fund
/// instead of plain 2-of-2 when they need automatic refunds.
pub fn refund_csv_script(pk_a: &PublicKey, blocks: u16) -> ScriptBuf {
    // `<T> OP_CSV OP_DROP <pk_A> OP_CHECKSIG`
    Builder::new()
        .push_int(blocks as i64)
        .push_opcode(OP_CSV)
        .push_opcode(OP_DROP)
        .push_key(pk_a)
        .push_opcode(OP_CHECKSIG)
        .into_script()
}

/// Dust / relay minimums operators must respect (policy, not consensus).
#[derive(Clone, Copy, Debug)]
pub struct RelayLimits {
    /// Typical P2WPKH dust threshold under Bitcoin Core default dustrelayfee.
    pub p2wpkh_dust_sats: u64,
    /// Typical P2WSH dust threshold.
    pub p2wsh_dust_sats: u64,
}

impl Default for RelayLimits {
    fn default() -> Self {
        Self {
            p2wpkh_dust_sats: 294,
            p2wsh_dust_sats: 330,
        }
    }
}

impl RelayLimits {
    /// Paper suggests ε = 1 satoshi; Core will not relay that for standard outputs.
    pub fn recommend_aux_value(&self, paper_epsilon: u64) -> (u64, &'static str) {
        if paper_epsilon >= self.p2wpkh_dust_sats {
            (paper_epsilon, "paper ε is above dust; usable as-is")
        } else {
            (
                self.p2wpkh_dust_sats,
                "paper ε=1 is below dustrelayfee; use dust minimum for testnet/regtest relay",
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::RoleKey;

    #[test]
    fn deposit_2of2_address_and_descriptor() {
        let net = BtcNetwork::Regtest;
        let a = RoleKey::generate(net).unwrap();
        let s = RoleKey::generate(net).unwrap();
        let dep = DepositOutput::p2wsh_2of2(&a.public, &s.public, net).unwrap();
        assert!(dep.address.to_string().starts_with("bcrt"));
        assert!(dep.descriptor_wsh_multi().starts_with("wsh(multi(2,"));
        assert!(!dep.witness_script.is_empty());
        assert!(dep.script_pubkey.is_p2wsh());
    }

    #[test]
    fn aux_dust_recommendation() {
        let lim = RelayLimits::default();
        let (v, note) = lim.recommend_aux_value(1);
        assert_eq!(v, 294);
        assert!(note.contains("dust"));
    }
}
