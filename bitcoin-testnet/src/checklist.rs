//! Capability checklist: what a Bitcoin deployment must provide to realize Vitārit.

use crate::network::BtcNetwork;
use crate::policy::RelayLimits;
use serde::{Deserialize, Serialize};
use std::process::Command;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CheckItem {
    pub id: String,
    pub required: bool,
    pub status: CheckStatus,
    pub detail: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    Pass,
    Fail,
    Warn,
    Info,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChecklistReport {
    pub network: String,
    pub items: Vec<CheckItem>,
    pub summary: String,
}

/// Static requirements derived from the paper (independent of a running node).
pub fn paper_requirements(network: BtcNetwork) -> Vec<CheckItem> {
    let lim = RelayLimits::default();
    let (aux, aux_note) = lim.recommend_aux_value(1);
    vec![
        CheckItem {
            id: "utxo_model".into(),
            required: true,
            status: CheckStatus::Pass,
            detail: "Bitcoin UTXO model required for auxiliary pay-at-most-once (Fig 2).".into(),
        },
        CheckItem {
            id: "signature_scripts_only".into(),
            required: true,
            status: CheckStatus::Pass,
            detail: "Deposit Φ_j = 2-of-2 signature check; aux Φ = single-key signature (no Turing-complete contract).".into(),
        },
        CheckItem {
            id: "deposit_2of2".into(),
            required: true,
            status: CheckStatus::Info,
            detail: format!(
                "Encode deposits as P2WSH 2-of-2 (wsh(multi(2,pk_A,pk_S))). Network={}",
                network.name()
            ),
        },
        CheckItem {
            id: "schnorr_adaptor".into(),
            required: true,
            status: CheckStatus::Warn,
            detail: "Paper Γ²ᵖᶜ uses Schnorr adaptor signatures (Taproot/BIP340). P2WSH 2-of-2 uses ECDSA — pair with ../code adaptor on a Taproot/MuSig path for a full match, or run ECDSA deposit + crypto off-chain for UTXO tests.".into(),
        },
        CheckItem {
            id: "aux_epsilon_dust".into(),
            required: true,
            status: CheckStatus::Warn,
            detail: format!(
                "Paper ε=1 sat; Core dustrelayfee ⇒ use ≥ {aux} sats for P2WPKH aux. {aux_note}"
            ),
        },
        CheckItem {
            id: "payment_two_inputs".into(),
            required: true,
            status: CheckStatus::Pass,
            detail: "Payment tx^j_pay,i must spend deposit_j AND aux_i atomically (Fig 7).".into(),
        },
        CheckItem {
            id: "t_plus_1_deposits".into(),
            required: true,
            status: CheckStatus::Pass,
            detail: "Setup creates exactly (t+1) independent deposit outputs of value x.".into(),
        },
        CheckItem {
            id: "optional_refund_csv".into(),
            required: false,
            status: CheckStatus::Info,
            detail: "Section 3 mentions timeout T refunds; optional CSV script helper in policy::refund_csv_script.".into(),
        },
        CheckItem {
            id: "offchain_vne_gamma".into(),
            required: true,
            status: CheckStatus::Info,
            detail: "VNE + Γ²ᵖᶜ (Figs 8–9) stay off-chain in ../code; chain only carries adapted/ordinary signatures.".into(),
        },
    ]
}

/// Probe whether `bitcoin-cli` is available and which chain it talks to.
pub fn probe_bitcoin_cli(extra_args: &[&str]) -> Vec<CheckItem> {
    let mut items = Vec::new();
    let mut base = Command::new("bitcoin-cli");
    for a in extra_args {
        base.arg(a);
    }
    match base.arg("getblockchaininfo").output() {
        Ok(out) if out.status.success() => {
            let body = String::from_utf8_lossy(&out.stdout);
            let chain = body
                .split("\"chain\":")
                .nth(1)
                .and_then(|s| s.split('"').nth(1))
                .unwrap_or("unknown");
            items.push(CheckItem {
                id: "bitcoin_cli".into(),
                required: false,
                status: CheckStatus::Pass,
                detail: format!("bitcoin-cli reachable; chain={chain}"),
            });
            // Taproot active?
            let mut tip = Command::new("bitcoin-cli");
            for a in extra_args {
                tip.arg(a);
            }
            if let Ok(o) = tip.args(["getblockcount"]).output() {
                let height = String::from_utf8_lossy(&o.stdout).trim().to_string();
                items.push(CheckItem {
                    id: "block_height".into(),
                    required: false,
                    status: CheckStatus::Info,
                    detail: format!("block height {height}"),
                });
            }
        }
        Ok(out) => {
            items.push(CheckItem {
                id: "bitcoin_cli".into(),
                required: false,
                status: CheckStatus::Fail,
                detail: format!(
                    "bitcoin-cli failed: {}",
                    String::from_utf8_lossy(&out.stderr).trim()
                ),
            });
        }
        Err(e) => {
            items.push(CheckItem {
                id: "bitcoin_cli".into(),
                required: false,
                status: CheckStatus::Fail,
                detail: format!("bitcoin-cli not found / not runnable: {e}"),
            });
        }
    }
    items
}

pub fn full_report(network: BtcNetwork, cli_args: &[&str]) -> ChecklistReport {
    let mut items = paper_requirements(network);
    items.extend(probe_bitcoin_cli(cli_args));
    let fails = items
        .iter()
        .filter(|i| i.required && i.status == CheckStatus::Fail)
        .count();
    let warns = items
        .iter()
        .filter(|i| i.status == CheckStatus::Warn)
        .count();
    let summary = if fails > 0 {
        format!("BLOCKED: {fails} required checks failed, {warns} warnings")
    } else if warns > 0 {
        format!("READY WITH CAVEATS: {warns} warnings (see schnorr_adaptor / dust)")
    } else {
        "READY".into()
    };
    ChecklistReport {
        network: network.name().into(),
        items,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paper_checklist_has_core_items() {
        let items = paper_requirements(BtcNetwork::Testnet);
        assert!(items.iter().any(|i| i.id == "payment_two_inputs"));
        assert!(items.iter().any(|i| i.id == "aux_epsilon_dust"));
        let report = full_report(BtcNetwork::Regtest, &[]);
        assert!(!report.summary.is_empty());
    }
}
