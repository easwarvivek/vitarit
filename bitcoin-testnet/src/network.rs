//! Network selection for addresses and scripts.

use bitcoin::Network;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum BtcNetwork {
    /// Local isolation — default for automated tests.
    Regtest,
    /// Public Bitcoin test network (testnet3).
    Testnet,
    /// Signet (often easier faucets / cheaper).
    Signet,
    /// Mainnet (not used by the tooling by default).
    Bitcoin,
}

impl BtcNetwork {
    pub fn to_bitcoin(self) -> Network {
        match self {
            BtcNetwork::Regtest => Network::Regtest,
            BtcNetwork::Testnet => Network::Testnet,
            BtcNetwork::Signet => Network::Signet,
            BtcNetwork::Bitcoin => Network::Bitcoin,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            BtcNetwork::Regtest => "regtest",
            BtcNetwork::Testnet => "testnet",
            BtcNetwork::Signet => "signet",
            BtcNetwork::Bitcoin => "mainnet",
        }
    }

    pub fn parse(s: &str) -> crate::Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "regtest" => Ok(BtcNetwork::Regtest),
            "testnet" | "testnet3" => Ok(BtcNetwork::Testnet),
            "signet" => Ok(BtcNetwork::Signet),
            "mainnet" | "bitcoin" => Ok(BtcNetwork::Bitcoin),
            other => Err(crate::Error::InvalidParam(format!("unknown network {other}"))),
        }
    }
}
