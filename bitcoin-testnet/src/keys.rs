//! Key and address material for client, service, and auxiliary roles.

use crate::error::{Error, Result};
use crate::network::BtcNetwork;
use bitcoin::key::{Keypair, PrivateKey, PublicKey};
use bitcoin::secp256k1::{rand::rngs::OsRng, Secp256k1};
use bitcoin::{Address, CompressedPublicKey};
use serde::{Deserialize, Serialize};

/// One keypair plus its common address forms.
#[derive(Clone, Debug)]
pub struct RoleKey {
    pub secret: PrivateKey,
    pub public: PublicKey,
    /// P2WPKH (SegWit v0) — works everywhere bitcoin-cli knows.
    pub p2wpkh: Address,
    /// P2TR output (untweaked x-only) for Taproot experiments.
    pub p2tr: Address,
}

impl RoleKey {
    pub fn generate(network: BtcNetwork) -> Result<Self> {
        let sk = bitcoin::secp256k1::SecretKey::new(&mut OsRng);
        let secret = PrivateKey::new(sk, network.to_bitcoin());
        Self::from_private(secret, network)
    }

    pub fn from_wif(wif: &str, network: BtcNetwork) -> Result<Self> {
        let secret =
            PrivateKey::from_wif(wif).map_err(|e| Error::Bitcoin(format!("bad WIF: {e}")))?;
        Self::from_private(secret, network)
    }

    fn from_private(secret: PrivateKey, network: BtcNetwork) -> Result<Self> {
        let secp = Secp256k1::new();
        let public = PublicKey::from_private_key(&secp, &secret);
        let net = network.to_bitcoin();
        let compressed = CompressedPublicKey(public.inner);
        let p2wpkh = Address::p2wpkh(&compressed, net);
        let keypair = Keypair::from_secret_key(&secp, &secret.inner);
        let (xonly, _parity) = keypair.x_only_public_key();
        let p2tr = Address::p2tr(&secp, xonly, None, net);
        Ok(Self {
            secret,
            public,
            p2wpkh,
            p2tr,
        })
    }

    pub fn wif(&self) -> String {
        self.secret.to_wif()
    }

    pub fn pubkey_hex(&self) -> String {
        self.public.to_string()
    }

    pub fn to_card(&self, role: &str, network: BtcNetwork) -> KeyCard {
        KeyCard {
            role: role.to_string(),
            network: network.name().to_string(),
            wif: self.wif(),
            pubkey: self.pubkey_hex(),
            p2wpkh: self.p2wpkh.to_string(),
            p2tr: self.p2tr.to_string(),
        }
    }
}

/// Exportable key card for scripts / JSON.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyCard {
    pub role: String,
    pub network: String,
    pub wif: String,
    pub pubkey: String,
    pub p2wpkh: String,
    pub p2tr: String,
}

/// Paper parties for one Vitārit session.
#[derive(Clone, Debug)]
pub struct SessionKeys {
    pub network: BtcNetwork,
    pub client_funding: RoleKey,
    pub client_deposit: Vec<RoleKey>,
    pub service_deposit: Vec<RoleKey>,
    pub server_aux: Vec<RoleKey>,
    pub server_receive: Vec<RoleKey>,
}

impl SessionKeys {
    pub fn generate(network: BtcNetwork, t: usize, n: usize) -> Result<Self> {
        if n == 0 || t >= n {
            return Err(Error::InvalidParam(format!(
                "need 0 ≤ t < n, got t={t} n={n}"
            )));
        }
        let deposits = t + 1;
        Ok(Self {
            network,
            client_funding: RoleKey::generate(network)?,
            client_deposit: (0..deposits)
                .map(|_| RoleKey::generate(network))
                .collect::<Result<_>>()?,
            service_deposit: (0..deposits)
                .map(|_| RoleKey::generate(network))
                .collect::<Result<_>>()?,
            server_aux: (0..n)
                .map(|_| RoleKey::generate(network))
                .collect::<Result<_>>()?,
            server_receive: (0..n)
                .map(|_| RoleKey::generate(network))
                .collect::<Result<_>>()?,
        })
    }

    pub fn export_cards(&self) -> Vec<KeyCard> {
        let mut cards = Vec::new();
        cards.push(self.client_funding.to_card("client_funding", self.network));
        for (j, k) in self.client_deposit.iter().enumerate() {
            cards.push(k.to_card(&format!("client_deposit_{}", j + 1), self.network));
        }
        for (j, k) in self.service_deposit.iter().enumerate() {
            cards.push(k.to_card(&format!("service_deposit_{}", j + 1), self.network));
        }
        for (i, k) in self.server_aux.iter().enumerate() {
            cards.push(k.to_card(&format!("server_aux_{}", i + 1), self.network));
        }
        for (i, k) in self.server_receive.iter().enumerate() {
            cards.push(k.to_card(&format!("server_receive_{}", i + 1), self.network));
        }
        cards
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_session_keys() {
        let keys = SessionKeys::generate(BtcNetwork::Regtest, 1, 3).unwrap();
        assert_eq!(keys.client_deposit.len(), 2);
        assert_eq!(keys.server_aux.len(), 3);
        assert!(keys.client_funding.p2wpkh.to_string().starts_with("bcrt"));
    }
}
