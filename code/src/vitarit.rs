//! Figure 7 — Vitārit protocol.
//!
//! Setup → Payment (per-server Γ²ᵖᶜ) → Reconstruction.

use crate::dvrf::{Dvts, FullEval, FullProof, KeySet, PartialEval, PartialProof};
use crate::error::{Error, Result};
use crate::gamma2pc::{ClientInput, CommonInput, Gamma2pc, ServerInput};
use crate::schnorr::{self, SigningKey, VerificationKey};
use crate::tx::{
    self, make_payment_tx, make_setup_tx, Address, Ledger,
};
use crate::vne::Instance;
use rand_core::{CryptoRng, RngCore};

/// Protocol parameters.
#[derive(Clone, Debug)]
pub struct Params {
    /// Corruption threshold t (need t+1 shares / deposits).
    pub t: usize,
    /// Number of servers n.
    pub n: usize,
    /// Coins per deposit.
    pub deposit_value: u64,
    /// Auxiliary lock amount ε (paper: 1 satoshi).
    pub aux_value: u64,
    /// Cut-and-choose λ_s (paper default 32).
    pub lambda_s: usize,
}

impl Default for Params {
    fn default() -> Self {
        Self {
            t: 1,
            n: 3,
            deposit_value: 100_000,
            aux_value: 1,
            lambda_s: 4, // tests use small λ_s; set 32 for paper parameters
        }
    }
}

/// Server-side long-term material.
pub struct ServerParty {
    pub index: usize, // 1-indexed
    pub sk_dvts: crate::dvrf::PartialSk,
    pub sk_aux: SigningKey,
    pub pk_aux: VerificationKey,
    pub aux_addr: Address,
    /// Shared service signing keys for each of the t+1 deposits.
    pub sk_s: Vec<SigningKey>,
    pub pk_s: Vec<VerificationKey>,
}

/// Client-side material.
pub struct ClientParty {
    pub sk_funding: SigningKey,
    pub pk_funding: VerificationKey,
    pub funding_addr: Address,
    /// Per-deposit client keys (pk_{A,j}, sk_{A,j}).
    pub sk_a: Vec<SigningKey>,
    pub pk_a: Vec<VerificationKey>,
    /// Receiving address key for the server payout (not used by client).
    pub deposit_addrs: Vec<Address>,
}

/// Public protocol view after key generation / address setup.
pub struct PublicSetup {
    pub params: Params,
    pub keys: KeySet,
    pub pk_s: Vec<VerificationKey>,
    pub deposit_addrs: Vec<Address>,
    pub aux_addrs: Vec<Address>,
    pub server_payout_addrs: Vec<Address>,
}

pub struct VitaritProtocol {
    pub params: Params,
    pub gamma: Gamma2pc,
    pub ledger: Ledger,
}

impl VitaritProtocol {
    pub fn new(params: Params) -> Self {
        let gamma = Gamma2pc::new(params.lambda_s);
        Self {
            params,
            gamma,
            ledger: Ledger::new(),
        }
    }

    /// Generate DVTS keys + per-party transaction keys.
    pub fn setup_parties<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
    ) -> Result<(ClientParty, Vec<ServerParty>, PublicSetup)> {
        let p = &self.params;
        let keys = Dvts::dkgen(p.t, p.n, rng)?;

        // Shared service keys for each deposit j ∈ [t+1].
        let mut sk_s = Vec::with_capacity(p.t + 1);
        let mut pk_s = Vec::with_capacity(p.t + 1);
        for _ in 0..(p.t + 1) {
            let (sk, pk) = schnorr::Ds::kgen(rng);
            sk_s.push(sk);
            pk_s.push(pk);
        }

        // Client deposit keys.
        let (sk_funding, pk_funding) = schnorr::Ds::kgen(rng);
        let funding_addr = Address::from_vk(&pk_funding);
        let mut sk_a = Vec::with_capacity(p.t + 1);
        let mut pk_a = Vec::with_capacity(p.t + 1);
        let mut deposit_addrs = Vec::with_capacity(p.t + 1);
        for j in 0..(p.t + 1) {
            let (sk, pk) = schnorr::Ds::kgen(rng);
            deposit_addrs.push(Address::from_multisig(&pk, &pk_s[j]));
            sk_a.push(sk);
            pk_a.push(pk);
        }

        let client = ClientParty {
            sk_funding,
            pk_funding,
            funding_addr: funding_addr.clone(),
            sk_a,
            pk_a: pk_a.clone(),
            deposit_addrs: deposit_addrs.clone(),
        };

        let mut servers = Vec::with_capacity(p.n);
        let mut aux_addrs = Vec::with_capacity(p.n);
        let mut server_payout_addrs = Vec::with_capacity(p.n);
        for i in 0..p.n {
            let (sk_aux, pk_aux) = schnorr::Ds::kgen(rng);
            let aux_addr = Address::from_vk(&pk_aux);
            let (sk_pay, pk_pay) = schnorr::Ds::kgen(rng);
            let pay_addr = Address::from_vk(&pk_pay);
            let _ = sk_pay; // payout sk not needed in simulation
            aux_addrs.push(aux_addr.clone());
            server_payout_addrs.push(pay_addr.clone());
            servers.push(ServerParty {
                index: i + 1,
                sk_dvts: keys.partial_sks[i].clone(),
                sk_aux,
                pk_aux,
                aux_addr,
                sk_s: sk_s.clone(),
                pk_s: pk_s.clone(),
            });
            // Fund each auxiliary address with ε.
            self.ledger.credit(&aux_addrs[i], p.aux_value);
        }

        // Fund the client's funding address.
        let total = p.deposit_value * (p.t as u64 + 1);
        self.ledger.credit(&funding_addr, total);

        let public = PublicSetup {
            params: p.clone(),
            keys,
            pk_s,
            deposit_addrs,
            aux_addrs,
            server_payout_addrs,
        };
        Ok((client, servers, public))
    }

    /// Setup phase of Figure 7: publish `tx_stp`.
    pub fn setup_phase(&self, client: &ClientParty, public: &PublicSetup) -> Result<()> {
        let p = &self.params;
        let total = p.deposit_value * (p.t as u64 + 1);
        let deposits: Vec<(Address, u64)> = public
            .deposit_addrs
            .iter()
            .map(|a| (a.clone(), p.deposit_value))
            .collect();
        let tx_stp = make_setup_tx(&client.funding_addr, total, &deposits);
        // Client signature is implicit in our abstract ledger.
        let _sig = tx::sign_tx(&client.sk_funding, &tx_stp);
        self.ledger.publish_setup(&tx_stp)?;
        Ok(())
    }

    /// Payment phase: client interacts with the first `t+1` servers
    /// (the "fastest responders" in the model). Each server claims a
    /// distinct deposit via its auxiliary address (pay-at-most-once).
    pub fn payment_phase<R: RngCore + CryptoRng>(
        &self,
        client: &ClientParty,
        servers: &[ServerParty],
        public: &PublicSetup,
        m_star: &[u8],
        rng: &mut R,
    ) -> Result<Vec<(usize, PartialEval, PartialProof)>> {
        let p = &self.params;
        let need = p.t + 1;
        if servers.len() < need {
            return Err(Error::InsufficientShares {
                need,
                got: servers.len(),
            });
        }

        let mut collected = Vec::with_capacity(need);

        // Server i claims deposit j = i (for the first t+1 servers).
        for j in 0..need {
            let server = &servers[j];
            let (v_i, pi_i) = Dvts::part_eval(&server.sk_dvts, m_star);

            let tx_pay = make_payment_tx(
                &public.deposit_addrs[j],
                p.deposit_value,
                &server.aux_addr,
                p.aux_value,
                &public.server_payout_addrs[j],
            );

            let inst = Instance::new(
                server.index,
                public.keys.vk.clone(),
                public.keys.partial_vks.clone(),
                m_star,
            );

            let cinp = CommonInput {
                pk_a_j: client.pk_a[j].clone(),
                inst,
                tx_pay,
            };
            let cin = ClientInput {
                sk_a_j: SigningKey(client.sk_a[j].0),
            };
            let sin = ServerInput {
                sk_dvts_i: PartialSkClone(&server.sk_dvts).clone_sk(),
                v_i: v_i.clone(),
                pi_i: pi_i.clone(),
                sk_s_j: SigningKey(server.sk_s[j].0),
                sk_aux_i: SigningKey(server.sk_aux.0),
                server_index: server.index,
                deposit_index: j + 1,
            };

            let (cout, _sout) = self.gamma.run(
                &cinp,
                &cin,
                &sin,
                &server.pk_s[j],
                &server.pk_aux,
                &self.ledger,
                rng,
            )?;

            // Sanity: recovered value matches what the server evaluated.
            if cout.v_i.to_bytes() != v_i.to_bytes() {
                return Err(Error::ProtocolAbort(
                    "client recovered mismatched partial evaluation".into(),
                ));
            }
            collected.push((server.index, cout.v_i, pi_i));
        }

        Ok(collected)
    }

    /// Reconstruction phase of Figure 7.
    pub fn reconstruct(
        &self,
        public: &PublicSetup,
        m_star: &[u8],
        shares: &[(usize, PartialEval, PartialProof)],
    ) -> Result<(FullEval, FullProof)> {
        Dvts::combine(
            &public.keys.vk,
            &public.keys.partial_vks,
            m_star,
            shares,
        )
    }

    /// End-to-end Figure 7 execution.
    pub fn run<R: RngCore + CryptoRng>(
        &self,
        m_star: &[u8],
        rng: &mut R,
    ) -> Result<(FullEval, FullProof, PublicSetup)> {
        let (client, servers, public) = self.setup_parties(rng)?;
        self.setup_phase(&client, &public)?;
        let shares = self.payment_phase(&client, &servers, &public, m_star, rng)?;
        let (v, pi) = self.reconstruct(&public, m_star, &shares)?;
        if !Dvts::verify(&public.keys.vk, &public.keys.partial_vks, m_star, &v, &pi) {
            return Err(Error::Verification("final VRF Verify failed".into()));
        }
        Ok((v, pi, public))
    }
}

/// Helper because PartialSk's Zeroize+Clone needs an explicit clone path
/// that does not trip move-from-reference issues with SigningKey.
struct PartialSkClone<'a>(&'a crate::dvrf::PartialSk);
impl PartialSkClone<'_> {
    fn clone_sk(&self) -> crate::dvrf::PartialSk {
        crate::dvrf::PartialSk(self.0 .0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    #[test]
    fn vitarit_fig7_end_to_end() {
        let mut rng = thread_rng();
        let params = Params {
            t: 1,
            n: 3,
            deposit_value: 50_000,
            aux_value: 1,
            lambda_s: 4,
        };
        let proto = VitaritProtocol::new(params);
        let m = b"vitarit-request";
        let (v, pi, public) = proto.run(m, &mut rng).unwrap();
        assert!(Dvts::verify(
            &public.keys.vk,
            &public.keys.partial_vks,
            m,
            &v,
            &pi
        ));
        // Exactly t+1 payments posted, each consuming one aux + one deposit.
        assert_eq!(proto.ledger.payments().len(), 2);
    }

    #[test]
    fn pay_at_most_once_via_aux() {
        let mut rng = thread_rng();
        let params = Params {
            t: 1,
            n: 3,
            deposit_value: 10,
            aux_value: 1,
            lambda_s: 2,
        };
        let proto = VitaritProtocol::new(params.clone());
        let (client, servers, public) = proto.setup_parties(&mut rng).unwrap();
        proto.setup_phase(&client, &public).unwrap();

        // First payment by server 1 on deposit 1 succeeds.
        let m = b"m";
        let shares = proto
            .payment_phase(&client, &servers, &public, m, &mut rng)
            .unwrap();
        assert_eq!(shares.len(), 2);

        // Attempting to reuse server 1's already-spent aux address must fail.
        let server = &servers[0];
        let (v_i, pi_i) = Dvts::part_eval(&server.sk_dvts, m);
        let tx_pay = make_payment_tx(
            &public.deposit_addrs[0], // deposit already spent too
            params.deposit_value,
            &server.aux_addr,
            params.aux_value,
            &public.server_payout_addrs[0],
        );
        let inst = Instance::new(
            server.index,
            public.keys.vk.clone(),
            public.keys.partial_vks.clone(),
            m,
        );
        let cinp = CommonInput {
            pk_a_j: client.pk_a[0].clone(),
            inst,
            tx_pay,
        };
        let cin = ClientInput {
            sk_a_j: SigningKey(client.sk_a[0].0),
        };
        let sin = ServerInput {
            sk_dvts_i: crate::dvrf::PartialSk(server.sk_dvts.0),
            v_i,
            pi_i,
            sk_s_j: SigningKey(server.sk_s[0].0),
            sk_aux_i: SigningKey(server.sk_aux.0),
            server_index: server.index,
            deposit_index: 1,
        };
        let err = proto.gamma.run(
            &cinp,
            &cin,
            &sin,
            &server.pk_s[0],
            &server.pk_aux,
            &proto.ledger,
            &mut rng,
        );
        match err {
            Err(e) => {
                let msg = format!("{e}");
                assert!(
                    msg.contains("already spent") || msg.contains("pay-at-most-once"),
                    "unexpected error: {msg}"
                );
            }
            Ok(_) => panic!("expected auxiliary address reuse to fail"),
        }
    }

    #[test]
    fn vitarit_phases_separately() {
        let mut rng = thread_rng();
        let params = Params {
            t: 1,
            n: 3,
            deposit_value: 1_000,
            aux_value: 1,
            lambda_s: 2,
        };
        let proto = VitaritProtocol::new(params);
        let (client, servers, public) = proto.setup_parties(&mut rng).unwrap();
        assert_eq!(public.deposit_addrs.len(), 2);
        assert_eq!(servers.len(), 3);
        proto.setup_phase(&client, &public).unwrap();
        let m = b"phased";
        let shares = proto
            .payment_phase(&client, &servers, &public, m, &mut rng)
            .unwrap();
        let (v, pi) = proto.reconstruct(&public, m, &shares).unwrap();
        assert!(Dvts::verify(
            &public.keys.vk,
            &public.keys.partial_vks,
            m,
            &v,
            &pi
        ));
    }

    #[test]
    fn vitarit_t2_n5() {
        let mut rng = thread_rng();
        let params = Params {
            t: 2,
            n: 5,
            deposit_value: 100,
            aux_value: 1,
            lambda_s: 2,
        };
        let proto = VitaritProtocol::new(params);
        let m = b"larger-threshold";
        let (v, pi, public) = proto.run(m, &mut rng).unwrap();
        assert!(Dvts::verify(
            &public.keys.vk,
            &public.keys.partial_vks,
            m,
            &v,
            &pi
        ));
        assert_eq!(proto.ledger.payments().len(), 3); // t+1
    }

    #[test]
    fn vitarit_payment_needs_enough_servers() {
        let mut rng = thread_rng();
        let params = Params {
            t: 2,
            n: 3,
            deposit_value: 10,
            aux_value: 1,
            lambda_s: 2,
        };
        let proto = VitaritProtocol::new(params);
        let (client, servers, public) = proto.setup_parties(&mut rng).unwrap();
        proto.setup_phase(&client, &public).unwrap();
        // Truncate server list artificially
        let few = &servers[..2];
        let err = proto.payment_phase(&client, few, &public, b"m", &mut rng);
        assert!(matches!(
            err,
            Err(crate::error::Error::InsufficientShares { need: 3, got: 2 })
        ));
    }

    #[test]
    fn params_default_sane() {
        let p = Params::default();
        assert!(p.t < p.n);
        assert!(p.lambda_s >= 1);
    }
}
