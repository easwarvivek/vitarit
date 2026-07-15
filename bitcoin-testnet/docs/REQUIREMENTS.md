# Bitcoin requirements to realize Vitārit (ePrint 2025/174)

This document maps the paper’s on-chain assumptions to concrete Bitcoin features.

## Must have

| Paper element | Bitcoin requirement |
|---------------|---------------------|
| UTXO uniqueness | Native Bitcoin consensus (UTXO set) |
| Deposit Φ_j | Signature script requiring **both** `pk_{A,j}` and `pk_{S,j}` — implemented as **P2WSH 2-of-2** `wsh(multi(2,…))` |
| Aux Φ_aux,i | Single-key spend — **P2WPKH** (or P2TR) |
| `tx^j_pay,i` | **One transaction, two inputs**: deposit UTXO + aux UTXO → server receive |
| Pay at most once | Spending `aux_i` consumes that UTXO; a second payment referencing it is invalid |
| Minimal scripts | Signature verification only (no smart-contract VM) |

## Cryptographic / script caveats

| Paper element | Status on Bitcoin today |
|---------------|-------------------------|
| Schnorr adaptor signatures (Fig 8) | Requires **Taproot (BIP340)** key-path (or MuSig2 aggregate). The crypto crate in `../code` implements adaptor math off-chain. |
| P2WSH 2-of-2 drills in this folder | Use **ECDSA** multisig for live `bitcoin-cli` regtest drills. Good for testing the **UTXO / two-input** design; not a byte-level match to Schnorr AS. |
| ε = 1 satoshi | Below Bitcoin Core **dustrelayfee** for standard P2WPKH (~294 sats). Tooling raises aux to dust minimum and warns. |
| Timeout refund `T` (overview §3) | Optional **CSV** refund branch (`policy::refund_csv_script`); not required for Fig 7 happy path. |

## Off-chain vs on-chain split

```
Off-chain (../code)          On-chain (this folder)
─────────────────────        ───────────────────────
DVRF / DVTS                  —
VNE (Fig 9)                  —
Γ²ᵖᶜ / adaptor (Fig 8)       Final signatures in witnesses
                             Setup tx_stp
                             Aux funding tx_aux,i
                             Payment tx^j_pay,i
```

## Suggested deployment order

1. Run offline checklist + Fig 7 simulation (`cargo test`, `dry_run.sh`).
2. Stand up regtest (`01_regtest_up.sh`) and run `30_regtest_fig7_drill.sh`.
3. Repeat on **signet** or **testnet** with faucets; keep aux ≥ dust.
4. For paper-faithful Schnorr AS: migrate deposit signing to Taproot/MuSig2 and feed BIP340 sighashes into `../code` adaptor APIs.
