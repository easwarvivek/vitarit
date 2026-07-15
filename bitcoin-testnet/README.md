# Vitārit — Bitcoin testnet / regtest layer

On-chain half of **Vitārit** ([ePrint 2025/174](https://eprint.iacr.org/2025/174)):
Figures **2** and **7** (deposits, auxiliary UTXOs, payment transactions,
pay-at-most-once).

This folder is **independent** of `../code` (crypto: VNE, Γ²ᵖᶜ, DVRF).
The full protocol (wire + signing) is exercised from `../integration`.
Do not need to modify the crypto crate to use the Bitcoin tools alone.

## What you get

| Piece | Purpose |
|-------|---------|
| Rust crate `vitarit-bitcoin` | Build/verify Fig 7 tx shapes, descriptors, simulated ledger |
| `docs/REQUIREMENTS.md` | What Bitcoin must provide to realize the paper |
| `docs/TRANSACTION_MAP.md` | Paper txs ↔ concrete inputs/outputs |
| `scripts/` | Prereq check, regtest up/down, live drill, offline dry-run |

## Quick start (no bitcoind)

```bash
cd bitcoin-testnet
chmod +x scripts/*.sh
./scripts/00_check_prereqs.sh
./scripts/dry_run.sh
```

Or manually:

```bash
cd bitcoin-testnet
cargo test
cargo run --example checklist
cargo run --example simulate_fig7
cargo run --bin vitarit-btc -- simulate --t 1 --n 3
```

## Live regtest (optional)

Requires Bitcoin Core (`bitcoind` / `bitcoin-cli`).

```bash
./scripts/01_regtest_up.sh
./scripts/30_regtest_fig7_drill.sh
./scripts/02_regtest_down.sh
```

Testnet / signet: point `bitcoin-cli -testnet` / `-signet` at a funded wallet,
import `wsh(multi(2,…))` deposit descriptors from `vitarit-btc playbook`, keep
aux ≥ dust (~294 sats).

## Layout

```text
bitcoin-testnet/
├── Cargo.toml
├── README.md
├── docs/
│   ├── REQUIREMENTS.md
│   └── TRANSACTION_MAP.md
├── scripts/
│   ├── 00_check_prereqs.sh
│   ├── 01_regtest_up.sh
│   ├── 02_regtest_down.sh
│   ├── 30_regtest_fig7_drill.sh
│   └── dry_run.sh
├── examples/
│   ├── checklist.rs
│   └── simulate_fig7.rs
└── src/
    ├── lib.rs
    ├── main.rs          # vitarit-btc CLI
    ├── checklist.rs     # paper + node capability report
    ├── keys.rs          # client / service / aux / receive keys
    ├── policy.rs        # 2-of-2 P2WSH, P2WPKH, optional CSV refund
    ├── transactions.rs  # tx_stp, tx_aux, tx_pay builders
    ├── ledger.rs        # in-memory UTXO set (pay-at-most-once tests)
    ├── signing.rs       # ECDSA P2WSH 2-of-2 + P2WPKH payment witnesses
    ├── protocol.rs      # Fig 7 session + simulation report
    └── network.rs
```

### Full protocol (crypto + Bitcoin)

```bash
cd ..   # repo root (Cargo workspace)
cargo test -p vitarit-integration
cargo run -p vitarit-integration --example local_testnet_session
# or: ./scripts/run_local_session.sh
```


## Tests

```bash
cargo test                 # unit + integration (no bitcoind)
cargo test ledger::        # pay-at-most-once
cargo test protocol::      # full Fig 7 offline simulation
```

Positive coverage: setup/payment shapes, descriptors, end-to-end simulation.  
Negative coverage: dust violations, double-spend of aux, bad indices/params.

## Benchmarking

```bash
cd bitcoin-testnet

# One-shot table
cargo run --release --example timings

# Criterion
cargo bench --bench tx_bench
```

Measures key generation, setup/payment tx build, ledger apply, and full Fig 7 offline simulation.

## CLI

```bash
cargo run --bin vitarit-btc -- checklist --network testnet
cargo run --bin vitarit-btc -- simulate --network regtest --t 1 --n 3
cargo run --bin vitarit-btc -- playbook --network regtest
```

## Relation to `../code`

| Concern | Where |
|---------|--------|
| PKEnc / VNE / Γ²ᵖᶜ / DVRF | `../code` |
| UTXO graph, scripts, PSBT/raw tx, dust, pay-once | **this folder** |

For a paper-faithful Schnorr adaptor end-to-end, use Taproot for the client
signature path and the adaptor APIs in `../code`; this crate still validates
the required **two-input payment** and **aux uniqueness** on regtest/testnet.
