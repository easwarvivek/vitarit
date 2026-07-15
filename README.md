# Vitārit (Rust)

Rust realization of **Vitārit: Paying for Threshold Services on Bitcoin and Friends**
([ePrint 2025/174](https://eprint.iacr.org/2025/174))

A client pays `t+1` out of `n` threshold-VRF servers exactly once, using adaptor
signatures and verifiable non-committing encryption (VNE) over an abstract UTXO ledger.

## Requirements

- Rust toolchain (edition 2021; tested with rustc 1.96+)

## Build

```bash
cd code
cargo build
```

## Run tests

All unit tests (currently 82) live in `#[cfg(test)]` modules next to the code they cover.

```bash
cd code

# Full suite
cargo test

# Quiet summary
cargo test -q

# Single module
cargo test pkenc::
cargo test vne::
cargo test vitarit::

# Single test by name
cargo test vne_fig9_roundtrip
cargo test adaptor_flow -- --nocapture
```

## Run the end-to-end demo

```bash
cd code
cargo run --example run_protocol
```

The demo runs Figure 7 with `t=1`, `n=3`, and a reduced cut-and-choose parameter
(`λ_s = 8`) for speed. For the paper parameter use `λ_s = 32` (`2λ_s = 64`) via
`Params.lambda_s` in `src/vitarit.rs` / the example.

## APIs

```text
PKEnc.KGen(1λ) → (ek, dk)
PKEnc.Enc(ek, m) → c = (c1, c2, c3)
PKEnc.Dec(dk, c) → m

VNE.KGen(1λ) → (ek, dk)
VNE.Enc(ek, inst, wit, z) → ct
VNE.VfEnc(ek, inst, ct) → 0/1
VNE.Dec(dk, inst, ct) → wit
```

Groups (§7):

| Group | Curve / crate | Used for |
|-------|---------------|----------|
| **Gp** | Ristretto (`curve25519-dalek`) | PKEnc, Schnorr DS, adaptor signatures |
| **Gq** | BLS12-381 G1/G2 (`bls12_381`) | Threshold BLS VRF witness, `Aj`, `Bj`, `Zj` |

## Repository layout

```text
code/
├── Cargo.toml
├── README.md
├── examples/
│   ├── run_protocol.rs      # end-to-end Figure 7 demo
│   └── timings.rs           # one-shot per-step timing table
├── benches/
│   ├── protocol_bench.rs    # Criterion micro-benchmarks
│   └── lambda_s_sweep.rs    # VNE cost vs λ_s
└── src/
    ├── lib.rs               # crate root; re-exports PkEnc, Vne, VitaritProtocol
    ├── error.rs             # shared Error / Result
    ├── hash.rs              # Hm, Hc, XOR helpers
    ├── group/
    │   ├── mod.rs
    │   ├── ristretto.rs     # Gp helpers
    │   └── bls.rs           # Gq helpers, pairing, Lagrange
    ├── pkenc.rs             # Figure 5 — PKEnc
    ├── schnorr.rs           # DS — Schnorr over Gp
    ├── adaptor.rs           # AS — adaptor signatures w.r.t. R_DL
    ├── dvrf.rs              # DVTS as threshold BLS VRF (§7.1)
    ├── nizk.rs              # Fiat–Shamir Schnorr for language L′
    ├── vne.rs               # Figure 9 — concrete cut-and-choose VNE
    ├── tx.rs                # abstract UTXO ledger + payment txs
    ├── gamma2pc.rs          # Figure 8 — Γ²ᵖᶜ exchange
    └── vitarit.rs           # Figure 7 — full protocol
```

## What each file does

| File | Role |
|------|------|
| `src/lib.rs` | Crate entry point; module list and public re-exports. |
| `src/error.rs` | `Error` variants (verification, decryption, ledger, …) and `Result<T>`. |
| `src/hash.rs` | Domain-separated hashes: `Hm` (Fig. 5 mask), `Hc` (cut-and-choose challenge set), XOR. |
| `src/group/ristretto.rs` | Gp: generator, random/hash-to-scalar, point/scalar encoding. |
| `src/group/bls.rs` | Gq: G1/G2 encoding, `Hq`-style hash-to-G1, pairing equality, Lagrange at 0. |
| `src/pkenc.rs` | **Figure 5** hashed ElGamal: `KGen`, `Enc`, `Dec`, deterministic re-encrypt check for opened slots. |
| `src/schnorr.rs` | Digital signatures DS = `(KGen, Sign, Vf)` on Gp (used on ledger transactions). |
| `src/adaptor.rs` | Adaptor signatures AS = `(pSign, pVf, Adapt, Ext)` bound to statement `Y = gp^y` (the VNE encryption key). |
| `src/dvrf.rs` | DVTS interface: `DKgen`, `PartEval`, `PartVerify`, `Combine`, `Verify` via Shamir-shared BLS keys + DLEQ proofs. |
| `src/nizk.rs` | NIZK for L′: proves `B = g^b` and `Z = A^b · H(m)^{sk}` with matching `vk_i`. |
| `src/vne.rs` | **Figure 9** VNE: cut-and-choose over `2λ_s` PKEnc ciphertexts; opened openings + unopened `(Z_j, π_j)`. |
| `src/tx.rs` | UTXO model: addresses, setup/payment transactions, in-memory ledger enforcing pay-at-most-once via auxiliary outputs. |
| `src/gamma2pc.rs` | **Figure 8** two-party sub-protocol: server VNE-encrypts partial VRF; client pre-signs; server adapts & posts; client extracts `dk` and decrypts. |
| `src/vitarit.rs` | **Figure 7**: setup deposits, per-server Γ²ᵖᶜ payments, reconstruction of the final VRF. |
| `examples/run_protocol.rs` | Small driver that calls `VitaritProtocol::run` and prints success. |

## Suggested reading order

1. `pkenc.rs` → `vne.rs` (crypto core of Figs. 5 & 9)
2. `dvrf.rs` → `adaptor.rs` / `schnorr.rs` (service + payment primitives)
3. `gamma2pc.rs` → `vitarit.rs` (protocol assembly, Figs. 8 & 7)
4. `tx.rs` (ledger / pay-at-most-once)

## Parameters

| Parameter | Paper | Default in tests / demo |
|-----------|-------|-------------------------|
| `λ_s` (cut-and-choose) | 32 (`2λ_s = 64`) | 2–8 (fast) |
| `t`, `n` | threshold / servers | e.g. `t=1, n=3` |
| Deposit value `x`, aux `ε` | application-defined | see `Params` in `vitarit.rs` |

`DEFAULT_LAMBDA_S` in `vne.rs` is 32. Protocol tests/demos override it downward; set `Params.lambda_s = 32` for paper-scale cut-and-choose.

## Benchmarking

### One-shot table (fast)

Mean wall-clock per step (Table 1 style). Always use `--release`:

```bash
cd code
cargo run --release --example timings
cargo run --release --example timings -- --lambda-s 32 --iters 50
```

### Criterion (statistical)

```bash
cd code

# PKEnc, DVRF, Schnorr/Adaptor, NIZK L′, VNE, Γ²ᵖᶜ, full Fig 7
cargo bench --bench protocol_bench

# VNE / VfEnc / Dec vs λ_s (paper Figure 10)
cargo bench --bench lambda_s_sweep
```

HTML reports under `target/criterion/report/index.html`.

From the repo root you can also run:

```bash
./scripts/run_benchmarks.sh
```
