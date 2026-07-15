# Vitārit integration — crypto + Bitcoin locally

Wires the protocol crate (`../code`) and Bitcoin layer (`../bitcoin-testnet`)
into one end-to-end local session:

1. DVTS keygen + VNE encrypt (server)
2. Framed wire messages (`VIT1` codec in `vitarit::wire`)
3. Client adaptor pre-sign bound to the unsigned Bitcoin payment template
4. Server adapts (Ristretto) + ECDSA-signs P2WSH 2-of-2 + P2WPKH payment
5. Client extracts `dk` and decrypts the partial VRF eval
6. Payment applied on a simulated regtest UTXO ledger

## Architecture

| Channel | Primitive |
|---------|-----------|
| Off-chain fairness | Ristretto adaptor + VNE (paper Fig 8–9) |
| On-chain witnesses | ECDSA SegWit-v0 (P2WSH / P2WPKH) |

On-chain Schnorr adaptor signatures require Taproot/BIP340; this crate uses ECDSA
for SegWit-v0 payments while keeping the paper’s adaptor/VNE exchange off-chain.

## Run (no bitcoind)

From the repo root:

```bash
cargo test -p vitarit-integration
cargo run -p vitarit-integration --example local_testnet_session
```

## Live regtest

Install Bitcoin Core, then:

```bash
cd ../bitcoin-testnet && ./scripts/01_regtest_up.sh && ./scripts/30_regtest_fig7_drill.sh
```

The integration example uses `SimulatedLedger` so it always works offline; broadcast
the printed `payment_tx_hex` with `bitcoin-cli sendrawtransaction` once a funded
regtest wallet holds matching deposit/aux UTXOs.
