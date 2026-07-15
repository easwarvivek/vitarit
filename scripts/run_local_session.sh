#!/usr/bin/env bash
# Full local Vitārit session (wire + simulated Bitcoin regtest ledger).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
cargo test -p vitarit --lib wire -q
cargo test -p vitarit-bitcoin signing -q
cargo test -p vitarit-integration -q
cargo run -p vitarit-integration --example local_testnet_session
