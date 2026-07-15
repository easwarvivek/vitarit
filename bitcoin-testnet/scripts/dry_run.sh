#!/usr/bin/env bash
# Offline path: no bitcoind required.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
echo "== cargo test =="
cargo test
echo
echo "== checklist =="
cargo run --quiet --example checklist
echo
echo "== simulate Fig 7 =="
cargo run --quiet --example simulate_fig7
echo
echo "Offline Bitcoin-layer verification complete."
