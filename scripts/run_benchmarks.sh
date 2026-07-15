#!/usr/bin/env bash
# Run crypto + bitcoin timing suites.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

echo "== code: timings example =="
(cd "$ROOT/code" && cargo run --release --quiet --example timings -- --lambda-s 8 --iters 20)

echo
echo "== bitcoin-testnet: timings example =="
(cd "$ROOT/bitcoin-testnet" && cargo run --release --quiet --example timings)

echo
echo "For Criterion HTML reports:"
echo "  (cd code && cargo bench --bench protocol_bench)"
echo "  (cd code && cargo bench --bench lambda_s_sweep)"
echo "  (cd bitcoin-testnet && cargo bench --bench tx_bench)"
