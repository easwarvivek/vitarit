#!/usr/bin/env bash
# Check local prerequisites for Vitārit Bitcoin realization.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
NET="${1:-regtest}"

echo "== Vitārit Bitcoin prerequisites =="
echo "network hint: $NET"
echo

have() { command -v "$1" >/dev/null 2>&1; }

ok=0
warn=0
fail=0

check() {
  local status="$1"; shift
  local msg="$*"
  case "$status" in
    PASS) echo "[PASS] $msg"; ok=$((ok+1));;
    WARN) echo "[WARN] $msg"; warn=$((warn+1));;
    FAIL) echo "[FAIL] $msg"; fail=$((fail+1));;
    INFO) echo "[INFO] $msg";;
  esac
}

if have rustc && have cargo; then
  check PASS "Rust toolchain available ($(rustc --version | head -1))"
else
  check FAIL "Rust/cargo required to build vitarit-bitcoin"
fi

if have bitcoin-cli; then
  check PASS "bitcoin-cli found at $(command -v bitcoin-cli)"
else
  check WARN "bitcoin-cli not found — offline Rust tests still work; live regtest/testnet disabled"
fi

if have bitcoind; then
  check PASS "bitcoind found"
else
  check WARN "bitcoind not found — install Bitcoin Core for live tests"
fi

FLAG="-regtest"
case "$NET" in
  testnet) FLAG="-testnet";;
  signet) FLAG="-signet";;
  regtest) FLAG="-regtest";;
esac

if have bitcoin-cli; then
  if bitcoin-cli "$FLAG" getblockchaininfo >/dev/null 2>&1; then
    CHAIN=$(bitcoin-cli "$FLAG" getblockchaininfo | sed -n 's/.*"chain": "\([^"]*\)".*/\1/p' | head -1)
    check PASS "bitcoin-cli $FLAG responding (chain=$CHAIN)"
  else
    check WARN "bitcoin-cli $FLAG not responding (start bitcoind or skip live tests)"
  fi
fi

check INFO "Paper needs: UTXO, 2-of-2 deposit, aux single-sig, 2-input payment, Schnorr adaptor (Taproot) for full Fig 8"
check INFO "Run: cd $ROOT && cargo test && cargo run --example checklist"

echo
echo "summary: pass=$ok warn=$warn fail=$fail"
if [[ "$fail" -gt 0 ]]; then exit 1; fi
exit 0
