#!/usr/bin/env bash
# Start a disposable bitcoind regtest instance for Vitārit drills.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DATADIR="${VITARIT_BTC_DATADIR:-$ROOT/.regtest-data}"
mkdir -p "$DATADIR"

if ! command -v bitcoind >/dev/null; then
  echo "bitcoind not installed. On macOS: brew install bitcoin"
  exit 1
fi

if bitcoin-cli -regtest -datadir="$DATADIR" getblockchaininfo >/dev/null 2>&1; then
  echo "regtest already running (datadir=$DATADIR)"
  exit 0
fi

echo "Starting bitcoind -regtest (datadir=$DATADIR)"
bitcoind -regtest -datadir="$DATADIR" -daemon \
  -fallbackfee=0.0002 \
  -acceptnonstdtxn=1 \
  -txindex=1

for i in $(seq 1 30); do
  if bitcoin-cli -regtest -datadir="$DATADIR" getblockchaininfo >/dev/null 2>&1; then
    echo "regtest ready"
    bitcoin-cli -regtest -datadir="$DATADIR" createwallet "vitarit" >/dev/null 2>&1 || true
    # Mine mature coinbase
    ADDR=$(bitcoin-cli -regtest -datadir="$DATADIR" -rpcwallet=vitarit getnewaddress)
    bitcoin-cli -regtest -datadir="$DATADIR" -rpcwallet=vitarit generatetoaddress 101 "$ADDR" >/dev/null
    echo "funded wallet 'vitarit' with 101 blocks → $ADDR"
    exit 0
  fi
  sleep 0.5
done
echo "timeout waiting for bitcoind"
exit 1
