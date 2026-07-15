#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DATADIR="${VITARIT_BTC_DATADIR:-$ROOT/.regtest-data}"
bitcoin-cli -regtest -datadir="$DATADIR" stop >/dev/null 2>&1 || true
echo "stopped regtest (datadir=$DATADIR)"
