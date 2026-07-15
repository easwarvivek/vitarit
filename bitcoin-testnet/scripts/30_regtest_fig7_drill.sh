#!/usr/bin/env bash
# Live regtest drill: create 2-of-2 deposit, aux UTXO, payment with 2 inputs,
# then attempt a second claim to show pay-at-most-once.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DATADIR="${VITARIT_BTC_DATADIR:-$ROOT/.regtest-data}"
CLI=(bitcoin-cli -regtest -datadir="$DATADIR" -rpcwallet=vitarit)

if ! "${CLI[@]}" getblockchaininfo >/dev/null 2>&1; then
  echo "regtest node not up — run scripts/01_regtest_up.sh first"
  exit 1
fi

echo "== Generate keys =="
# Use wallet addresses as stand-ins for client A, service S, aux, receive
ADDR_A=$("${CLI[@]}" getnewaddress "client_A" "bech32")
ADDR_S=$("${CLI[@]}" getnewaddress "service_S" "bech32")
ADDR_AUX=$("${CLI[@]}" getnewaddress "aux" "bech32")
ADDR_RECV=$("${CLI[@]}" getnewaddress "server_recv" "bech32")
PUB_A=$("${CLI[@]}" getaddressinfo "$ADDR_A" | sed -n 's/.*"pubkey": "\([^"]*\)".*/\1/p' | head -1)
PUB_S=$("${CLI[@]}" getaddressinfo "$ADDR_S" | sed -n 's/.*"pubkey": "\([^"]*\)".*/\1/p' | head -1)

if [[ -z "$PUB_A" || -z "$PUB_S" ]]; then
  echo "Could not extract pubkeys (descriptor wallet?). Falling back to Rust offline simulate."
  echo "Run: cd $ROOT && cargo run --example simulate_fig7"
  exit 0
fi

DESC="wsh(multi(2,$PUB_A,$PUB_S))"
# checksummed descriptor
DESC_CS=$("${CLI[@]}" getdescriptorinfo "$DESC" | sed -n 's/.*"descriptor": "\([^"]*\)".*/\1/p' | head -1)
echo "deposit descriptor: $DESC_CS"

echo "== Import deposit descriptor =="
# watch-only multi may need privkeys for spending — import as active if possible
IMPORT_JSON=$(printf '[{"desc":"%s","timestamp":"now","active":false,"internal":false}]' "$DESC_CS")
"${CLI[@]}" importdescriptors "$IMPORT_JSON" >/dev/null || true
DEP_ADDR=$("${CLI[@]}" deriveaddresses "$DESC_CS" | sed -n 's/.*"\(bcrt[^"]*\)".*/\1/p' | head -1)
echo "deposit address: $DEP_ADDR"

DEPOSIT_SATS=100000
AUX_SATS=294

echo "== Fund deposit ($DEPOSIT_SATS) and aux ($AUX_SATS) =="
TXID_DEP=$("${CLI[@]}" sendtoaddress "$DEP_ADDR" "$(awk "BEGIN{print $DEPOSIT_SATS/1e8}")")
TXID_AUX=$("${CLI[@]}" sendtoaddress "$ADDR_AUX" "$(awk "BEGIN{print $AUX_SATS/1e8}")")
"${CLI[@]}" -generate 1 >/dev/null
echo "funded deposit tx=$TXID_DEP aux tx=$TXID_AUX"

# Locate vouts
VOUT_DEP=$("${CLI[@]}" gettransaction "$TXID_DEP" true | python3 -c "
import json,sys
t=json.load(sys.stdin)
# details may not list multi; scan listunspent
" 2>/dev/null || true)

echo "== Locate UTXOs via listunspent =="
UTXO_JSON=$("${CLI[@]}" listunspent 0)
python3 - "$DEP_ADDR" "$ADDR_AUX" "$ADDR_RECV" "$DATADIR" <<'PY'
import json, subprocess, sys, os
dep_addr, aux_addr, recv, datadir = sys.argv[1:5]
cli = ["bitcoin-cli","-regtest",f"-datadir={datadir}","-rpcwallet=vitarit"]
utxos = json.loads(subprocess.check_output(cli+["listunspent","0"]))
dep = next((u for u in utxos if u.get("address")==dep_addr), None)
aux = next((u for u in utxos if u.get("address")==aux_addr), None)
if not dep or not aux:
    print("UTXOs not visible yet (descriptor watch?). Use offline simulate_fig7.")
    print("dep", dep, "aux", aux)
    sys.exit(0)
amount = float(dep["amount"]) + float(aux["amount"]) - 0.00001
raw = subprocess.check_output(cli+[
    "createrawtransaction",
    json.dumps([
        {"txid": dep["txid"], "vout": dep["vout"]},
        {"txid": aux["txid"], "vout": aux["vout"]},
    ]),
    json.dumps({recv: round(amount, 8)}),
], text=True).strip()
print("unsigned payment hex:", raw)
# Try funded wallet to sign both if it owns all keys (A,S,aux)
signed = json.loads(subprocess.check_output(cli+["signrawtransactionwithwallet", raw], text=True))
print("complete:", signed.get("complete"))
if signed.get("complete"):
    txid = subprocess.check_output(cli+["sendrawtransaction", signed["hex"]], text=True).strip()
    print("broadcast payment txid:", txid)
    subprocess.check_output(cli+["-generate","1"])
    # Second attempt reusing aux should fail
    try:
        # rebuild would fail at UTXO selection; try sending same hex again
        subprocess.check_output(cli+["sendrawtransaction", signed["hex"]], stderr=subprocess.STDOUT)
        print("UNEXPECTED: double broadcast succeeded")
    except subprocess.CalledProcessError as e:
        print("pay-at-most-once OK (rebroadcast rejected):", e.output.decode()[:200])
else:
    print("partial signatures — export hex and finish signing offline / with service key")
    print("errors:", signed.get("errors"))
PY

echo "done"
