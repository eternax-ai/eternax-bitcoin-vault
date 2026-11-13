#!/usr/bin/env bash
# Re-runs the whole verification of eternax-bitcoin-vault @ ccb2603a.
# Needs: Python 3.10-3.12, the vault checked out at ../vault, and a Bitcoin Core v31.1 regtest node
#   bitcoind -regtest -daemon -fallbackfee=0.0001 -rpcuser=u -rpcpassword=p -txindex=1
# Every step exits non-zero on failure.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
VAULT="${VAULT:-$HERE/../vault}"
PY="${PY:-python3}"
export EBV_RPC_URL="${EBV_RPC_URL:-http://u:p@127.0.0.1:18443}"

git -C "$VAULT" rev-parse HEAD | grep -q '^ccb2603a548606d29be7b8f43140d516007a692b$' || { echo "vault is not at ccb2603a"; exit 1; }
mkdir -p "$HERE/results"
cd "$HERE"
echo "== repo's own tests (offline + regtest)";  (cd "$VAULT" && "$PY" -m pytest -q tests/)
echo "== P1 script soundness (Z3)";              "$PY" p1_spend_soundness.py
echo "== P2/P5 transaction proofs";              "$PY" p2_p5_tx_proofs.py
echo "== P3/P4/P6 checks";                       "$PY" p3_p4_p6_checks.py
echo "== Bitcoin Core differential";             "$PY" core_differential.py
echo "== Findings reproduction";                 "$PY" findings_repro.py
echo "== Mutation testing of this suite";        "$PY" mutation_test.py "$VAULT"
echo "ALL VERIFICATION STEPS PASSED"
