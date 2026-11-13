#!/usr/bin/env bash
# Re-runs the whole verification of eternax-bitcoin-vault on the checkout this folder sits in.
# Needs Python 3.10-3.12 with requirements.lock installed, and a Bitcoin Core regtest node
# (v31.1 is the reference); README.md has the commands. Set EBV_RPC_URL if the node is not at the default.
# Every step exits non-zero on failure. The output is also written to results/run_all.log.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
VAULT="${VAULT:-$(cd "$HERE/.." && pwd)}"
PY="${PY:-python3}"
export EBV_RPC_URL="${EBV_RPC_URL:-http://u:p@127.0.0.1:18443}"
export PYTHONPATH="$VAULT${PYTHONPATH:+:$PYTHONPATH}"     # test this checkout, not an installed copy

mkdir -p "$HERE/results"
exec > >(tee "$HERE/results/run_all.log") 2>&1
trap 'echo "exit=$?"' EXIT
cd "$HERE"

changed="$(git -C "$VAULT" status --porcelain -- eternax_vault tests verification ':!verification/results' | wc -l | tr -d ' ')"
echo "== commit $(git -C "$VAULT" rev-parse HEAD)$([ "$changed" = 0 ] || echo " plus $changed uncommitted change(s)")"
"$PY" - <<'EOF'
import os, sys, hypothesis, z3
from eternax_vault.rpc import RPC
rpc = RPC(os.environ["EBV_RPC_URL"])
print(f"== Python {sys.version.split()[0]}, Z3 {z3.get_version_string()}, Hypothesis {hypothesis.__version__}")
print(f"== Bitcoin Core {rpc('getnetworkinfo')['subversion']} on {rpc('getblockchaininfo')['chain']}")
EOF

echo "== repo's own tests (offline + regtest)";  (cd "$VAULT" && "$PY" -m pytest -q tests/)
echo "== P1 script soundness (Z3)";              "$PY" p1_spend_soundness.py
echo "== P2/P5 transaction proofs";              "$PY" p2_p5_tx_proofs.py
echo "== P3/P4/P6 checks";                       "$PY" p3_p4_p6_checks.py
echo "== Bitcoin Core differential";             "$PY" core_differential.py
echo "== Findings status";                       "$PY" findings_repro.py
echo "== Mutation testing of this suite";        "$PY" mutation_test.py "$VAULT"
echo "ALL VERIFICATION STEPS PASSED"
