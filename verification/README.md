# Verification suite

These scripts check six properties of the vault (P1–P6) and the status of each known finding, on the
checkout they sit in. One command runs everything and exits non-zero on any failure.

| Script | Checks |
| --- | --- |
| `p1_spend_soundness.py` | P1, only all n signatures spend the vault: Z3 proof over a model of segwit v0 script execution for n = 1..201, the real script bytes against the model, and negative controls |
| `p2_p5_tx_proofs.py` | P2, every unlock the tool builds is valid and standard and pays at least the requested rate; P5, signatures commit to the transaction and value is conserved. Z3 proofs of the weight, fee and value arithmetic, property-based tests tying `build_unlock` to that model, and an independent BIP-143 implementation |
| `p3_p4_p6_checks.py` | P3, the address and descriptor commit to exactly the script; P4, seed to keys to address is deterministic; P6, an unlock never pays the vault it spends. Independent miniscript and BIP-32 implementations, and Bitcoin Core's own derivation |
| `core_differential.py` | P1–P5 judged by Bitcoin Core: witness mutations rejected at consensus and policy, unlocks accepted and mined, descriptors and addresses matching, Core's wallet spending a vault from its descriptor |
| `findings_repro.py` | Each finding against its expected status: fixed findings must be refused, open ones must still reproduce |
| `mutation_test.py` | Plants 16 bugs, one at a time, in copies of the code; the offline suites must fail on every one |
| `run_all.sh` | All of the above plus the repository's own tests |
| `verify_sigs.py` | Optional: checks the builder signatures on Bitcoin Core's `SHA256SUMS` |

## Findings are tracked by status

`findings_repro.py` fails when a finding's observed status differs from its entry in `EXPECTED`, so
fixing an open finding or undoing a fix both show up as a failed run.

| ID | Status | Finding |
| --- | --- | --- |
| F1 | fixed | A fee rate under the 0.1 sat/vB relay floor was signed |
| F3 | fixed | Some bad arguments crashed with a traceback instead of a message |
| F4 | open, documented | The sweep sees confirmed outputs only; a deposit still in the mempool is left behind |
| F5 | fixed | Non-standard unlocks had no cap at the 4,000,000 WU block weight |
| F6 | open, documented | Vaults with different `--keys` at one deposit share keys, as do the test networks |
| F7 | fixed | There was no fee ceiling |
| F8 | open | The one-time guard compares exact scriptPubKeys only |
| F9 | fixed | Amounts typed in `--utxo` overrode the node's |

F2, change sent to a deposit that was already spent, is not checked: a stateless tool cannot know
which deposits were spent, and the main README tells users to keep the used indices with the 24 words.

## Running it

Python 3.10–3.12 and Bitcoin Core on regtest; v31.1 is the reference node. From the repository root:

```bash
python3 -m venv .venv
.venv/bin/pip install --require-hashes -r verification/requirements.lock
```

`requirements.lock` pins the vault's own dependencies, at the same hashes as the top-level
`requirements.lock`, plus the tools: Z3, Hypothesis, `ecdsa`, pytest and PGPy.

Start a throwaway regtest node. The login is a local test credential, not a secret:

```bash
mkdir -p /tmp/ebv-regtest
bitcoind -regtest -daemon -datadir=/tmp/ebv-regtest -fallbackfee=0.0001 -rpcuser=u -rpcpassword=p -txindex=1
```

Then run everything:

```bash
PY=.venv/bin/python ./verification/run_all.sh
```

The scripts test the `eternax_vault` package in this checkout, not an installed copy. If the node is
elsewhere, set `EBV_RPC_URL`, for example `http://u:p@127.0.0.1:18443`. Mutation testing takes most of
the time, since it re-runs the offline suites once per planted bug.

## Results record the last full run

`results/run_all.log` starts with the commit, the toolchain and the node version, and ends with
`ALL VERIFICATION STEPS PASSED` and `exit=0`. `results/core_differential.json` and
`results/findings_repro.json` hold the raw verdicts. `run_all.sh` overwrites all three.

## Checking the reference node

bitcoincore.org's download page explains how to check a release with `gpg`. `verify_sigs.py` does the
same check with PGPy, for a folder holding `SHA256SUMS`, `SHA256SUMS.asc` and the builder keys from
[bitcoin-core/guix.sigs](https://github.com/bitcoin-core/guix.sigs/tree/main/builder-keys) in `keys/`:

```bash
.venv/bin/python verification/verify_sigs.py path/to/folder
```
