"""The findings, checked through the real CLI against a Bitcoin Core regtest node.

Each finding has an expected status on this checkout. A fixed finding must be refused; an open one
must still reproduce. The run fails when the code and the table below disagree, so the table cannot
quietly go stale: fixing an open finding, or undoing a fix, both need it updated.

  F1  fixed  --feerate under the 0.1 sat/vB relay floor (-1, 0, 0.05) is refused, and no transaction is printed
  F3  fixed  a negative --amount, --feerate inf, a negative vout and a negative --deposit exit with a message,
             not a traceback
  F4  open   the sweep sees confirmed outputs only: a deposit still in the mempool is left behind and confirms
             at the spent vault (the README says so)
  F5  fixed  with --allow-nonstandard, a transaction over the 4,000,000 WU block weight is refused
  F6  open   the key path has no key-count level, so vaults with different --keys at one deposit share keys,
             as do the test networks, which all use coin type 1' (the README says so)
  F7  fixed  a fee over 0.1 BTC (5,000 and 20,000 sat/vB on a 1 BTC vault) is refused unless --max-fee raises it
  F8  open   the one-time guard compares exact scriptPubKeys: P2SH-P2WSH of the vault's own script, P2WPKH of a
             vault key, and a witness v1 20-byte program are accepted as destinations
  F9  fixed  with --rpc-url, an amount typed in --utxo must equal the node's, and every listed outpoint must be
             a confirmed output at the vault

F2 (change sent to a deposit that was already spent) is not checked: a stateless tool cannot know which
deposits were spent. The README tells users to keep the used indices with the 24 words.

Usage: EBV_RPC_URL=http://u:p@127.0.0.1:18443 python findings_repro.py
"""
import contextlib
import hashlib
import io
import json
import os
import sys
import tempfile

from mnemonic import Mnemonic

from eternax_vault import cli, network
from eternax_vault.encoding import address_to_script_pubkey, b58check_encode, segwit_encode
from eternax_vault.keys import pubkey, vault_secrets
from eternax_vault.rpc import RPC
from eternax_vault.script import chain_script, p2wsh_script_pubkey
from eternax_vault.tx import PLACEHOLDER_SIG, Outpoint, UnlockTx, build_unlock

EXPECTED = {"F1": "fixed", "F3": "fixed", "F4": "open", "F5": "fixed", "F6": "open", "F7": "fixed",
            "F8": "open", "F9": "fixed"}

URL = os.environ["EBV_RPC_URL"]
rpc = RPC(URL)
assert rpc("getblockchaininfo")["chain"] == "regtest"
try:
    rpc("createwallet", "fv-miner")
except RuntimeError:
    try:
        rpc("loadwallet", "fv-miner")
    except RuntimeError:
        pass
miner = rpc.wallet("fv-miner")
MINE = miner("getnewaddress")
if miner("getbalance") < 10:                     # run on its own, on a fresh node
    rpc("generatetoaddress", 110, MINE)
NET = network.get("regtest")
OUT = {}
STATUS = {}


def run(argv):
    """Run the CLI in-process. Returns (stdout, stderr, exit code or message, traceback-worthy crash or None)."""
    o, e = io.StringIO(), io.StringIO()
    code, crash = 0, None
    try:
        with contextlib.redirect_stdout(o), contextlib.redirect_stderr(e):
            cli.main(argv)
    except SystemExit as x:
        code = x.code
    except Exception as x:
        code, crash = 1, f"{type(x).__name__}: {x}"
    return o.getvalue().strip(), e.getvalue().strip(), code, crash


def refused(stdout, code, crash):
    """Refused cleanly: a non-zero exit with a message, no traceback, and nothing signed on stdout."""
    return code not in (0, None) and crash is None and not stdout


def new_seed():
    f = tempfile.NamedTemporaryFile("w", suffix=".seed", delete=False)
    f.write(Mnemonic("english").to_mnemonic(os.urandom(32)))
    f.close()
    return f.name


def address(seed_file, deposit):
    out, _, _, _ = run(["lock", "--seed-file", seed_file, "--network", "regtest", "--deposit", str(deposit)])
    return out.splitlines()[-1]


def fund(addr, btc, mine=True):
    txid = miner("sendtoaddress", addr, btc)
    if mine:
        rpc("generatetoaddress", 1, MINE)
    return txid


def unlock(seed_file, *extra):
    return run(["unlock", "--seed-file", seed_file, "--network", "regtest", "--to", MINE, "--rpc-url", URL, *extra])


def message(stderr, code):
    return (code if isinstance(code, str) else stderr.splitlines()[-1] if stderr else str(code))[:100]


def record(fid, fixed_check, observed):
    """fixed_check: True if the code refuses what the finding describes, False if it still reproduces."""
    OUT[fid] = observed
    STATUS[fid] = "fixed" if fixed_check else "open"
    print(fid, STATUS[fid], json.dumps(observed, indent=1))


# F1 ---------------------------------------------------------------------------------------------
seed = new_seed()
fund(address(seed, 0), 0.01)
f1 = {}
for fr in ("-1", "0", "0.05"):
    raw, err, code, crash = unlock(seed, "--feerate", fr)
    f1[fr] = {"refused": refused(raw, code, crash), "message": message(err, code), "crash": crash}
record("F1", all(v["refused"] for v in f1.values()), f1)

# F3 ---------------------------------------------------------------------------------------------
seed = new_seed()
fund(address(seed, 0), 0.01)
real = rpc("scantxoutset", "start", [f"addr({address(seed, 0)})"])["unspents"][0]
f3 = {}
for label, args in {"--amount -5": ["--feerate", "2", "--amount", "-5", "--change-deposit", "1"],
                    "--feerate inf": ["--feerate", "inf"],
                    "--utxo with vout -1": ["--feerate", "2", "--utxo", f"{real['txid']}:-1:1000000"],
                    "--deposit -1": ["--feerate", "2", "--deposit", "-1"]}.items():
    raw, err, code, crash = unlock(seed, *args)
    f3[label] = {"refused": refused(raw, code, crash), "message": message(err, code), "crash": crash}
record("F3", all(v["refused"] for v in f3.values()), f3)

# F4 ---------------------------------------------------------------------------------------------
seed = new_seed()
a0 = address(seed, 0)
fund(a0, 0.01)                                   # confirmed
late = fund(a0, 0.02, mine=False)                # still in the mempool
raw4, err4, c4, crash4 = unlock(seed, "--feerate", "2", "--broadcast")
rpc("generatetoaddress", 1, MINE)
left = rpc("scantxoutset", "start", [f"addr({a0})"])["unspents"]
f4 = {"unlock_exit": c4 if not crash4 else crash4, "late_deposit_txid": late,
      "left_at_spent_vault_sats": sum(round(u["amount"] * 1e8) for u in left), "outputs_left": len(left)}
record("F4", not left, f4)

# F5 ---------------------------------------------------------------------------------------------
secrets = vault_secrets(os.urandom(64), NET, 201, 0)
dest = bytes([0, 20]) + bytes(20)
ws = chain_script([pubkey(s) for s in secrets])


def placeholder_weight(k):
    return UnlockTx([Outpoint("00" * 32, i, 0) for i in range(k)], [(0, dest)], [[PLACEHOLDER_SIG] * 201 + [ws]] * k).weight


k = 1
while placeholder_weight(k + 1) <= 4_000_000:
    k += 1
largest = build_unlock(secrets, [Outpoint(f"{i:064x}", 0, 10 ** 6) for i in range(k)], dest, 1.0, standard=False)
try:
    build_unlock(secrets, [Outpoint(f"{i:064x}", 0, 10 ** 6) for i in range(k + 1)], dest, 1.0, standard=False)
    over = {"inputs": k + 1, "refused": False}
except ValueError as e:
    over = {"inputs": k + 1, "refused": True, "message": str(e)[:100]}
f5 = {"keys": 201, "largest_built": {"inputs": k, "weight": largest.weight}, "one_more": over}
record("F5", largest.weight <= 4_000_000 and over["refused"], f5)

# F6 ---------------------------------------------------------------------------------------------
seed_bytes = os.urandom(64)
k50, k100 = vault_secrets(seed_bytes, NET, 50, 0), vault_secrets(seed_bytes, NET, 100, 0)
f6 = {"keys50_equal_first50_of_keys100": k50 == k100[:50],
      "regtest_keys_equal_signet_keys": vault_secrets(seed_bytes, NET, 3, 0)
      == vault_secrets(seed_bytes, network.get("signet"), 3, 0)}
record("F6", not any(f6.values()), f6)

# F7 ---------------------------------------------------------------------------------------------
seed = new_seed()
fund(address(seed, 0), 1.0)
f7 = {}
for fr in ("5000", "20000"):
    raw, err, code, crash = unlock(seed, "--feerate", fr)
    f7[f"{fr} sat/vB"] = {"refused": refused(raw, code, crash), "message": message(err, code)}
raw7, err7, c7, _ = unlock(seed, "--feerate", "5000", "--max-fee", str(10 ** 8))
v7 = rpc("testmempoolaccept", [raw7])[0] if raw7 else {}
f7["5000 sat/vB with --max-fee 1 BTC"] = {"signed": bool(raw7), "core_allowed": v7.get("allowed"),
                                          "fee_sats": round(v7["fees"]["base"] * 1e8) if v7.get("fees") else None}
record("F7", f7["5000 sat/vB"]["refused"] and f7["20000 sat/vB"]["refused"] and bool(v7.get("allowed")), f7)

# F8 ---------------------------------------------------------------------------------------------
secrets = vault_secrets(os.urandom(64), NET, 100, 0)
ws = chain_script([pubkey(s) for s in secrets])
h160 = lambda b: hashlib.new("ripemd160", hashlib.sha256(b).digest()).digest()
dests = {"P2SH-P2WSH of the vault's own script": b58check_encode(bytes([NET.p2sh]) + h160(p2wsh_script_pubkey(ws))),
         "P2WPKH of one of the vault's keys": segwit_encode(NET.hrp, 0, h160(pubkey(secrets[0]))),
         "witness v1 with a 20-byte program (anyone can spend)": segwit_encode(NET.hrp, 1, bytes(20))}
f8 = {}
for label, addr in dests.items():
    try:
        build_unlock(secrets, [Outpoint("ab" * 32, 0, 10 ** 6)], address_to_script_pubkey(addr, NET), 2.0)
        f8[label] = {"address": addr, "tool": "accepted", "core_validateaddress": rpc("validateaddress", addr)["isvalid"]}
    except ValueError as e:
        f8[label] = {"address": addr, "tool": f"refused: {e}"}
record("F8", all(v["tool"] != "accepted" for v in f8.values()), f8)

# F9 ---------------------------------------------------------------------------------------------
seed = new_seed()
a = address(seed, 0)
fund(a, 0.01)
real = rpc("scantxoutset", "start", [f"addr({a})"])["unspents"][0]
real_sats = round(real["amount"] * 1e8)
f9 = {}
for label, utxos in {"amount 1,000 sat above the node's": [f"{real['txid']}:{real['vout']}:{real_sats + 1000}"],
                     "an outpoint the node does not show": [f"{real['txid']}:{real['vout']}", f"{'ee' * 32}:0:500000"]}.items():
    raw, err, code, crash = unlock(seed, "--feerate", "2", *[x for u in utxos for x in ("--utxo", u)])
    f9[label] = {"refused": refused(raw, code, crash), "message": message(err, code)}
record("F9", all(v["refused"] for v in f9.values()), f9)

# ------------------------------------------------------------------------------------------------
with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "results", "findings_repro.json"), "w") as f:
    json.dump({"expected": EXPECTED, "observed_status": STATUS, "details": OUT}, f, indent=1)
drift = [fid for fid in EXPECTED if STATUS.get(fid) != EXPECTED[fid]]
for fid in EXPECTED:
    print(f"{fid}  expected {EXPECTED[fid]:5s}  observed {STATUS.get(fid, 'missing'):5s}  {'OK' if fid not in drift else 'MISMATCH'}")
print("ALL FINDINGS AS EXPECTED" if not drift else f"STATUS CHANGED: {drift}; update EXPECTED and the report")
sys.exit(1 if drift else 0)
