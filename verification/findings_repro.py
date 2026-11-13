"""Reproductions of the findings, through the real CLI against Bitcoin Core v31.1 regtest.

  F1  --feerate <= 0 (or below the 0.1 sat/vB relay floor) is accepted; the tool prints a signed unlock
      that every node rejects. With --broadcast the node check stops it before sending.
  F2  --change-deposit may name a deposit whose vault was already spent (keys public); the tool sends
      the change there, warning only.
  F3  a negative --amount crashes with OverflowError before signing (no transaction is produced).
  F4  the sweep sees confirmed outputs only: a deposit still in the mempool when the unlock is built
      is left behind, and confirms at an address whose 100 public keys are now public.
  F5  with --allow-nonstandard there is no cap at the consensus transaction weight (4,000,000 WU).
"""
import contextlib
import io
import json
import os
import sys
import tempfile

from mnemonic import Mnemonic

from eternax_vault import cli, network
from eternax_vault.encoding import p2wsh_address
from eternax_vault.keys import pubkey, seed_from_mnemonic, vault_secrets
from eternax_vault.rpc import RPC
from eternax_vault.script import chain_script
from eternax_vault.tx import Outpoint, build_unlock

URL = os.environ["EBV_RPC_URL"]
rpc = RPC(URL)
assert rpc("getblockchaininfo")["chain"] == "regtest"
miner = rpc.wallet("fv-miner")
MINE = miner("getnewaddress")
NET = network.get("regtest")
OUT = {}


def run(argv):
    o, e = io.StringIO(), io.StringIO()
    code = 0
    try:
        with contextlib.redirect_stdout(o), contextlib.redirect_stderr(e):
            cli.main(argv)
    except SystemExit as x:
        code = x.code
    except Exception as x:
        code = f"{type(x).__name__}: {x}"
    return o.getvalue().strip(), e.getvalue().strip(), code


def new_seed():
    f = tempfile.NamedTemporaryFile("w", suffix=".seed", delete=False)
    f.write(Mnemonic("english").to_mnemonic(os.urandom(32)))
    f.close()
    return f.name


def address(seed_file, deposit):
    out, _, _ = run(["lock", "--seed-file", seed_file, "--network", "regtest", "--deposit", str(deposit)])
    return out.splitlines()[-1]


def fund(addr, btc, mine=True):
    txid = miner("sendtoaddress", addr, btc)
    if mine:
        rpc("generatetoaddress", 1, MINE)
    return txid


def unlock(seed_file, *extra):
    return run(["unlock", "--seed-file", seed_file, "--network", "regtest", "--to", MINE, "--rpc-url", URL, *extra])


# F1 ---------------------------------------------------------------------------------------------
seed = new_seed()
a0 = address(seed, 0)
fund(a0, 0.01)
f1 = {}
for fr in ("-1", "0", "0.05"):
    raw, err, code = unlock(seed, "--feerate", fr)
    verdict = rpc("testmempoolaccept", [raw])[0] if raw else None
    _, err_b, code_b = unlock(seed, "--feerate", fr, "--broadcast")
    f1[fr] = {"tool_exit": code, "signed_tx_printed": bool(raw), "tx_bytes": len(raw) // 2,
              "core_verdict": verdict and verdict.get("reject-reason"),
              "with_broadcast": str(code_b)[:80]}
OUT["F1"] = f1
print("F1", json.dumps(f1, indent=1))

# F2 ---------------------------------------------------------------------------------------------
seed = new_seed()
a0, a1 = address(seed, 0), address(seed, 1)
fund(a0, 0.01)
fund(a1, 0.01)
raw1, _, c1 = unlock(seed, "--deposit", "1", "--feerate", "2", "--broadcast")         # vault 1 spent: keys public
rpc("generatetoaddress", 1, MINE)
raw0, err0, c0 = unlock(seed, "--deposit", "0", "--feerate", "2", "--amount", "100000", "--change-deposit", "1",
                        "--broadcast")
rpc("generatetoaddress", 1, MINE)
left = rpc("scantxoutset", "start", [f"addr({a1})"])["unspents"]
OUT["F2"] = {"vault1_spent_first": c1 == 0, "unlock0_exit": c0, "change_sent_to_spent_vault": bool(left),
             "sats_now_at_exposed_vault": sum(round(u["amount"] * 1e8) for u in left),
             "tool_warning": [l for l in err0.splitlines() if "NEVER BEEN SPENT" in l][:1]}
print("F2", json.dumps(OUT["F2"], indent=1))

# F3 ---------------------------------------------------------------------------------------------
seed = new_seed()
fund(address(seed, 0), 0.01)
_, _, c3 = unlock(seed, "--feerate", "2", "--amount", "-5", "--change-deposit", "1")
OUT["F3"] = {"exit": str(c3)}
print("F3", OUT["F3"])

# F4 ---------------------------------------------------------------------------------------------
seed = new_seed()
a0 = address(seed, 0)
fund(a0, 0.01)                                   # confirmed
late = fund(a0, 0.02, mine=False)                # still in the mempool
raw4, err4, c4 = unlock(seed, "--feerate", "2", "--broadcast")
rpc("generatetoaddress", 1, MINE)
left = rpc("scantxoutset", "start", [f"addr({a0})"])["unspents"]
OUT["F4"] = {"unlock_exit": c4, "late_deposit_txid": late, "left_at_spent_vault_sats":
             sum(round(u["amount"] * 1e8) for u in left), "outputs_left": len(left)}
print("F4", json.dumps(OUT["F4"], indent=1))

# F5 ---------------------------------------------------------------------------------------------
secrets = vault_secrets(os.urandom(64), NET, 201, 0)
k = 1
while True:
    try:
        tx = build_unlock(secrets, [Outpoint(f"{i:064x}", 0, 10 ** 6) for i in range(k)],
                          bytes([0, 20]) + bytes(20), 1.0, standard=False)
    except ValueError as e:
        OUT["F5"] = {"stopped_at_inputs": k, "error": str(e)}
        break
    if tx.weight > 4_000_000:
        OUT["F5"] = {"inputs": k, "weight": tx.weight, "built_anyway": True}
        break
    k = k * 2 if tx.weight * 2 < 4_000_000 else k + 10
print("F5", OUT["F5"])

# F6 ---------------------------------------------------------------------------------------------
# the key path has no key-count level: vaults with different --keys at one deposit share keys
seed_bytes = os.urandom(64)
k50, k100 = vault_secrets(seed_bytes, NET, 50, 0), vault_secrets(seed_bytes, NET, 100, 0)
OUT["F6"] = {"keys50_equal_first50_of_keys100": k50 == k100[:50],
             "regtest_keys_equal_signet_keys": vault_secrets(seed_bytes, NET, 3, 0)
             == vault_secrets(seed_bytes, network.get("signet"), 3, 0)}
print("F6", OUT["F6"])

# F7 ---------------------------------------------------------------------------------------------
seed = new_seed()
fund(address(seed, 0), 1.0)
raw7, err7, c7 = unlock(seed, "--feerate", "20000")
v7 = rpc("testmempoolaccept", [raw7])[0]
_, errb7, cb7 = unlock(seed, "--feerate", "20000", "--broadcast")
OUT["F7"] = {"tool_exit": c7, "fee_sats": round(v7["fees"]["base"] * 1e8) if v7.get("fees") else None,
             "core_verdict": v7.get("reject-reason", "allowed"), "with_broadcast": str(cb7)[:80],
             "fee_line": [l for l in err7.splitlines() if "fee" in l][:1]}
print("F7", json.dumps(OUT["F7"], indent=1))

# F8 ---------------------------------------------------------------------------------------------
import hashlib
from eternax_vault.encoding import address_to_script_pubkey, segwit_encode, b58check_encode
secrets = vault_secrets(os.urandom(64), NET, 100, 0)
ws = chain_script([pubkey(s) for s in secrets])
h160 = lambda b: hashlib.new("ripemd160", hashlib.sha256(b).digest()).digest()
from eternax_vault.script import p2wsh_script_pubkey
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
OUT["F8"] = f8
print("F8", json.dumps(f8, indent=1))

# F9 ---------------------------------------------------------------------------------------------
seed = new_seed()
a = address(seed, 0)
txid = fund(a, 0.01)
outs = rpc("scantxoutset", "start", [f"addr({a})"])["unspents"]
real = outs[0]
raw9, _, c9 = unlock(seed, "--feerate", "2", "--utxo", f"{real['txid']}:{real['vout']}:{round(real['amount'] * 1e8) + 1000}")
v9 = rpc("testmempoolaccept", [raw9])[0] if raw9 else {}
crashes = {}
for args in (["--feerate", "inf"], ["--feerate", "2", "--utxo", f"{real['txid']}:-1:1000000"]):
    _, _, c = unlock(seed, *args)
    crashes[" ".join(args)[:40]] = str(c)[:70]
OUT["F9"] = {"wrong_user_amount_signed": bool(raw9), "core_verdict": v9.get("reject-reason"), "crashes": crashes}
print("F9", json.dumps(OUT["F9"], indent=1))

with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "results", "findings_repro.json"), "w") as f:
    json.dump(OUT, f, indent=1)
