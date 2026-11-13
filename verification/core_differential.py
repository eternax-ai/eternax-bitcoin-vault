"""Differential checks against an unmodified Bitcoin Core v31.1 node (regtest).

Bitcoin Core is the reference implementation of consensus and relay policy (assumption A4). Each
check below asks Core to judge what eternax_vault produces:

  P1  every mutation of a valid 100-key (and 3-key) witness is rejected by consensus
      (generateblock refuses a block containing it) and by policy (testmempoolaccept)
  P2  unlocks across key counts, input counts, fee rates and both output shapes are accepted and
      mined; Core's weight equals the tool's; the paid fee rate >= the requested one; the largest
      sweep build_unlock allows is accepted, and the next one up is refused by the tool itself
  P3  Core's descriptor checksum, derived address and decoded script equal the tool's; Bitcoin
      Core's own wallet, given only the private descriptor, spends the vault
  P5  the transaction signatures verify in Core (so tx.sighash == Core's BIP-143 digest) for 1..37
      inputs and both output shapes; address_to_script_pubkey agrees with Core's validateaddress
      on valid and corrupted addresses of every type

Usage: EBV_RPC_URL=http://u:p@127.0.0.1:18443 python core_differential.py
"""
import json
import os
import random
import sys

from mnemonic import Mnemonic

from eternax_vault import network
from eternax_vault.descriptor import vault_descriptor
from eternax_vault.encoding import address_to_script_pubkey, p2wsh_address, segwit_encode, b58check_encode
from eternax_vault.keys import pubkey, seed_from_mnemonic, sign_low_r, vault_secrets
from eternax_vault.rpc import RPC
from eternax_vault.script import chain_script, p2wsh_script_pubkey
from eternax_vault.tx import (MAX_STANDARD_TX_WEIGHT, PLACEHOLDER_SIG, SIGHASH_ALL, Outpoint, UnlockTx,
                              build_unlock)

NET = network.get("regtest")
rng = random.Random(20261102)
rpc = RPC(os.environ["EBV_RPC_URL"])
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
rpc("generatetoaddress", 120, MINE)
RESULTS = {}
failures = []


def check(cond, label):
    if not cond:
        failures.append(label)
        print("FAIL", label)
    return cond


def fresh_secrets(n, deposit=0):
    seed = seed_from_mnemonic(Mnemonic("english").to_mnemonic(rng.randbytes(32)))
    return vault_secrets(seed, NET, n, deposit)


def fund(address, sats, count=1):
    outs = []
    for _ in range(count):
        txid = miner("sendtoaddress", address, sats / 1e8)
        tx = rpc("decoderawtransaction", miner("gettransaction", txid)["hex"])
        v = next(o for o in tx["vout"] if o["scriptPubKey"].get("address") == address)
        outs.append(Outpoint(txid, v["n"], round(v["value"] * 1e8)))
    rpc("generatetoaddress", 1, MINE)
    return outs


def dest_spk():
    return address_to_script_pubkey(miner("getnewaddress", "", "bech32"), NET)


def consensus_ok(raw):
    try:
        rpc("generateblock", MINE, [raw], False)       # submit=False: validate the block, do not add it
        return True, ""
    except RuntimeError as e:
        return False, str(e)


def mempool(raw):
    try:
        r = rpc("testmempoolaccept", [raw])[0]
    except RuntimeError as e:                          # undecodable transaction: rejected outright
        return False, str(e), {}
    return r["allowed"], r.get("reject-reason", ""), r


# ---------------------------------------------------------------- P1: witness mutations
def p1():
    out = {}
    for n in (3, 100):
        secrets = fresh_secrets(n)
        other = fresh_secrets(n)
        ws = chain_script([pubkey(s) for s in secrets])
        addr = p2wsh_address(ws, NET)
        prev = fund(addr, 1_000_000)
        tx = build_unlock(secrets, prev, dest_spk(), 2.0)
        good = tx.witnesses[0]
        sigs = good[:-1]                                    # [sig_{n-1}, ..., sig_0]
        h = tx.sighash(0, ws)
        alt = UnlockTx(tx.prevouts, [(tx.outputs[0][0] - 1, tx.outputs[0][1])], [])
        h_other_tx = alt.sighash(0, ws)
        top = len(sigs) - 1                                 # index of sig_0 in the witness list
        mid = len(sigs) // 2
        muts = {
            "drop sig_0 (top)": sigs[:top] + [ws],
            "drop middle sig": sigs[:mid] + sigs[mid + 1:] + [ws],
            "drop sig_{n-1} (bottom)": sigs[1:] + [ws],
            "swap two adjacent sigs": sigs[:mid] + [sigs[mid + 1], sigs[mid]] + sigs[mid + 2:] + [ws],
            "reverse all sigs": sigs[::-1] + [ws],
            "duplicate one sig over another": sigs[:mid] + [sigs[mid + 1]] + sigs[mid + 1:] + [ws],
            "sig by a wrong key": sigs[:mid] + [sign_low_r(other[n - 1 - mid], h) + bytes([SIGHASH_ALL])]
                                  + sigs[mid + 1:] + [ws],
            "sig over a different tx": sigs[:mid] + [sign_low_r(secrets[n - 1 - mid], h_other_tx) + bytes([SIGHASH_ALL])]
                                       + sigs[mid + 1:] + [ws],
            "empty sig (NULLFAIL)": sigs[:mid] + [b""] + sigs[mid + 1:] + [ws],
            "extra item at bottom": [b"\x01"] + sigs + [ws],
            "extra valid-looking sig": [sigs[0]] + sigs + [ws],
            "sighash byte -> NONE": sigs[:top] + [sigs[top][:-1] + b"\x02"] + [ws],
            "sighash byte -> ALL|ANYONECANPAY": sigs[:top] + [sigs[top][:-1] + b"\x81"] + [ws],
            "witness script of other keys": sigs + [chain_script([pubkey(s) for s in other])],
            "witness script truncated by one key": sigs[1:] + [chain_script([pubkey(s) for s in secrets[:-1]])],
            "no witness at all": [],
        }
        res = {}
        for name, wit in muts.items():
            t = UnlockTx(tx.prevouts, tx.outputs, [wit])
            raw = t.serialize(with_witness=bool(wit)).hex()  # empty witness: legacy encoding, as a wallet would send
            cons, cerr = consensus_ok(raw)
            pol, perr, _ = mempool(raw)
            res[name] = {"consensus_rejected": not cons, "mempool_rejected": not pol, "reason": perr}
            check(not cons and not pol, f"P1 n={n} mutation '{name}' was accepted")
        raw = tx.serialize().hex()
        cons, cerr = consensus_ok(raw)
        pol, perr, _ = mempool(raw)
        check(cons and pol, f"P1 n={n} honest witness rejected: {cerr} {perr}")
        res["honest witness"] = {"consensus_ok": cons, "mempool_ok": pol}
        rpc("sendrawtransaction", raw)
        rpc("generatetoaddress", 1, MINE)
        out[n] = res
        print(f"P1 n={n}: {len(muts)} mutations, all rejected: {all(r['consensus_rejected'] and r['mempool_rejected'] for k, r in res.items() if k != 'honest witness')}; honest accepted: {cons and pol}")
    RESULTS["P1"] = out


def p1_boundary():
    """Above 100 keys: consensus-valid up to 201 (generateblock accepts), never relayed; 202 is invalid."""
    out = {}
    for n in (101, 201, 202):
        secrets = fresh_secrets(n)
        addr = p2wsh_address(chain_script([pubkey(s) for s in secrets]), NET)
        prev = fund(addr, 1_000_000)
        tx = build_unlock(secrets, prev, dest_spk(), 2.0, standard=False)
        raw = tx.serialize().hex()
        cons, cerr = consensus_ok(raw)
        pol, perr, _ = mempool(raw)
        out[n] = {"consensus_valid": cons, "consensus_error": cerr[-60:], "mempool_reason": perr}
        expect_cons = n <= 201
        check(cons == expect_cons and not pol, f"P1 boundary n={n}: consensus {cons}, mempool {pol} {perr}")
    RESULTS["P1_boundary"] = out
    print("P1 boundary:", {n: (v["consensus_valid"], v["mempool_reason"] or v["consensus_error"]) for n, v in out.items()})


# ---------------------------------------------------------------- P2 + P5: liveness, fee, sighash
def estimate_weight(n, k, outputs):
    ws = b"\x00" * (35 * n)
    t = UnlockTx([Outpoint("00" * 32, i, 0) for i in range(k)], outputs, [[PLACEHOLDER_SIG] * n + [ws]] * k)
    return t.weight


def unlock_case(n, k, feerate, pay=False):
    secrets = fresh_secrets(n, 0)
    ws = chain_script([pubkey(s) for s in secrets])
    addr = p2wsh_address(ws, NET)
    prev = fund(addr, 2_000_000, k)
    dest = dest_spk()
    if pay:
        change_ws = chain_script([pubkey(s) for s in vault_secrets_like(secrets, n)])
        tx = build_unlock(secrets, prev, dest, feerate, amount=50_000, change_script_pubkey=p2wsh_script_pubkey(change_ws))
    else:
        tx = build_unlock(secrets, prev, dest, feerate)
    raw = tx.serialize().hex()
    ok, reason, r = mempool(raw)
    est = estimate_weight(n, k, [(0, spk) for _, spk in tx.outputs])
    fee = sum(p.amount for p in prev) - sum(v for v, _ in tx.outputs)
    row = {"keys": n, "inputs": k, "feerate": feerate, "pay+change": pay, "accepted": ok, "reason": reason,
           "core_vsize": r.get("vsize"), "tool_vsize": tx.vsize, "tool_weight": tx.weight, "estimate_weight": est,
           "fee": fee, "paid_rate": round(fee / tx.vsize, 6)}
    check(ok, f"P2 n={n} k={k} fr={feerate} pay={pay} rejected: {reason}")
    if ok:
        check(r["vsize"] == tx.vsize, f"P2 vsize mismatch n={n} k={k}: core {r['vsize']} tool {tx.vsize}")
        check(r["fees"]["base"] * 1e8 == fee or abs(r["fees"]["base"] * 1e8 - fee) < 0.5, "P2 fee mismatch")
        check(tx.weight <= est, f"P2 weight above estimate n={n} k={k}")
        check(fee >= tx.vsize * feerate - 1e-9, f"P2 paid rate below requested n={n} k={k}")
        check(sum(v for v, _ in tx.outputs) + fee == sum(p.amount for p in prev), "P5 value not conserved")
        rpc("sendrawtransaction", raw)
        blk = rpc("generatetoaddress", 1, MINE)[0]
        row["mined"] = rpc("getrawtransaction", tx.txid, True, blk)["confirmations"] == 1
        check(row["mined"], "P2 not mined")
    return row


def vault_secrets_like(_secrets, n):
    return fresh_secrets(n, 1)


def p2():
    rows = []
    for n in (1, 2, 7, 8, 20, 99, 100):
        for k in (1, 3):
            rows.append(unlock_case(n, k, 2.0))
    for fr in (0.1, 1.0, 3.7, 25.0, 500.0):
        rows.append(unlock_case(100, 1, fr))
    for n in (1, 100):
        rows.append(unlock_case(n, 2, 2.0, pay=True))
    # largest sweep the tool allows for 100 keys, and the one above it
    secrets = fresh_secrets(100)
    k = 1
    while estimate_weight(100, k + 1, [(0, dest_spk())]) <= MAX_STANDARD_TX_WEIGHT:
        k += 1
    rows.append(unlock_case(100, k, 1.0))
    try:
        build_unlock(secrets, [Outpoint(f"{i:064x}", 0, 100_000) for i in range(k + 1)], dest_spk(), 1.0)
        refused = False
    except ValueError:
        refused = True
    check(refused, f"P2 tool did not refuse {k + 1} inputs")
    print(f"P2: max 100-key sweep = {k} inputs (accepted by Core), {k + 1} refused by the tool: {refused}")
    RESULTS["P2"] = {"cases": rows, "max_inputs_100_keys": k, "next_refused": refused}
    print(f"P2/P5: {len(rows)} unlocks, accepted+mined: {sum(1 for r in rows if r.get('mined'))}")


# ---------------------------------------------------------------- P3: commitment and descriptor
def p3():
    rows = []
    for n in (1, 2, 3, 15, 16, 20, 100, 101, 201):
        secrets = fresh_secrets(n, rng.randrange(1000))
        ws = chain_script([pubkey(s) for s in secrets])
        addr = p2wsh_address(ws, NET)
        pub = vault_descriptor(secrets, NET, private=False)
        priv = vault_descriptor(secrets, NET, private=True)
        val = rpc("validateaddress", addr)
        dec = rpc("decodescript", ws.hex())
        row = {"keys": n,
               "validateaddress_spk_match": val["isvalid"] and val["scriptPubKey"] == p2wsh_script_pubkey(ws).hex()}
        # decodescript offers a P2WSH address for a script unless it is a bare pubkey script (n = 1),
        # where it offers the P2WPKH form instead; for n = 1 compare its decoded asm instead.
        if dec["type"] == "pubkey":
            row["decodescript_asm_match"] = dec["asm"] == f"{pubkey(secrets[0]).hex()} OP_CHECKSIG"
        else:
            row["decodescript_address_match"] = dec.get("segwit", {}).get("address") == addr
        if n <= 100:
            info = rpc("getdescriptorinfo", pub)
            info_priv = rpc("getdescriptorinfo", priv)
            row["checksum_match"] = info["checksum"] == pub.split("#")[1]
            row["private_checksum_match"] = info_priv["checksum"] == priv.split("#")[1]
            row["derived_address_match"] = rpc("deriveaddresses", pub) == [addr]
        else:
            # above 100 keys the spend is non-standard and Core refuses the descriptor (101: miniscript
            # sanity check, "needs witnesses that may exceed resource limits"; 201: the parser gives up).
            try:
                rpc("getdescriptorinfo", pub)
                row["core_refuses_descriptor_above_100"] = False
            except RuntimeError as e:
                row["core_refuses_descriptor_above_100"] = True
                row["core_refusal"] = str(e)[-90:]
        for key, v in row.items():
            if key not in ("keys", "core_refusal"):
                check(v, f"P3 n={n} {key}")
        rows.append(row)
    # Bitcoin Core's own wallet spends a 100-key vault from the private descriptor alone
    secrets = fresh_secrets(100, 7)
    ws = chain_script([pubkey(s) for s in secrets])
    addr = p2wsh_address(ws, NET)
    fund(addr, 300_000)
    name = f"fv-core-{os.urandom(6).hex()}"
    rpc("createwallet", name, False, True, "", False, True)       # blank descriptor wallet
    w = rpc.wallet(name)
    imp = w("importdescriptors", [{"desc": vault_descriptor(secrets, NET, private=True), "timestamp": 0}])
    sent = w("sendall", [MINE], None, "unset", 2)
    blk = rpc("generatetoaddress", 1, MINE)[0]
    mined = rpc("getrawtransaction", sent["txid"], True, blk)["confirmations"] == 1
    check(imp[0]["success"] and sent["complete"] and mined, "P3 Core wallet could not spend from descriptor")
    RESULTS["P3"] = {"cases": rows, "core_wallet_spend": {"import": imp[0]["success"], "mined": mined,
                                                         "txid": sent["txid"]}}
    print(f"P3: {len(rows)} key counts all match Core: {all(all(v for k, v in r.items() if k not in ('keys', 'core_refusal')) for r in rows)}; "
          f"Core wallet spent 100-key vault from descriptor alone: {mined}")


# ---------------------------------------------------------------- P5: destination address decoding
def corrupt(addr):
    s = list(addr)
    kind = rng.randrange(5)
    i = rng.randrange(len(s))
    if kind == 0:
        s[i] = rng.choice("qpzry9x8gf2tvdw0s3jn54khce6mua7l123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")
    elif kind == 1:
        del s[i]
    elif kind == 2:
        s.insert(i, rng.choice("qpzry9x8gf2tvdw0s3jn54khce6mua7l"))
    elif kind == 3:
        s[i] = s[i].swapcase()
    else:
        j = min(i + 1, len(s) - 1)
        s[i], s[j] = s[j], s[i]
    return "".join(s)


def gen_address():
    t = rng.randrange(8)
    if t == 0:
        return b58check_encode(bytes([NET.p2pkh]) + rng.randbytes(20))
    if t == 1:
        return b58check_encode(bytes([NET.p2sh]) + rng.randbytes(20))
    if t == 2:
        return segwit_encode(NET.hrp, 0, rng.randbytes(20))
    if t == 3:
        return segwit_encode(NET.hrp, 0, rng.randbytes(32))
    if t == 4:
        return segwit_encode(NET.hrp, 1, rng.randbytes(32))
    if t == 5:
        v = rng.randrange(1, 17)
        return segwit_encode(NET.hrp, v, rng.randbytes(rng.randrange(2, 41)))
    if t == 6:
        return b58check_encode(bytes([0x00]) + rng.randbytes(20))     # mainnet P2PKH: wrong network
    return segwit_encode("bc", 0, rng.randbytes(20))                   # mainnet bech32: wrong network


def p5_addresses():
    agree = disagree = 0
    samples = []
    for i in range(3000):
        a = gen_address()
        if i % 2:
            a = corrupt(a)
        v = rpc("validateaddress", a)
        try:
            ours = address_to_script_pubkey(a, NET).hex()
        except Exception:
            ours = None
        core = v["scriptPubKey"] if v["isvalid"] else None
        if ours == core:
            agree += 1
        else:
            disagree += 1
            samples.append({"address": a, "tool": ours, "core": core})
    check(disagree == 0, f"P5 address decoding disagrees with Core on {disagree} inputs")
    RESULTS["P5_addresses"] = {"checked": agree + disagree, "agree": agree, "disagree": disagree,
                               "examples": samples[:10]}
    print(f"P5: address decoding vs Core: {agree}/{agree + disagree} agree")


if __name__ == "__main__":
    p1()
    p1_boundary()
    p2()
    p3()
    p5_addresses()
    RESULTS["failures"] = failures
    RESULTS["core_version"] = rpc("getnetworkinfo")["subversion"]
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "results", "core_differential.json"), "w") as f:
        json.dump(RESULTS, f, indent=1)
    print("FAILURES:" if failures else "ALL CORE DIFFERENTIAL CHECKS PASSED", *failures, sep="\n")
    sys.exit(1 if failures else 0)
