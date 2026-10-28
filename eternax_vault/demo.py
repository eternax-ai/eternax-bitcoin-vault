"""Regtest walkthrough against an unmodified Bitcoin Core node (wallet enabled).

    bitcoind -regtest -daemon -fallbackfee=0.0001
    python -m eternax_vault.demo --rpc-cookie ~/.bitcoin/regtest/.cookie
    #   or --rpc-url http://user:pass@127.0.0.1:18443   (macOS cookie: ~/Library/Application Support/Bitcoin/regtest/.cookie)

1. lock    derive a 100-key vault address from a fresh seed and fund it from a Core wallet
2. unlock  sign the 100-signature sweep with this package, check it, broadcast it, mine it
3. core    the same kind of vault through Bitcoin Core alone: import the descriptor, receive, sendall
4. limits  101 and 201 keys: refused by the mempool, valid in a block; 202 keys: invalid
"""
from __future__ import annotations

import argparse
import json
import os
import re
import time

from . import network
from .descriptor import vault_descriptor
from .encoding import address_to_script_pubkey, p2wsh_address
from .keys import new_mnemonic, pubkey, seed_from_mnemonic, vault_secrets
from .odds import attack_odds
from .rpc import RPC
from .script import chain_script, limits
from .tx import Outpoint, build_unlock

NET = network.get("regtest")
MINER_WALLET = "eternax-demo-miner"


def fresh_seed() -> bytes:
    return seed_from_mnemonic(new_mnemonic())


class Node:
    def __init__(self, rpc: RPC):
        self.rpc = rpc
        if rpc("getblockchaininfo")["chain"] != "regtest":
            raise SystemExit("refusing to run: this demo only talks to a regtest node")
        if MINER_WALLET not in rpc("listwallets"):
            try:
                rpc("loadwallet", MINER_WALLET)
            except RuntimeError:
                rpc("createwallet", MINER_WALLET)
        self.miner = rpc.wallet(MINER_WALLET)
        self.mine_addr = self.miner("getnewaddress")
        if self.miner("getbalance") < 10:
            self.mine(101)

    def mine(self, n: int = 1) -> list[str]:
        return self.rpc("generatetoaddress", n, self.mine_addr)

    def fund(self, address: str, btc: float) -> Outpoint:
        txid = self.miner("sendtoaddress", address, btc)
        tx = self.rpc("decoderawtransaction", self.miner("gettransaction", txid)["hex"])
        out = next(o for o in tx["vout"] if o["scriptPubKey"].get("address") == address)
        self.mine(1)
        return Outpoint(txid, out["n"], round(out["value"] * 100_000_000))

    def confirmations(self, txid: str, block: str) -> int:
        return self.rpc("getrawtransaction", txid, True, block)["confirmations"]


def lock_and_unlock(node: Node, n_keys: int = 100, feerate: float = 5.0) -> dict:
    secrets = vault_secrets(fresh_seed(), NET, n_keys, deposit=0)
    ws = chain_script([pubkey(s) for s in secrets])
    address = p2wsh_address(ws, NET)
    prevout = node.fund(address, 1.0)
    t = time.perf_counter()
    tx = build_unlock(secrets, [prevout], address_to_script_pubkey(node.miner("getnewaddress"), NET), feerate)
    sign_ms = (time.perf_counter() - t) * 1000
    check = node.rpc("testmempoolaccept", [tx.serialize().hex()])[0]
    txid = node.rpc("sendrawtransaction", tx.serialize().hex())
    block = node.mine(1)[0]
    return {"keys": n_keys, "vault_address": address, "funding_txid": prevout.txid, "unlock_txid": txid,
            "witness_script_bytes": len(ws), "witness_items": len(tx.witnesses[0]), "weight": tx.weight,
            "vsize": tx.vsize, "core_vsize": check["vsize"], "fee_sat": prevout.amount - tx.outputs[0][0],
            "mempool_allowed": check["allowed"], "confirmations": node.confirmations(txid, block),
            "build_and_sign_ms": round(sign_ms, 1)}


def through_core(node: Node, n_keys: int = 100) -> dict:
    secrets = vault_secrets(fresh_seed(), NET, n_keys, deposit=0)
    ours = p2wsh_address(chain_script([pubkey(s) for s in secrets]), NET)
    desc = vault_descriptor(secrets, NET, private=True)
    info = node.rpc("getdescriptorinfo", desc.split("#")[0])
    core_address = node.rpc("deriveaddresses", desc)[0]
    name = f"eternax-demo-vault-{os.urandom(4).hex()}"
    node.rpc("createwallet", name, False, True)                       # blank descriptor wallet
    vault = node.rpc.wallet(name)
    imported = vault("importdescriptors", [{"desc": desc, "timestamp": "now"}])[0]["success"]
    node.fund(core_address, 1.0)
    sent = vault("sendall", [node.miner("getnewaddress")], None, "unset", 5)
    block = node.mine(1)[0]
    tx = node.rpc("getrawtransaction", sent["txid"], True, block)
    node.rpc("unloadwallet", name)
    return {"keys": n_keys, "checksum_matches_core": info["checksum"] == desc.split("#")[1],
            "address_matches_ours": core_address == ours, "imported": imported, "unlock_txid": sent["txid"],
            "witness_items": len(tx["vin"][0]["txinwitness"]), "vsize": tx["vsize"], "weight": tx["weight"],
            "confirmations": tx["confirmations"]}


def probe(node: Node, n_keys: int) -> dict:
    secrets = vault_secrets(fresh_seed(), NET, n_keys, deposit=0)
    prevout = node.fund(p2wsh_address(chain_script([pubkey(s) for s in secrets]), NET), 0.1)
    tx = build_unlock(secrets, [prevout], address_to_script_pubkey(node.mine_addr, NET), 5, standard=False)
    raw = tx.serialize().hex()
    check = node.rpc("testmempoolaccept", [raw])[0]
    try:
        node.rpc("generateblock", node.mine_addr, [raw])             # a miner including it directly
        block = "valid"
    except RuntimeError as e:                                          # "...-failed (Operation limit exceeded), input 0..."
        reason = re.search(r"\(([^()]+)\)", str(e))
        block = f"invalid: {reason.group(1) if reason else e}"
    return {**limits(n_keys), "vsize": tx.vsize, "mempool": "accepted" if check["allowed"] else check["reject-reason"],
            "block": block}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--rpc-url", default="http://127.0.0.1:18443")
    p.add_argument("--rpc-cookie")
    p.add_argument("--json-out", help="write the results here")
    args = p.parse_args(argv)
    node = Node(RPC(args.rpc_url, cookie=args.rpc_cookie))
    version = node.rpc("getnetworkinfo")["subversion"]
    print(f"node {version}\n")

    print("1-2. lock and unlock with this package")
    ours = lock_and_unlock(node)
    for k, v in ours.items():
        print(f"     {k:22} {v}")
    print("\n3. the same thing with Bitcoin Core's wallet alone")
    core = through_core(node)
    for k, v in core.items():
        print(f"     {k:22} {v}")
    print("\n4. key-count limits")
    probes = [probe(node, n) for n in (100, 101, 201, 202)]
    for r in probes:
        print(f"     {r['keys']:>3} keys  {r['script_bytes']:>5} B script  {r['vsize']:>5} vB  "
              f"mempool: {r['mempool']:<24} block: {r['block']}")
    print("\nin-flight attack odds (9 min/key, 10-min blocks)")
    odds = {m: {c: attack_odds(m, c) for c in (1, 5, 10, 20, 50, 100)} for m in (1, 20, 100)}
    for m, row in odds.items():
        print(f"     {m:>3} keys  " + "  ".join(f"{c}: {pr:.2g}" for c, pr in row.items()))
    if args.json_out:
        with open(args.json_out, "w") as f:
            json.dump({"node": version, "lock_unlock": ours, "bitcoin_core_wallet": core, "limits": probes,
                       "odds": odds}, f, indent=1)


if __name__ == "__main__":
    main()
