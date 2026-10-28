"""End-to-end tests against an unmodified Bitcoin Core regtest node with its wallet enabled.

    bitcoind -regtest -daemon -fallbackfee=0.0001
    EBV_RPC_URL=http://user:pass@127.0.0.1:18443 pytest tests/test_regtest.py
    # or EBV_RPC_URL=http://127.0.0.1:18443 EBV_RPC_COOKIE=~/.bitcoin/regtest/.cookie
"""
import os

import pytest

from eternax_vault import cli
from eternax_vault.demo import Node, lock_and_unlock, probe, through_core
from eternax_vault.rpc import RPC

URL = os.environ.get("EBV_RPC_URL")
COOKIE = os.environ.get("EBV_RPC_COOKIE")
pytestmark = pytest.mark.skipif(not URL, reason="set EBV_RPC_URL to a regtest node")


@pytest.fixture(scope="module")
def node():
    return Node(RPC(URL, cookie=COOKIE))


def test_unlock_sweeps_every_deposit_at_the_address(node, tmp_path, capsys):
    seed = str(tmp_path / "vault.seed")
    cli.main(["new", "--seed-file", seed])
    cli.main(["lock", "--seed-file", seed, "--network", "regtest"])
    address = capsys.readouterr().out.strip().splitlines()[-1]
    deposits = [node.fund(address, btc) for btc in (0.1, 0.2, 0.3)]           # three payments, one address
    unlock = ["unlock", "--seed-file", seed, "--network", "regtest", "--to", node.mine_addr, "--feerate", "2",
              "--rpc-url", URL] + (["--rpc-cookie", COOKIE] if COOKIE else [])
    with pytest.raises(SystemExit, match="also holds"):                        # leaving one behind is refused
        cli.main(unlock + ["--utxo", f"{deposits[0].txid}:{deposits[0].vout}"])
    cli.main(unlock + ["--broadcast"])                                         # finds all three itself
    txid = capsys.readouterr().out.strip()
    tx = node.rpc("getrawtransaction", txid, True, node.mine(1)[0])
    assert sorted((i["txid"], i["vout"]) for i in tx["vin"]) == sorted((d.txid, d.vout) for d in deposits)
    assert all(len(i["txinwitness"]) == 101 for i in tx["vin"]) and tx["confirmations"] == 1
    assert node.rpc("scantxoutset", "start", [f"addr({address})"])["unspents"] == []


def test_hundred_key_lock_and_unlock(node):
    r = lock_and_unlock(node, 100)
    assert r["mempool_allowed"] and r["confirmations"] == 1
    assert r["witness_script_bytes"] == 3500 and r["witness_items"] == 101
    assert abs(r["vsize"] - r["core_vsize"]) <= 1


def test_bitcoin_core_wallet_spends_the_same_script(node):
    r = through_core(node, 100)
    assert r["checksum_matches_core"] and r["address_matches_ours"] and r["imported"]
    assert r["witness_items"] == 101 and r["confirmations"] == 1


@pytest.mark.parametrize("n, mempool, block", [(100, "accepted", "valid"),
                                               (101, "bad-witness-nonstandard", "valid"),
                                               (201, "bad-witness-nonstandard", "valid"),
                                               (202, "bad-witness-nonstandard", "invalid")])
def test_key_count_limits(node, n, mempool, block):
    r = probe(node, n)
    assert r["mempool"] == mempool and r["block"].startswith(block)
