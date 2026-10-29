"""eternax-vault: lock coins in a 100-key one-time P2WSH vault, and unlock them.

    eternax-vault new        --seed-file vault.seed                              # writes a 24-word BIP-39 phrase
    eternax-vault lock       --seed-file vault.seed --network mainnet            # prints the address to send to
    eternax-vault unlock     --seed-file vault.seed --network mainnet \\
                             --utxo <txid>:0:100000 [--utxo …] --to <address> --feerate 5    # every output at the address
                             [--amount <sats> --change-deposit 1]          # pay part, the rest to a fresh vault
    eternax-vault descriptor --seed-file vault.seed --network mainnet --private  # for Bitcoin Core
    eternax-vault odds       --keys 100
"""
from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path

from . import network
from .descriptor import vault_descriptor
from .encoding import address_to_script_pubkey, p2wsh_address
from .keys import PURPOSE, new_mnemonic, pubkey, seed_from_mnemonic, vault_secrets
from .odds import attack_odds
from .rpc import RPC
from .script import MAX_CONSENSUS_KEYS, MAX_STANDARD_KEYS, chain_script, p2wsh_script_pubkey
from .tx import Outpoint, build_unlock

DEFAULT_KEYS = 100


def _read_seed(path: str) -> bytes:
    try:
        return seed_from_mnemonic(Path(path).expanduser().read_text())
    except ValueError as e:
        sys.exit(f"{path}: {e}")


def _secrets(args, deposit: int | None = None) -> list[bytes]:
    if not 1 <= args.keys <= MAX_CONSENSUS_KEYS:
        sys.exit(f"--keys must be between 1 and {MAX_CONSENSUS_KEYS}")
    return vault_secrets(_read_seed(args.seed_file), network.get(args.network), args.keys,
                         args.deposit if deposit is None else deposit)


def cmd_new(args):
    path = Path(args.seed_file).expanduser()
    if path.exists():
        sys.exit(f"{path} exists; refusing to overwrite a seed")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(new_mnemonic() + "\n")
    print(f"wrote a 24-word BIP-39 seed phrase to {path} (mode 600). Write the words down and store them like any "
          "wallet seed: every vault key derives from them, and without them the coins are gone.")
    print(f"WRITE DOWN THE DERIVATION PATH ON THE SAME PAPER AS THE 24 WORDS: m/{PURPOSE}'/0'/0..99'/<deposit>' "
          f"ON MAINNET (1' INSTEAD OF 0' ON TEST NETWORKS). {PURPOSE}' IS NOT A STANDARD PURPOSE: WITHOUT THE PATH, "
          "NO WALLET WILL FIND THESE KEYS.")


def cmd_lock(args):
    net = network.get(args.network)
    secrets = _secrets(args)
    ws = chain_script([pubkey(s) for s in secrets])
    print(p2wsh_address(ws, net))
    print(f"# {args.keys}-of-{args.keys} chain, {len(ws)}-byte witness script, keys at "
          f"m/{PURPOSE}'/{net.coin}'/0..{args.keys - 1}'/{args.deposit}'", file=sys.stderr)
    if args.keys > MAX_STANDARD_KEYS:
        print(f"# WARNING: more than {MAX_STANDARD_KEYS} keys cannot be relayed; the unlock must go to a miner directly",
              file=sys.stderr)
    print("# Receive here as often as you like, then unlock once: the unlock sweeps every output at this address, "
          "and the address is retired. Keep the seed and this vault's public keys private until then: at rest "
          "only their hash is on-chain.", file=sys.stderr)
    print(f"# WRITE DOWN WITH THE 24 WORDS: PATH m/{PURPOSE}'/{net.coin}'/0..{args.keys - 1}'/{args.deposit}', "
          f"NETWORK {args.network.upper()}, DEPOSIT {args.deposit}, {args.keys} KEYS. WITHOUT THE PATH, "
          "NO WALLET WILL FIND THESE KEYS.", file=sys.stderr)


def cmd_descriptor(args):
    net = network.get(args.network)
    print(vault_descriptor(_secrets(args), net, private=args.private))
    if args.private:
        print("# This descriptor contains the private keys: anyone holding it can spend. Treat it like the seed.",
              file=sys.stderr)
    else:
        print("# This descriptor contains every public key. Keep it private until you unlock: "
              "at rest the vault's protection is that nobody has seen them.", file=sys.stderr)


def _utxo(text: str) -> tuple[str, int, int | None]:
    parts = text.split(":")
    try:
        if len(parts) not in (2, 3) or len(bytes.fromhex(parts[0])) != 32:
            raise ValueError
        return parts[0].lower(), int(parts[1]), int(parts[2]) if len(parts) == 3 else None
    except ValueError:
        raise argparse.ArgumentTypeError(f"expected TXID:VOUT or TXID:VOUT:SATS, got {text!r}") from None


def _vault_outputs(rpc: RPC, address: str) -> dict[tuple[str, int], int]:
    """Every confirmed unspent output at the address, from the node's UTXO set."""
    scan = rpc("scantxoutset", "start", [f"addr({address})"])
    return {(u["txid"], u["vout"]): round(u["amount"] * 100_000_000) for u in scan["unspents"]}


def cmd_unlock(args):
    net = network.get(args.network)
    rpc = RPC(args.rpc_url, cookie=args.rpc_cookie) if args.rpc_url else None
    secrets = _secrets(args)
    address = p2wsh_address(chain_script([pubkey(s) for s in secrets]), net)
    on_chain = _vault_outputs(rpc, address) if rpc else None
    if args.utxo:
        listed = {(txid, vout) for txid, vout, _ in args.utxo}
        if on_chain is not None and set(on_chain) - listed:
            missing = ", ".join(f"{t}:{v}" for t, v in sorted(set(on_chain) - listed))
            sys.exit(f"{address} also holds {missing}; list every output, or it is exposed once this unlock confirms")
        prevouts = []
        for txid, vout, sats in args.utxo:
            if sats is None:
                if on_chain is None or (txid, vout) not in on_chain:
                    sys.exit(f"{txid}:{vout}: give the amount as TXID:VOUT:SATS, or a --rpc-url whose node has it confirmed")
                sats = on_chain[(txid, vout)]
            prevouts.append(Outpoint(txid, vout, sats))
    elif on_chain:
        prevouts = [Outpoint(t, v, sats) for (t, v), sats in sorted(on_chain.items())]
    else:
        sys.exit("--utxo is required without --rpc-url" if rpc is None else f"no confirmed outputs at {address}")
    change_address = change_spk = None
    if args.change_deposit is not None:
        change_ws = chain_script([pubkey(s) for s in _secrets(args, args.change_deposit)])
        change_address, change_spk = p2wsh_address(change_ws, net), p2wsh_script_pubkey(change_ws)
    t = time.perf_counter()
    try:
        tx = build_unlock(secrets, prevouts, address_to_script_pubkey(args.to, net), args.feerate,
                          standard=not args.allow_nonstandard, amount=args.amount, change_script_pubkey=change_spk)
    except ValueError as e:
        sys.exit(str(e))
    ms = (time.perf_counter() - t) * 1000
    raw = tx.serialize().hex()
    fee = sum(p.amount for p in prevouts) - sum(v for v, _ in tx.outputs)
    print(f"# txid {tx.txid}\n# {len(prevouts)} input(s) from {address}\n"
          f"# {tx.vsize} vB, {tx.weight} WU, fee {fee} sat ({fee / tx.vsize:.2f} sat/vB), "
          f"{len(secrets) * len(prevouts)} signatures in {ms:.0f} ms", file=sys.stderr)
    if change_address:
        print(f"# pays {tx.outputs[0][0]} sat to {args.to}; change {tx.outputs[1][0]} sat to {change_address} "
              f"(deposit {args.change_deposit})", file=sys.stderr)
        print(f"# WRITE DOWN WITH THE 24 WORDS: THE CHANGE IS IN DEPOSIT {args.change_deposit}, PATH "
              f"m/{PURPOSE}'/{net.coin}'/0..{args.keys - 1}'/{args.change_deposit}'. IT MUST BE A DEPOSIT THAT HAS "
              "NEVER BEEN SPENT: A SPENT VAULT'S KEYS ARE PUBLIC.", file=sys.stderr)
    if on_chain is None:
        print(f"# Check that these are all the outputs at {address}: any left behind is exposed once this confirms.",
              file=sys.stderr)
    if args.broadcast:
        if rpc is None:
            sys.exit("--broadcast needs --rpc-url")
        check = rpc("testmempoolaccept", [raw])[0]
        if not check["allowed"]:
            sys.exit(f"node refuses it: {check.get('reject-reason')}")
        print(rpc("sendrawtransaction", raw))
    else:
        print(raw)


def cmd_odds(args):
    print(f"P(attacker derives all {args.keys} keys before the next block), "
          f"{args.minutes_per_key:g} min/key, {args.block_minutes:g}-min blocks")
    for c in args.machines:
        print(f"  {c:>4} machine{'s' if c > 1 else ' '}  {attack_odds(args.keys, c, args.minutes_per_key, args.block_minutes):.3g}")


def main(argv=None):
    p = argparse.ArgumentParser(prog="eternax-vault", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    def vault_args(sp):
        sp.add_argument("--seed-file", required=True)
        sp.add_argument("--network", required=True, choices=list(network.NETWORKS))
        sp.add_argument("--keys", type=int, default=DEFAULT_KEYS, help=f"keys in the script (default {DEFAULT_KEYS})")
        sp.add_argument("--deposit", type=int, default=0, help="deposit index; use each index once")

    sp = sub.add_parser("new", help="create a seed file")
    sp.add_argument("--seed-file", required=True)
    sp.set_defaults(func=cmd_new)

    sp = sub.add_parser("lock", help="print the vault address for a deposit index")
    vault_args(sp)
    sp.set_defaults(func=cmd_lock)

    sp = sub.add_parser("descriptor", help="print the vault as a Bitcoin Core descriptor")
    vault_args(sp)
    sp.add_argument("--private", action="store_true", help="include private keys so Bitcoin Core can sign")
    sp.set_defaults(func=cmd_descriptor)

    sp = sub.add_parser("unlock", help="sign a transaction spending every output at the vault address")
    vault_args(sp)
    sp.add_argument("--utxo", type=_utxo, action="append",
                    help="TXID:VOUT:SATS of an output at the vault address; repeat for each. With --rpc-url, SATS "
                         "can be left out, and without --utxo every confirmed output at the address is swept")
    sp.add_argument("--to", required=True, help="destination address")
    sp.add_argument("--amount", type=int,
                    help="satoshis to pay to --to; the rest, less the fee, goes to the vault at --change-deposit. "
                         "Without it, everything goes to --to")
    sp.add_argument("--change-deposit", type=int,
                    help="deposit index of the fresh vault, from the same seed, that takes the change; "
                         "use an index that has never been spent")
    sp.add_argument("--feerate", type=float, required=True, help="sat/vB")
    sp.add_argument("--rpc-url", help="Bitcoin Core RPC, e.g. http://user:pass@127.0.0.1:8332")
    sp.add_argument("--rpc-cookie", help="path to Bitcoin Core's .cookie file instead of URL credentials")
    sp.add_argument("--broadcast", action="store_true", help="check with testmempoolaccept, then send")
    sp.add_argument("--allow-nonstandard", action="store_true", help=f"allow more than {MAX_STANDARD_KEYS} keys")
    sp.set_defaults(func=cmd_unlock)

    sp = sub.add_parser("odds", help="in-flight attack odds for a key count")
    sp.add_argument("--keys", type=int, default=DEFAULT_KEYS)
    sp.add_argument("--machines", type=int, nargs="+", default=[1, 5, 10, 20, 50, 100])
    sp.add_argument("--minutes-per-key", type=float, default=9.0)
    sp.add_argument("--block-minutes", type=float, default=10.0)
    sp.set_defaults(func=cmd_odds)

    args = p.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
