"""P3 (commitment), P4 (derivation), P6 (one-time use).

  P3.1  exhaustive n = 1..201: an independent miniscript-subset compiler turns the tool's descriptor
        into exactly chain_script's bytes, and SPK = 0x00 0x20 SHA256(WS)
  P3.2  bech32 address <-> SPK round trip for n = 1..201 (encode, then decode with the tool's decoder)
  P4.1  BIP-39 official vector (Trezor, passphrase "TREZOR")
  P4.2  independent BIP-32 (hmac + pure-python secp256k1 from `ecdsa`) == vault_secrets, 300 random
        (seed, network, slot, deposit) cases incl. boundary indices
  P4.3  Bitcoin Core derives the same keys: wpkh(tprv/17752h/1h/slot h/deposit h) via deriveaddresses
        (needs EBV_RPC_URL; skipped otherwise)
  P4.4  path injectivity and range: (coin, slot, deposit) -> path is injective; indices >= 2^31 or < 0
        are refused (no silent aliasing); repeated derivation is identical
  P6.1  Hypothesis: build_unlock never creates an output paying the vault being spent
  P6.2  cmd_unlock refuses a partial sweep when the node shows more outputs at the address
  P6.3  with node data, cmd_unlock refuses a typed amount that differs from the node's, and an outpoint the node
        does not show at the vault, before signing anything (finding F9)
"""
import contextlib
import hashlib
import hmac
import io
import os
import random
import sys
import types

from ecdsa import SECP256k1
from hypothesis import HealthCheck, given, settings, strategies as st

from eternax_vault import cli, network
from eternax_vault.descriptor import vault_descriptor
from eternax_vault.encoding import address_to_script_pubkey, b58check_encode, p2wsh_address, segwit_encode
from eternax_vault.keys import PURPOSE, pubkey, seed_from_mnemonic, vault_secrets
from eternax_vault.script import chain_script, p2wsh_script_pubkey
from eternax_vault.tx import Outpoint, build_unlock

results = {}


def report(name, ok, detail=""):
    results[name] = ok
    print(f"{name:6s} {'PASS' if ok else 'FAIL' if ok is False else 'SKIP'}  {detail}")


# ---------------------------------------------------------------- P3.1 descriptor -> script
def compile_ms(expr: str) -> bytes:
    """Independent compiler for the miniscript fragments the vault uses: pk(K), v:pk(K), and_v(X,Y).
    Written from the miniscript spec: pk(K) = <K> CHECKSIG; v:pk(K) = <K> CHECKSIGVERIFY; and_v(X,Y) = [X] [Y]."""
    def parse(s, i):
        if s.startswith("and_v(", i):
            x, i = parse(s, i + 6)
            assert s[i] == ","
            y, i = parse(s, i + 1)
            assert s[i] == ")"
            return x + y, i + 1
        verify = s.startswith("v:", i)
        if verify:
            i += 2
        assert s.startswith("pk(", i), s[i:i + 10]
        j = s.index(")", i)
        key = bytes.fromhex(s[i + 3:j])
        assert len(key) == 33
        return bytes([33]) + key + bytes([0xAD if verify else 0xAC]), j + 1
    out, end = parse(expr, 0)
    assert end == len(expr)
    return out


def p3_1():
    rng = random.Random(11)
    net = network.get("mainnet")
    bad = 0
    for n in range(1, 202):
        secrets = vault_secrets(rng.randbytes(64), net, n, rng.randrange(2 ** 31))
        d = vault_descriptor(secrets, net, private=False)
        body, _ = d.split("#")
        assert body.startswith("wsh(") and body.endswith(")")
        ws = chain_script([pubkey(s) for s in secrets])
        ok = compile_ms(body[4:-1]) == ws and p2wsh_script_pubkey(ws) == b"\x00\x20" + hashlib.sha256(ws).digest()
        bad += not ok
    report("P3.1", bad == 0, "exhaustive n=1..201: independent compile(descriptor) == chain_script bytes; SPK = OP_0 <SHA256(WS)>")


def p3_2():
    rng = random.Random(12)
    bad = 0
    for name in ("mainnet", "regtest", "signet"):
        net = network.get(name)
        for n in range(1, 202):
            ws = chain_script([pubkey(s) for s in vault_secrets(rng.randbytes(64), net, n, 0)])
            if address_to_script_pubkey(p2wsh_address(ws, net), net) != p2wsh_script_pubkey(ws):
                bad += 1
    report("P3.2", bad == 0, "n=1..201 on mainnet, regtest, signet: decode(p2wsh_address(WS)) == SPK")


# ---------------------------------------------------------------- P4 derivation
G, N = SECP256k1.generator, SECP256k1.order


def ser_p(sk_int):
    P = G * sk_int
    return bytes([2 + (P.y() & 1)]) + P.x().to_bytes(32, "big")


def ckd_priv(k, c, i):
    """BIP-32 CKDpriv, written from the BIP text."""
    data = (b"\x00" + k.to_bytes(32, "big") if i >= 2 ** 31 else ser_p(k)) + i.to_bytes(4, "big")
    I = hmac.new(c, data, hashlib.sha512).digest()
    il = int.from_bytes(I[:32], "big")
    assert il < N
    k2 = (il + k) % N
    assert k2 != 0
    return k2, I[32:]


def master(seed):
    I = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    return int.from_bytes(I[:32], "big"), I[32:]


def derive(seed, path):
    k, c = master(seed)
    for i in path:
        k, c = ckd_priv(k, c, i)
    return k


def tprv(seed):
    k, c = master(seed)
    return b58check_encode(bytes.fromhex("04358394") + b"\x00" + b"\x00" * 4 + b"\x00" * 4 + c + b"\x00" + k.to_bytes(32, "big"))


H = 2 ** 31


def p4_1():
    words = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    expect = ("c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c"
              "4ab7c81b2f001698e7463b04")
    ref = hashlib.pbkdf2_hmac("sha512", words.encode(), b"mnemonicTREZOR", 2048).hex()
    report("P4.1", seed_from_mnemonic(words, "TREZOR").hex() == expect == ref,
           "BIP-39 Trezor vector (passphrase TREZOR) == tool == stdlib PBKDF2")


def p4_2():
    rng = random.Random(13)
    bad = 0
    cases = 0
    for t in range(300):
        seed = rng.randbytes(rng.choice([16, 32, 64]))
        net = network.get(rng.choice(["mainnet", "testnet", "regtest", "signet"]))
        deposit = rng.choice([0, 1, 2 ** 31 - 1, rng.randrange(2 ** 31)])
        n = rng.choice([1, 2, 5])
        got = vault_secrets(seed, net, n, deposit)
        for slot in range(n):
            ref = derive(seed, [PURPOSE + H, net.coin + H, slot + H, deposit + H]).to_bytes(32, "big")
            bad += ref != got[slot]
            cases += 1
        # slot 99 and 100 of a 101-key vault
        if t % 30 == 0:
            got = vault_secrets(seed, net, 101, deposit)
            for slot in (99, 100):
                bad += derive(seed, [PURPOSE + H, net.coin + H, slot + H, deposit + H]).to_bytes(32, "big") != got[slot]
                cases += 1
    report("P4.2", bad == 0, f"{cases} keys: independent BIP-32 == vault_secrets (seeds 16/32/64 B, all networks, deposit up to 2^31-1)")


def p4_3():
    url = os.environ.get("EBV_RPC_URL")
    if not url:
        report("P4.3", None, "skipped: no EBV_RPC_URL")
        return
    from eternax_vault.rpc import RPC
    rpc = RPC(url)
    rng = random.Random(14)
    net = network.get("regtest")
    bad = 0
    for _ in range(40):
        seed = rng.randbytes(64)
        slot, deposit = rng.randrange(101), rng.choice([0, 1, rng.randrange(2 ** 31)])
        desc = f"wpkh({tprv(seed)}/{PURPOSE}h/1h/{slot}h/{deposit}h)"
        desc += "#" + rpc("getdescriptorinfo", desc)["checksum"]
        core_addr = rpc("deriveaddresses", desc)[0]
        sk = vault_secrets(seed, net, slot + 1, deposit)[slot]
        h160 = hashlib.new("ripemd160", hashlib.sha256(pubkey(sk)).digest()).digest()
        bad += core_addr != segwit_encode(net.hrp, 0, h160)
    report("P4.3", bad == 0, "40 random (seed, slot, deposit): Bitcoin Core's BIP-32 derivation == vault_secrets")


def p4_4():
    seen = {}
    ok = True
    for coin in (0, 1):
        for slot in range(202):
            for deposit in list(range(50)) + [2 ** 31 - 1]:
                p = f"m/{PURPOSE}h/{coin}h/{slot}h/{deposit}h"
                ok &= p not in seen
                seen[p] = (coin, slot, deposit)
                parts = p.split("/")
                ok &= tuple(int(x[:-1]) for x in parts[2:]) == (coin, slot, deposit)
    seed = bytes(range(64))
    net = network.get("mainnet")
    refused = 0
    for bad_idx in (2 ** 31, 2 ** 31 + 1, 2 ** 32, -1):
        try:
            vault_secrets(seed, net, 1, bad_idx)
        except Exception:
            refused += 1
    ok &= refused == 4
    ok &= vault_secrets(seed, net, 5, 3) == vault_secrets(seed, net, 5, 3)
    ok &= network.get("mainnet").coin == 0 and all(network.get(x).coin == 1 for x in ("testnet", "testnet4", "signet", "regtest"))
    report("P4.4", ok, "paths injective (decimal round trip); deposit >= 2^31 or < 0 refused (4/4); deterministic; "
                       "mainnet coin 0' vs test networks 1'")


# ---------------------------------------------------------------- P6 one-time use
_S = vault_secrets(bytes(range(64)), network.get("regtest"), 3, 0)
_VAULT = p2wsh_script_pubkey(chain_script([pubkey(s) for s in _S]))
_OTHER = p2wsh_script_pubkey(chain_script([pubkey(s) for s in vault_secrets(bytes(range(64)), network.get("regtest"), 3, 1)]))


@settings(max_examples=300, deadline=None, suppress_health_check=list(HealthCheck))
@given(dest=st.sampled_from([_VAULT, _OTHER, bytes([0, 20]) + bytes(20)]),
       change=st.sampled_from([None, _VAULT, _OTHER]), amount=st.integers(1000, 10 ** 6))
def _p6_1(dest, change, amount):
    try:
        tx = build_unlock(_S, [Outpoint("ab" * 32, 0, 5 * 10 ** 6)], dest, 1.0,
                          amount=amount if change is not None else None, change_script_pubkey=change)
    except ValueError as e:
        assert _VAULT in (dest, change) or "dust" in str(e) or "cover" in str(e), str(e)
        return
    assert all(spk != _VAULT for _, spk in tx.outputs)


def p6_1():
    try:
        _p6_1()
        report("P6.1", True, "Hypothesis, 300 cases: no unlock ever pays the vault being spent (as destination or change)")
    except Exception as e:
        report("P6.1", False, repr(e)[:300])


STUB_OUTPUTS = {("aa" * 32, 0): 100_000, ("bb" * 32, 1): 200_000, ("cc" * 32, 2): 300_000}


@contextlib.contextmanager
def stub_node():
    """cmd_unlock arguments for a 3-key vault, with cli.RPC replaced by a stub node that reports the three
    STUB_OUTPUTS at the vault address."""
    import tempfile
    from mnemonic import Mnemonic
    phrase = Mnemonic("english").to_mnemonic(bytes(32))
    with tempfile.NamedTemporaryFile("w", suffix=".seed", delete=False) as f:
        f.write(phrase)

    class StubRPC:
        def __init__(self, *a, **k):
            pass

        def __call__(self, method, *params):
            assert method == "scantxoutset"
            return {"unspents": [{"txid": t, "vout": v, "amount": s / 1e8} for (t, v), s in STUB_OUTPUTS.items()]}
    real = cli.RPC
    cli.RPC = StubRPC
    try:
        yield ["unlock", "--seed-file", f.name, "--network", "regtest", "--keys", "3", "--to",
               segwit_encode("bcrt", 0, bytes(20)), "--feerate", "1", "--rpc-url", "http://x:y@127.0.0.1:1"]
    finally:
        cli.RPC = real
        os.unlink(f.name)


def p6_2():
    """Drive cmd_unlock with a stub node that reports three outputs at the vault address."""
    with stub_node() as base:
        try:
            cli.main(base + ["--utxo", f"{'aa' * 32}:0"])
            partial_refused = False
        except SystemExit as e:
            partial_refused = "also holds" in str(e)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(io.StringIO()):
            cli.main(base)                                   # no --utxo: sweeps everything the node reports
        raw = bytes.fromhex(buf.getvalue().strip())
        n_inputs = raw[6]                                    # version(4) + marker/flag(2) -> input count varint
        full_sweep = n_inputs == 3
    report("P6.2", partial_refused and full_sweep,
           f"cmd_unlock with node data: partial list refused ({partial_refused}); default sweeps all 3 outputs ({full_sweep})")


def p6_3():
    listed = [x for (t, v) in STUB_OUTPUTS for x in ("--utxo", f"{t}:{v}")]
    cases = {"typed amount differs from the node's": (["--utxo", f"{'aa' * 32}:0:100001"] + listed[2:], "not 100001"),
             "outpoint the node does not show": (listed + ["--utxo", f"{'dd' * 32}:3:50000"], "not a confirmed output")}
    refused = {}
    with stub_node() as base:
        for label, (extra, expect) in cases.items():
            out = io.StringIO()
            try:
                with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
                    cli.main(base + extra)
                refused[label] = False
            except SystemExit as e:
                refused[label] = expect in str(e.code) and not out.getvalue()
    report("P6.3", all(refused.values()), "cmd_unlock with node data refuses before signing: "
           + "; ".join(f"{k} ({v})" for k, v in refused.items()))


if __name__ == "__main__":
    for fn in (p3_1, p3_2, p4_1, p4_2, p4_3, p4_4, p6_1, p6_2, p6_3):
        fn()
    bad = [k for k, v in results.items() if v is False]
    print("ALL PASS" if not bad else f"FAILED: {bad}")
    sys.exit(1 if bad else 0)
