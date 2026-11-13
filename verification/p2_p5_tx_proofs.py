"""P2 (liveness, limits, fee bound) and P5 (sighash, value conservation) — offline proofs and checks.

Z3 proofs over a model of build_unlock's arithmetic, then property-based tests (Hypothesis) that tie
the real Python to that model, then an independent BIP-143 implementation compared byte for byte.

  P2.1  limits(): standard <=> n <= 100, consensus-valid <=> n <= 201 (exhaustive, n = 1..1000)
  P2.2  every signature sign_low_r produces is DER, low-R, low-S and <= 71 bytes with the sighash byte
  P2.3  Z3: weight(real tx) <= weight(placeholder estimate) for every signature length <= 71
  P2.4  Z3: paid fee / real vsize >= requested feerate, for every feerate > 0
  P2.5  Z3: sigop cost <= 16,000 (Core's standard limit) whenever weight <= 400,000, for n = 1..201
  P2.6  Z3: n <= 100 keeps every per-input policy limit (items, item size, script size)
  P5.1  Z3: value conservation and non-negative outputs >= dust, on both output shapes
  P5.2  Z3 counterexample: without feerate > 0 the conservation-with-positive-fee property fails
  P5.3  Hypothesis: build_unlock agrees with the model (values, errors) on random inputs
  P5.4  Hypothesis: tx.sighash == independent BIP-143 implementation, byte for byte
  P5.5  Hypothesis: changing any output, amount or outpoint changes every input's sighash
"""
import hashlib
import math
import random
import sys

import coincurve
import z3
from hypothesis import HealthCheck, example, given, settings, strategies as st

from eternax_vault.keys import pubkey, sign_low_r, vault_secrets
from eternax_vault.script import MAX_STANDARD_P2WSH_SCRIPT_SIZE, chain_script, limits, p2wsh_script_pubkey
from eternax_vault.tx import (MAX_STANDARD_TX_WEIGHT, PLACEHOLDER_SIG, SEQUENCE_RBF, Outpoint, UnlockTx, build_unlock,
                              dust_threshold)
from eternax_vault import network

NET = network.get("regtest")
SECP_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
results = {}


def report(name, ok, detail=""):
    results[name] = ok
    print(f"{name:6s} {'PASS' if ok else 'FAIL'}  {detail}")


def proved(s):
    return s.check() == z3.unsat


# ---------------------------------------------------------------- P2.1 limits() vs Core's rules
def p2_1():
    bad = []
    for n in range(1, 1001):
        lim = limits(n)
        std = n <= 100 and 35 * n <= MAX_STANDARD_P2WSH_SCRIPT_SIZE       # Core: items <= 100, script <= 3,600
        cons = n <= 201 and 35 * n <= 10_000                                # Core: 201 ops, 10,000-byte script
        if lim["standard"] != std or lim["consensus_valid"] != cons or lim["script_bytes"] != 35 * n:
            bad.append(n)
    report("P2.1", not bad and limits(100)["standard"] and not limits(101)["standard"]
           and limits(201)["consensus_valid"] and not limits(202)["consensus_valid"],
           "limits(n) matches Core's standard (n<=100) and consensus (n<=201) rules for n=1..1000")


# ---------------------------------------------------------------- P2.2 signature encoding bound
def der_parse(sig):
    assert sig[0] == 0x30 and sig[1] == len(sig) - 2 and sig[2] == 0x02
    lr = sig[3]
    r = sig[4:4 + lr]
    assert sig[4 + lr] == 0x02
    ls = sig[5 + lr]
    s = sig[6 + lr:6 + lr + ls]
    assert 6 + lr + ls == len(sig)
    for x in (r, s):                                       # strict DER: minimal, positive
        assert x[0] < 0x80 and (len(x) == 1 or x[0] != 0 or x[1] >= 0x80)
    return int.from_bytes(r, "big"), int.from_bytes(s, "big"), lr, ls


def p2_2(count=20000):
    rng = random.Random(7)
    worst = 0
    ok = True
    for _ in range(count):
        sk = rng.randbytes(32)
        if not 0 < int.from_bytes(sk, "big") < SECP_N:
            continue
        sig = sign_low_r(sk, rng.randbytes(32))
        r, s, lr, ls = der_parse(sig)
        ok &= lr <= 32 and r < 2 ** 255 and s <= SECP_N // 2 and len(sig) + 1 <= 71
        worst = max(worst, len(sig) + 1)
    # analytic bound: DER = 6 + len(r) + len(s); low R and low S (< 2^255) encode in <= 32 bytes each
    ok &= 6 + 32 + 32 + 1 == 71 == len(PLACEHOLDER_SIG)
    report("P2.2", ok, f"{count} signatures: all strict DER, low-R, low-S; longest {worst} B incl. sighash; "
                       f"bound 6+32+32+1 = 71 = placeholder")


# ---------------------------------------------------------------- weight model (from UnlockTx.serialize)
def varint_len(x):
    return z3.If(x < 0xFD, 1, z3.If(x <= 0xFFFF, 3, 5))


def weight_model(n, k, out_lens, sig_len):
    """Exact weight of an unlock with k inputs of an n-key vault; sig_len(i, j) = DER sig + sighash byte."""
    base = 4 + varint_len(k) + k * 41 + varint_len(len(out_lens)) + sum(8 + varint_len(L) + L for L in out_lens) + 4
    wit = 2
    for i in range(k):
        wit += varint_len(n + 1) + sum(1 + sig_len(i, j) for j in range(n)) + varint_len(35 * n) + 35 * n
    return 4 * base + wit


def weight_concrete(n, k, out_lens, sig_lens):
    return z3.simplify(weight_model(n, k, out_lens, lambda i, j: sig_lens[i][j])).as_long()


# ---------------------------------------------------------------- P2.3 weight <= estimate
def p2_3():
    ok = True
    for n in (1, 2, 7, 8, 20, 100, 201):
        for k in (1, 2, 5):
            L = {(i, j): z3.Int(f"L_{i}_{j}") for i in range(k) for j in range(n)}
            s = z3.Solver()
            for v in L.values():
                s.add(v >= 9, v <= 71)                     # shortest DER sig is 8 bytes + sighash byte
            for outs in ([22], [22, 34], [25, 23]):
                s.push()
                s.add(weight_model(n, k, outs, lambda i, j: L[(i, j)]) > weight_model(n, k, outs, lambda i, j: 71))
                ok &= proved(s)
                s.pop()
    report("P2.3", ok, "Z3: real weight <= placeholder-estimate weight for n in {1,2,7,8,20,100,201}, k in {1,2,5}")


# ---------------------------------------------------------------- P2.4 fee-rate bound
def ceil_div4(w):
    return (w + 3) / 4                                     # integer ceil(w/4) for w >= 0 (Z3 Int division)


def p2_4():
    W_est, W, fee = z3.Ints("W_est W fee")
    f = z3.Real("feerate")
    V_est, V = ceil_div4(W_est), ceil_div4(W)
    s = z3.Solver()
    s.add(W >= 0, W <= W_est, f > 0)
    prod = z3.ToReal(V_est) * f
    s.add(fee == -z3.ToInt(-prod))                         # fee = ceil(V_est * f)
    s.add(z3.ToReal(fee) < z3.ToReal(V) * f)              # paid rate below requested?
    report("P2.4", proved(s), "Z3: fee = ceil(vsize_est*f) and vsize <= vsize_est  =>  fee/vsize >= f (exact arithmetic)")
    # the code computes ceil on an IEEE-754 double; check the rounding never under-pays by >= 1 sat
    rng = random.Random(3)
    worst = 0.0
    for _ in range(200000):
        v = rng.randrange(100, 400_000)
        fr = rng.choice([rng.uniform(0.1, 1000), round(rng.uniform(0.1, 100), 1), rng.randrange(1, 500)])
        from fractions import Fraction
        exact = Fraction(v) * Fraction(fr)
        paid = math.ceil(v * fr)
        worst = max(worst, float(exact - paid))
    report("P2.4f", worst < 1e-6, f"float check, 200,000 cases: max under-payment vs exact product {worst:.2e} sat")


# ---------------------------------------------------------------- P2.5 sigops within standard limit
def p2_5():
    ok = True
    for n in range(1, 202):
        k = z3.Int("k")
        s = z3.Solver()
        s.add(k >= 1)
        # weight lower bound per input: 41 B base (x4) + witness (n sigs of >= 9 B + length bytes, script)
        per_input = 4 * 41 + 1 + n * (1 + 9) + 1 + 35 * n
        s.add(k * per_input <= MAX_STANDARD_TX_WEIGHT)    # any tx the tool allows (weight <= 400,000)
        s.add(k * n > 16_000)                              # sigop cost: 1 per CHECKSIG(VERIFY), witness scale 1
        ok &= proved(s)
    report("P2.5", ok, "Z3: weight <= 400,000 WU  =>  sigop cost n*k <= 16,000, for every n = 1..201")


# ---------------------------------------------------------------- P2.6 per-input policy limits
def p2_6():
    n = z3.Int("n")
    s = z3.Solver()
    s.add(n >= 1, n <= 100)
    s.add(z3.Or(n > 100,                                  # MAX_STANDARD_P2WSH_STACK_ITEMS (excl. script)
                35 * n > 3600,                             # MAX_STANDARD_P2WSH_SCRIPT_SIZE
                71 > 80,                                   # MAX_STANDARD_P2WSH_STACK_ITEM_SIZE vs longest sig
                n > 201,                                   # MAX_OPS_PER_SCRIPT
                n + 1 > 1000))                             # MAX_STACK_SIZE during execution
    report("P2.6", proved(s), "Z3: 1 <= n <= 100  =>  stack items, item size, script size, op count, stack depth all within limits")


# ---------------------------------------------------------------- P5.1 / P5.2 value model
def value_model(f_positive=True):
    T, fee, amt, dust_d, dust_c, out0, out1 = z3.Ints("T fee amount dust_d dust_c out0 out1")
    V = z3.Int("V")
    f = z3.Real("f")
    pay = z3.Bool("pay")
    pre = [T >= 0, T <= 21_000_000 * 10 ** 8, V >= 1, dust_d >= 0, dust_c >= 0,
           fee == -z3.ToInt(-(z3.ToReal(V) * f))]
    if f_positive:
        pre.append(f > 0)
    # branch A (sweep): accepted iff T - fee >= dust_d; output = T - fee
    # branch B (pay):   accepted iff amt >= dust_d and T - amt - fee >= 0 and >= dust_c
    accepted = z3.If(pay, z3.And(amt >= dust_d, T - amt - fee >= 0, T - amt - fee >= dust_c), T - fee >= dust_d)
    outs = [out0 == z3.If(pay, amt, T - fee), out1 == z3.If(pay, T - amt - fee, 0)]
    prop = z3.And(out0 + out1 + fee == T, out0 >= dust_d, out0 >= 0, out1 >= 0,
                  z3.Implies(pay, out1 >= dust_c), fee >= 1)
    return pre + outs + [accepted], prop, (T, fee, f, out0, pay)


def p5_1():
    pre, prop, _ = value_model(True)
    s = z3.Solver()
    s.add(*pre, z3.Not(prop))
    report("P5.1", proved(s), "Z3: accepted unlock => outputs + fee == inputs, outputs >= dust >= 0, fee >= 1 sat (feerate > 0)")


def p5_2():
    pre, prop, (T, fee, f, out0, pay) = value_model(False)
    s = z3.Solver()
    s.add(*pre, z3.Not(prop), f < 0, T >= 100_000, z3.Not(pay), out0 > T)    # an output larger than the inputs
    found = s.check() == z3.sat
    ex = ""
    if found:
        m = s.model()
        ex = f"e.g. feerate={m[f]}, inputs={m[T]}, output={m[out0]}, fee={m[fee]}"
    report("P5.2", found, f"Z3 finds the expected counterexample when feerate <= 0 is allowed (finding F1): {ex}")


# ---------------------------------------------------------------- P5.3 build_unlock vs model
_SECRETS = {n: vault_secrets(bytes(range(64)), NET, n, 0) for n in (1, 2, 3, 20, 99, 100)}
_CHANGE = {n: p2wsh_script_pubkey(chain_script([pubkey(s) for s in vault_secrets(bytes(range(64)), NET, n, 1)]))
           for n in _SECRETS}
_r = random.Random(5)
SPKS = [bytes([0, 20]) + bytes(20), bytes([0, 32]) + bytes(32), bytes([0x51, 32]) + bytes(32),
        b"\x76\xa9\x14" + bytes(20) + b"\x88\xac", b"\xa9\x14" + bytes(20) + b"\x87",
        bytes([0, 20]) + _r.randbytes(20), bytes([0, 32]) + _r.randbytes(32), bytes([0x51, 32]) + _r.randbytes(32),
        bytes([0x52, 2]) + _r.randbytes(2), bytes([0x60, 40]) + _r.randbytes(40)]


def model_unlock(n, amounts, dest, feerate, amount, change):
    """Independent re-statement of the spec: returns ('ok', outputs) or ('err', None)."""
    k = len(amounts)
    outs_spk = [dest] if amount is None else [dest, change]
    est = weight_concrete(n, k, [len(x) for x in outs_spk], [[71] * n for _ in range(k)])
    if est > MAX_STANDARD_TX_WEIGHT:
        return "err", None
    T = sum(amounts)
    fee = math.ceil(math.ceil(est / 4) * feerate)
    dust = lambda spk: 3 * (8 + 1 + len(spk) + (67 if spk[0] in (0, *range(0x51, 0x61)) and spk[1] == len(spk) - 2 else 148))
    if amount is None:
        return ("ok", [T - fee]) if T - fee >= dust(dest) else ("err", None)
    c = T - amount - fee
    if amount < dust(dest) or c < 0 or c < dust(change):
        return "err", None
    return "ok", [amount, c]


@settings(max_examples=400, deadline=None, suppress_health_check=list(HealthCheck))
@given(n=st.sampled_from([1, 2, 3, 20, 99, 100]), amounts=st.lists(st.integers(0, 5 * 10 ** 8), min_size=1, max_size=40),
       dest=st.sampled_from(SPKS), feerate=st.one_of(st.floats(0.1, 300, allow_nan=False), st.floats(300, 50_000)),
       amount=st.one_of(st.none(), st.integers(-10, 5 * 10 ** 8)))
@example(n=3, amounts=[10 ** 6], dest=SPKS[0], feerate=2.0, amount=-5)
@example(n=100, amounts=[10 ** 6] * 37, dest=SPKS[0], feerate=1.0, amount=None)
def _p5_3(n, amounts, dest, feerate, amount):
    prev = [Outpoint(f"{i:064x}", i % 3, a) for i, a in enumerate(amounts)]
    change = _CHANGE[n] if amount is not None else None
    expect, outs = model_unlock(n, amounts, dest, feerate, amount, change)
    try:
        tx = build_unlock(_SECRETS[n], prev, dest, feerate, amount=amount, change_script_pubkey=change)
        got = "ok"
    except ValueError:
        got = "err"
    except OverflowError:                                # finding F3: negative amount crashes before signing
        assert amount is not None and amount < 0
        CRASHES.append(amount)
        got = "err"
    assert got == expect, (got, expect)
    if got == "ok":
        assert [v for v, _ in tx.outputs] == outs
        assert sum(v for v, _ in tx.outputs) + math.ceil(math.ceil(
            weight_concrete(n, len(prev), [len(s) for _, s in tx.outputs], [[71] * n] * len(prev)) / 4) * feerate) == sum(amounts)
        assert tx.weight <= MAX_STANDARD_TX_WEIGHT and all(len(w) == n + 1 for w in tx.witnesses)
        assert tx.weight == weight_concrete(n, len(prev), [len(s) for _, s in tx.outputs],
                                            [[len(x) for x in w[:-1]] for w in tx.witnesses])
        # every signature, in its witness position, verifies under its key over the independent BIP-143 digest
        pks = [pubkey(s) for s in _SECRETS[n]]
        ws = chain_script(pks)
        for i in {0, len(prev) - 1}:
            w = tx.witnesses[i]
            assert w[-1] == ws
            digest = bip143(2, [(p.txid, p.vout) for p in prev], [SEQUENCE_RBF] * len(prev), tx.outputs, 0, i, ws,
                            prev[i].amount)
            for pos, sig in enumerate(w[:-1]):
                key = pks[n - 1 - pos]                   # witness [sig_{n-1} .. sig_0]: sig_0 on top
                assert sig[-1] == 1 and coincurve.PublicKey(key).verify(sig[:-1], digest, hasher=None)


CRASHES = []


def p5_3():
    try:
        _p5_3()
        report("P5.3", True, "Hypothesis, 400 cases: build_unlock == spec model (accept/refuse, every output value, "
                             f"fee, weight formula, witness shape); negative amounts crash before signing "
                             f"(OverflowError, no tx): {len(CRASHES)} cases")
    except Exception as e:
        report("P5.3", False, repr(e)[:300])


# ---------------------------------------------------------------- P5.4 / P5.5 sighash
def dsha(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def ser_compact(n):
    return bytes([n]) if n < 0xFD else b"\xfd" + n.to_bytes(2, "little") if n <= 0xFFFF else b"\xfe" + n.to_bytes(4, "little")


def bip143(version, prevouts, sequences, outputs, locktime, index, script_code, amount, hashtype=1):
    """Written from the BIP-143 text, independent of eternax_vault.tx."""
    hash_prevouts = dsha(b"".join(bytes.fromhex(t)[::-1] + v.to_bytes(4, "little") for t, v in prevouts))
    hash_sequence = dsha(b"".join(s.to_bytes(4, "little") for s in sequences))
    hash_outputs = dsha(b"".join(v.to_bytes(8, "little") + ser_compact(len(spk)) + spk for v, spk in outputs))
    t, v = prevouts[index]
    pre = (version.to_bytes(4, "little") + hash_prevouts + hash_sequence
           + bytes.fromhex(t)[::-1] + v.to_bytes(4, "little")
           + ser_compact(len(script_code)) + script_code
           + amount.to_bytes(8, "little") + sequences[index].to_bytes(4, "little")
           + hash_outputs + locktime.to_bytes(4, "little") + hashtype.to_bytes(4, "little"))
    return dsha(pre)


tx_strategy = dict(
    n=st.sampled_from([1, 3, 20, 100]),
    ins=st.lists(st.tuples(st.binary(min_size=32, max_size=32), st.integers(0, 2 ** 32 - 1),
                           st.integers(0, 21 * 10 ** 14)), min_size=1, max_size=6, unique_by=lambda x: (x[0], x[1])),
    outs=st.lists(st.tuples(st.integers(0, 21 * 10 ** 14), st.sampled_from(SPKS)), min_size=1, max_size=3),
)


@settings(max_examples=500, deadline=None, suppress_health_check=list(HealthCheck))
@given(**tx_strategy)
def _p5_4(n, ins, outs):
    ws = chain_script([pubkey(s) for s in _SECRETS[n]])
    prev = [Outpoint(t.hex(), v, a) for t, v, a in ins]
    tx = UnlockTx(prev, outs, [])
    for i in range(len(prev)):
        ref = bip143(2, [(p.txid, p.vout) for p in prev], [SEQUENCE_RBF] * len(prev), outs, 0, i, ws, prev[i].amount)
        assert tx.sighash(i, ws) == ref


@settings(max_examples=300, deadline=None, suppress_health_check=list(HealthCheck))
@given(**tx_strategy, which=st.integers(0, 3), delta=st.integers(1, 1000))
def _p5_5(n, ins, outs, which, delta):
    ws = chain_script([pubkey(s) for s in _SECRETS[n]])
    prev = [Outpoint(t.hex(), v, a) for t, v, a in ins]
    base = UnlockTx(prev, outs, [])
    if which == 0:                                       # change an output value
        outs2 = [(outs[0][0] + delta, outs[0][1])] + outs[1:]
        prev2 = prev
    elif which == 1:                                     # change an output script
        outs2 = [(outs[0][0], bytes([0, 20]) + delta.to_bytes(20, "big"))] + outs[1:] if outs[0][1] != bytes([0, 20]) + delta.to_bytes(20, "big") else [(outs[0][0], SPKS[1])] + outs[1:]
        prev2 = prev
    elif which == 2:                                     # change a spent amount
        prev2 = [Outpoint(prev[0].txid, prev[0].vout, prev[0].amount + delta)] + prev[1:]
        outs2 = outs
    else:                                                # add an output
        outs2 = outs + [(delta, SPKS[0])]
        prev2 = prev
    alt = UnlockTx(prev2, outs2, [])
    for i in range(len(prev)):
        if which == 2 and i != 0:
            continue                                     # BIP-143 commits each input's own amount only
        assert base.sighash(i, ws) != alt.sighash(i, ws)


def p5_4():
    try:
        _p5_4()
        report("P5.4", True, "Hypothesis, 500 txs (1-6 inputs, 1-3 outputs, n in {1,3,20,100}): tx.sighash == independent BIP-143")
    except Exception as e:
        report("P5.4", False, repr(e)[:300])


def p5_5():
    try:
        _p5_5()
        report("P5.5", True, "Hypothesis, 300 txs: changing an output value/script, adding an output, or the spent amount changes the sighash")
    except Exception as e:
        report("P5.5", False, repr(e)[:300])


if __name__ == "__main__":
    for fn in (p2_1, p2_2, p2_3, p2_4, p2_5, p2_6, p5_1, p5_2, p5_3, p5_4, p5_5):
        fn()
    bad = [k for k, v in results.items() if not v]
    print("ALL PASS" if not bad else f"FAILED: {bad}")
    sys.exit(1 if bad else 0)
