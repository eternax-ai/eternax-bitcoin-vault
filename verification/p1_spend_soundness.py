"""P1 — Spending soundness and completeness of the n-key chain script.

Part A (machine-checked, Z3): a model of Bitcoin Core's segwit-v0 script execution for the only
opcodes the vault script contains (33-byte push, OP_CHECKSIGVERIFY, OP_CHECKSIG), plus the segwit
clean-stack rule. Signature validity is an uninterpreted predicate Verify(pubkey, sig): the proof
holds for ANY behaviour of the signature check, so it reduces theft to forging signatures (A1).

  Soundness:    Eval(WS_n, witness of ANY length m with ANY contents) succeeds
                  ==>  m == n  and  Verify(pk_i, witness[m-1-i]) for every i in 0..n-1
  Completeness: m == n and all n signatures valid  ==>  Eval succeeds

Proven for every n in 1..201 (every key count the CLI accepts). The witness length m is an
unbounded symbolic integer and the witness contents an unconstrained array, so no witness shape is
left unchecked.

Part B (exhaustive): the real bytes produced by eternax_vault.script.chain_script are parsed by an
independent parser and must be exactly the program the model executes, for n = 1..201.
"""
import random
import sys

import z3

from eternax_vault.keys import pubkey, vault_secrets, seed_from_mnemonic
from eternax_vault.script import chain_script
from eternax_vault import network

OP_CHECKSIG, OP_CHECKSIGVERIFY = 0xAC, 0xAD


def model(n: int, mutant: str | None = None):
    """Symbolic execution of WS_n on a symbolic witness stack. Returns (success, m, W, PK, Verify).
    `mutant` deliberately breaks the script or the rules, for negative controls."""
    Verify = z3.Function("Verify", z3.IntSort(), z3.IntSort(), z3.BoolSort())
    W = z3.Array("W", z3.IntSort(), z3.IntSort())            # witness items, index 0 = bottom
    m = z3.Int("m")                                          # number of witness items (excl. script)
    PK = [z3.Int(f"pk{i}") for i in range(n)]
    stack, sp, err = W, m, z3.BoolVal(False)
    result = z3.BoolVal(False)
    # consensus limits Core enforces on a segwit-v0 witness script (script/interpreter.cpp):
    err = z3.Or(err, z3.BoolVal(35 * n > 10_000))                         # MAX_SCRIPT_SIZE
    err = z3.Or(err, z3.BoolVal(n > 201))                                  # MAX_OPS_PER_SCRIPT (non-push ops)
    for i in range(n):
        stack, sp = z3.Store(stack, sp, PK[i]), sp + 1                     # <pk_i>
        err = z3.Or(err, sp > 1000)                                        # MAX_STACK_SIZE after each op
        err = z3.Or(err, sp < 2)                                           # INVALID_STACK_OPERATION
        ok = Verify(stack[sp - 1], stack[sp - 2])                          # pubkey on top, sig below
        sp = sp - 2
        if i < n - 1 and mutant == "checksig_instead_of_verify":          # result left on stack, unchecked
            stack, sp = z3.Store(stack, sp, z3.If(ok, 1, 0)), sp + 1
        elif i < n - 1:                                                    # OP_CHECKSIGVERIFY
            err = z3.Or(err, z3.Not(ok))
        else:                                                              # OP_CHECKSIG pushes result
            result, sp = ok, sp + 1
    clean = z3.BoolVal(True) if mutant in ("no_clean_stack", "checksig_instead_of_verify") else sp == 1
    success = z3.And(m >= 0, z3.Not(err), sp >= 1, clean, result)         # segwit clean stack + true top
    return success, m, W, PK, Verify


def prove(n: int, mutant: str | None = None) -> tuple[bool, bool]:
    success, m, W, PK, Verify = model(n, mutant)
    distinct = z3.Distinct(*PK) if n > 1 else z3.BoolVal(True)
    sigs_ok = z3.And(*[Verify(PK[i], W[m - 1 - i]) for i in range(n)])
    s = z3.Solver()
    s.add(distinct, success, z3.Not(z3.And(m == n, sigs_ok)))
    sound = s.check() == z3.unsat
    c = z3.Solver()
    c.add(distinct, m == n, sigs_ok, z3.Not(success))
    complete = c.check() == z3.unsat
    return sound, complete


def parse(script: bytes) -> list:
    """Independent parser: list of ('push', bytes) / ('op', code). Rejects anything unexpected."""
    out, i = [], 0
    while i < len(script):
        b = script[i]
        if 1 <= b <= 75:
            assert i + 1 + b <= len(script), "truncated push"
            out.append(("push", script[i + 1:i + 1 + b]))
            i += 1 + b
        else:
            out.append(("op", b))
            i += 1
    return out


def main():
    failures = 0
    for n in range(1, 202):
        sound, complete = prove(n)
        if not (sound and complete):
            failures += 1
            print(f"FAIL n={n}: sound={sound} complete={complete}")
    print(f"Part A: Z3 soundness + completeness for n=1..201: {'PROVEN' if not failures else f'{failures} FAILURES'}")

    rng = random.Random(1)
    from mnemonic import Mnemonic
    net = network.get("regtest")
    bad = 0
    for n in range(1, 202):
        seed = seed_from_mnemonic(Mnemonic("english").to_mnemonic(rng.randbytes(32)))
        pks = [pubkey(s) for s in vault_secrets(seed, net, n, rng.randrange(1000))]
        prog = parse(chain_script(pks))
        expected = []
        for i, pk in enumerate(pks):
            expected += [("push", pk), ("op", OP_CHECKSIGVERIFY if i < n - 1 else OP_CHECKSIG)]
        if prog != expected or len(chain_script(pks)) != 35 * n:
            bad += 1
            print(f"FAIL bytes n={n}")
    # the model assumes n distinct, valid compressed keys: chain_script must refuse anything else
    pk = pks[:3]
    for bad_keys in ([pk[0], pk[1], pk[0]], [pk[0], b"\x04" + pk[1][1:]], [pk[0], pk[1][:32]], []):
        try:
            chain_script(bad_keys)
            bad += 1
            print(f"FAIL chain_script accepted {len(bad_keys)} bad keys")
        except ValueError:
            pass
    print(f"Part B: chain_script bytes == modelled program for n=1..201; duplicate, uncompressed, short and "
          f"empty key lists refused: {'OK' if not bad else f'{bad} FAILURES'}")

    # Part C: negative controls. Each mutant is a known-broken variant; the prover must find a
    # counterexample (soundness NOT proven). If it "proved" a broken script, the method would be vacuous.
    caught = 0
    for mutant in ("checksig_instead_of_verify", "no_clean_stack"):
        for n in (2, 3, 100):
            sound, _ = prove(n, mutant)
            caught += not sound
            print(f"Part C: mutant {mutant:28s} n={n:3d}: {'counterexample found (expected)' if not sound else 'NOT CAUGHT'}")
    # boundary control: with the consensus limits modelled, completeness must FAIL just above 201 keys
    # (Core: "Operation limit exceeded"), so the 1..201 range comes from the model, not from the loop.
    for n in (202, 203, 250):
        _, complete = prove(n)
        caught += not complete
        print(f"Part C: n={n}: honest spend {'impossible under consensus limits (expected)' if not complete else 'STILL POSSIBLE'}")
    controls_ok = caught == 9
    print(f"Part C: negative controls: {'OK' if controls_ok else 'FAILED'}")
    sys.exit(1 if failures or bad or not controls_ok else 0)


if __name__ == "__main__":
    main()
