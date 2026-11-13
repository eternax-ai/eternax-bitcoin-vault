"""Mutation testing of the verification suite itself.

Each mutant is a copy of eternax_vault with ONE deliberate, realistic bug. The suite must fail on
every mutant; a mutant that survives would show a blind spot. The unmodified code must pass.

Usage: EBV_RPC_URL=... python mutation_test.py /path/to/vault
"""
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
VAULT = os.path.abspath(sys.argv[1])
SUITES = ["p1_spend_soundness.py", "p2_p5_tx_proofs.py", "p3_p4_p6_checks.py"]

MUTANTS = {
    "M1 script: every check is CHECKSIG (no VERIFY)":
        ("script.py", 'body = b"".join(b"\\x21" + pk + bytes([OP_CHECKSIGVERIFY])', 'body = b"".join(b"\\x21" + pk + bytes([OP_CHECKSIG])'),
    "M2 sighash: spent amount left out of the preimage":
        ("tx.py", "+ prevout.amount.to_bytes(8, \"little\") + seq", "+ seq"),
    "M3 fee rounded down instead of up":
        ("tx.py", "fee = math.ceil(tx.vsize * feerate)", "fee = math.floor(tx.vsize * feerate)"),
    "M4 guard against paying the spent vault removed":
        ("tx.py", "if p2wsh_script_pubkey(ws) in (dest_script_pubkey, change_script_pubkey):", "if False:"),
    "M5 placeholder signature one byte short (fee under-estimate)":
        ("tx.py", 'PLACEHOLDER_SIG = b"\\x30" + b"\\x00" * 69 + b"\\x01"', 'PLACEHOLDER_SIG = b"\\x30" + b"\\x00" * 68 + b"\\x01"'),
    "M6 slot level not hardened":
        ("keys.py", '{slot}h/{deposit}h', '{slot}/{deposit}h'),
    "M7 descriptor lists keys in reverse order":
        ("descriptor.py", "desc = f\"wsh({_chain(keys)})\"", "desc = f\"wsh({_chain(keys[::-1])})\""),
    "M8 witness signatures not reversed":
        ("tx.py", "tx.witnesses[i] = sigs[::-1] + [ws]", "tx.witnesses[i] = sigs + [ws]"),
    "M9 change left at the vault: fee taken twice":
        ("tx.py", "change = total - amount - fee", "change = total - amount - 2 * fee"),
    "M10 partial-sweep check removed from the CLI":
        ("cli.py", "if on_chain is not None and set(on_chain) - listed:", "if False:"),
    "M11 duplicate-key check removed":
        ("script.py", "if len(set(pubkeys)) != len(pubkeys):", "if False:"),
    "M12 network coin type ignored (mainnet path on test networks)":
        ("keys.py", "{net.coin}h", "0h"),
}


def run_suites(pkg_parent):
    env = dict(os.environ, PYTHONPATH=pkg_parent)
    where = subprocess.run([sys.executable, "-c", "import eternax_vault; print(eternax_vault.__file__)"],
                           cwd=tempfile.gettempdir(), env=env, capture_output=True, text=True).stdout.strip()
    assert where.startswith(pkg_parent), f"suite would test {where}, not the copy in {pkg_parent}"
    failed = []
    for s in SUITES:
        r = subprocess.run([sys.executable, os.path.join(HERE, s)], cwd=tempfile.gettempdir(), env=env,
                           capture_output=True, text=True, timeout=1200)
        if r.returncode != 0:
            failed.append((s, [l for l in r.stdout.splitlines() if "FAIL" in l][:3] or r.stderr.strip().splitlines()[-1:]))
    return failed


def main():
    work = tempfile.mkdtemp(prefix="ebv-mut-")
    base = os.path.join(work, "orig")
    shutil.copytree(os.path.join(VAULT, "eternax_vault"), os.path.join(base, "eternax_vault"))
    clean = run_suites(base)
    print(f"unmodified code: {'PASS' if not clean else 'FAIL ' + str(clean)}")
    survived = []
    for name, (fname, old, new) in MUTANTS.items():
        d = os.path.join(work, name.split()[0])
        shutil.copytree(os.path.join(base, "eternax_vault"), os.path.join(d, "eternax_vault"))
        p = os.path.join(d, "eternax_vault", fname)
        src = open(p).read()
        assert src.count(old) == 1, f"{name}: pattern not found exactly once"
        open(p, "w").write(src.replace(old, new))
        failed = run_suites(d)
        caught = bool(failed)
        if not caught:
            survived.append(name)
        print(f"{name:62s} {'CAUGHT by ' + ', '.join(f[0].split('_')[0] + ':' + (f[1][0].split()[0] if f[1] else '?') for f in failed) if caught else 'SURVIVED'}")
    shutil.rmtree(work)
    print(f"mutation score: {len(MUTANTS) - len(survived)}/{len(MUTANTS)}")
    sys.exit(1 if survived or clean else 0)


if __name__ == "__main__":
    main()
