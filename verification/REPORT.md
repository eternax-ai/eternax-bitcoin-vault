# Verification report

EternaX Labs · 13 November 2026

| | |
| --- | --- |
| Code verified | `eternax_vault` at commit [`0e624ed`](https://github.com/eternax-ai/eternax-bitcoin-vault/commit/0e624eddec13d159222697ad00bd524f31ca514c) (`main`, 10 Nov 2026) |
| Reference node | Bitcoin Core v31.1, the signed bitcoincore.org release (hash and 11 of 11 builder signatures checked), on a fresh regtest node |
| Properties | P1–P6 from [SPEC.md](SPEC.md): all six hold; P2, P4 and P6 with stated limits |
| Findings | 3 open, all low. On an earlier commit, 5 more were found and fixed before publication, and 1 was accepted as a design limit |
| Checks on the checks | 9 of 9 negative controls caught; mutation score 16 of 16; internal adversarial review |
| Run | `run_all.sh`, ending `ALL VERIFICATION STEPS PASSED`; log in [results/run_all.log](results/run_all.log) |

## The vault's core properties hold on 0e624ed

Under standard cryptographic assumptions, a 100-key vault can be spent only with all 100 signatures.
Every unlock the tool builds within its documented limits is valid and standard, and Bitcoin Core
mines it. The address commits exactly to the script, and the 24-word seed deterministically rebuilds
every key.

Three low findings remain, all in the tool around the vault script, not in the script itself. None
lets a classical attacker spend without every key, and none locks funds. Each can cancel the vault's
at-rest protection through an operator mistake. The README documents two of them; the third, F8, is
open.

An earlier run, on commit `ccb2603`, found six more. Five, including one medium, were fixed before
this report, and the suite now fails if any of them comes back. The sixth, change sent to a deposit
that was already spent, cannot be caught by a tool that keeps no state; it is listed under limits.

## All six properties hold

P1 and P3 hold without exception over every key count the tool accepts. P2, P4 and P6 hold as
specified but are narrower than an institution would want, and the findings say where.

| Property | Result | Evidence | Strength |
| --- | --- | --- | --- |
| **P1** Only all n signatures spend it | Holds, n = 1–201 | Z3: soundness and completeness of the script under segwit v0 rules and consensus limits, for every n from 1 to 201; honest spends are impossible at n ≥ 202, as in Core. The real script bytes are the modelled program for every n. Core: 32 witness mutations (dropped, swapped, reversed, duplicated, wrong-key, wrong-transaction, empty and re-flagged signatures, wrong script, extra items, no witness) all rejected at consensus (`generateblock`) and by policy | Machine-checked model + consensus differential |
| **P2** Unlocks are valid, standard and pay at least the requested rate | Holds for n ≤ 100 and fee rate ≥ 0.1 sat/vB | Z3: real weight ≤ estimate; paid rate ≥ requested; sigop cost ≤ 16,000 at ≤ 400,000 WU; every per-input policy limit holds for n ≤ 100. 20,000 signatures, all ≤ 71 B. 400 random `build_unlock` calls match an independent model, including the refusals: fee rates under 0.1 sat/vB or non-finite, fees over 0.1 BTC. Non-standard: at 201 keys, 184 inputs build within 4,000,000 WU and 185 are refused. Core: 22 unlocks across 1–100 keys, 1–36 inputs, 0.1–500 sat/vB and both output shapes accepted and mined, with Core's vsize equal to the tool's every time. Largest standard sweep: 36 inputs accepted, 37 refused by the tool | Proof + property-based + consensus differential |
| **P3** Address and descriptor commit to exactly the script | Holds | Exhaustive for n = 1–201: an independent compiler turns the descriptor into exactly the script bytes, and the address round-trips to `OP_0 SHA256(script)`. Core: checksum, derived address and decoded script match for 9 key counts. Core's own wallet spent a 100-key vault given only the private descriptor. Core refuses descriptors above 100 keys, so Core-only recovery covers n ≤ 100 | Exhaustive + differential |
| **P4** Seed → keys → address is deterministic | Holds; key sets overlap across key counts (F6) | BIP-39 Trezor vector. 892 keys match an independent BIP-32 implementation written from the BIP. 40 random paths match Bitcoin Core's own derivation. Indices ≥ 2³¹ or < 0 refused | Differential against two independent implementations |
| **P5** Signatures bind the transaction; value is conserved | Holds | 500 random transactions: the sighash equals an independent BIP-143 implementation byte for byte, and any change to the outputs or the spent amount changes it. Z3: outputs + fee = inputs and outputs ≥ dust, for every fee rate > 0; Z3 also finds the counterexample at ≤ 0, which the code now refuses. Every signature verified in its witness position. Destination decoding agrees with Core on 3,000 valid and corrupted addresses | Proof + property-based + differential |
| **P6** An unlock never pays the vault it spends | Holds as specified; narrower than the goal (F8, change deposits) | 300 random cases: no output ever pays the vault being spent. With node data: a partial sweep is refused, the default sweeps every confirmed output, and a typed amount or outpoint the node does not show is refused before signing | Property-based + CLI tests |

## Three findings remain open, all low

Each is reproduced through the real CLI against Bitcoin Core v31.1 on regtest by
[`findings_repro.py`](findings_repro.py), which fails if any finding's status changes.

| ID | Severity | Finding | Reproduced impact | Recommendation | Status |
| --- | --- | --- | --- | --- | --- |
| F4 | Low | The sweep sees confirmed outputs only. A deposit still in the mempool is left behind and later confirms at the retired address. | 2,000,000 sat left at a spent vault. | Before signing, look in the mempool for unconfirmed outputs paying the vault address, and refuse until they confirm. | Documented in the README |
| F6 | Low | The key path has no key-count level, so vaults with different `--keys` at the same deposit share keys. | The 50-key vault at deposit 0 is exactly the first 50 keys of the 100-key vault at deposit 0, so spending either exposes the other. The test networks also share keys, all using coin type 1′. | Refuse a deposit index already used with another key count, or add the key count to the path under a new path version, keeping the old path for recovery. Sharing coin type 1′ across test networks is normal BIP-44 practice. | Documented in the README |
| F8 | Low | The one-time guard compares exact scriptPubKeys only. | The tool accepted three destinations: P2SH-P2WSH of the vault's own script, P2WPKH of a vault key, and a witness v1 20-byte program that anyone can spend. Core treats all three as valid addresses. | Refuse destination or change outputs that are the P2SH-wrapped vault script, or that pay any vault key as P2PK, P2PKH, P2WPKH or P2TR. Refuse witness versions 2 to 16, and version 1 programs that are not 32 bytes. | Open |

F4, F6 and the first two F8 cases matter only under the README's quantum threat model. Classically,
coins at an exposed vault still need every private key; what these cases cancel is the at-rest
protection the vault exists to provide. The third F8 case is different: anyone can spend an unknown
witness program today. The user chose that destination, and other wallets accept it too under
BIP-350, but an institutional tool should refuse it.

## Five findings were fixed before publication

The first run, on [`ccb2603`](https://github.com/eternax-ai/eternax-bitcoin-vault/commit/ccb2603a548606d29be7b8f43140d516007a692b)
(29 Oct 2026), also found these five. Each fix is in
[PR #3](https://github.com/eternax-ai/eternax-bitcoin-vault/pull/3). `findings_repro.py` checks that each is
now refused, and mutants M13–M16 show the offline suites would catch each fix being undone.

| ID | Severity on `ccb2603` | Issue | Fixed in |
| --- | --- | --- | --- |
| F7 | Medium | No fee ceiling: at 20,000 sat/vB the tool signed a 0.55 BTC fee on 1 BTC | [`3296e28`](https://github.com/eternax-ai/eternax-bitcoin-vault/commit/3296e28): fees over 0.1 BTC refused unless `--max-fee` raises the ceiling |
| F1 | Low | A fee rate of zero or less, or under the 0.1 sat/vB relay floor, was signed: no node relays the result, but the printed hex exposes every key | [`209b3dd`](https://github.com/eternax-ai/eternax-bitcoin-vault/commit/209b3dd) |
| F9 | Low | Amounts typed in `--utxo` overrode the node's value | [`18eefc3`](https://github.com/eternax-ai/eternax-bitcoin-vault/commit/18eefc3): with `--rpc-url`, listed outputs and amounts must match the node |
| F3 | Info | A negative `--amount` or `--feerate inf` crashed with a traceback | [`209b3dd`](https://github.com/eternax-ai/eternax-bitcoin-vault/commit/209b3dd) |
| F5 | Info | With `--allow-nonstandard` there was no cap at the 4,000,000 WU block weight | [`870c0b5`](https://github.com/eternax-ai/eternax-bitcoin-vault/commit/870c0b5) |

The scripts and raw results of the `ccb2603` run are in this folder's history, in the commit that added it.

## Three kinds of evidence back each property

Each property rests on a proof, an independent re-implementation, and Bitcoin Core as the
reference. The checks were then tested themselves.

**Toolchain**

- Python 3.12.11, with every dependency installed with `--require-hashes` from
  [requirements.lock](requirements.lock). It pins the vault's own dependencies at the same hashes as
  the top-level lock.
- Z3 5.3.3 (`z3-solver` 5.3.3.0) for proofs, Hypothesis 6.168.5 for property-based tests, and `ecdsa`
  0.19.2 for an independent secp256k1.
- Bitcoin Core v31.1 for arm64 macOS, `bitcoin-31.1-arm64-apple-darwin.tar.gz` from
  [bitcoincore.org](https://bitcoincore.org/bin/bitcoin-core-31.1/). The tarball's SHA-256 matched
  `SHA256SUMS`, and all 11 detached signatures on `SHA256SUMS` verified against the builder keys in
  [bitcoin-core/guix.sigs](https://github.com/bitcoin-core/guix.sigs/tree/main/builder-keys), with
  both `gpg` and [`verify_sigs.py`](verify_sigs.py). The `bitcoind` binary's SHA-256 is
  `d55c12b0b02001cc16b1481c4075361dcba193100a8143924abda911174c09ec`. It ran unmodified on a fresh
  regtest node with default policy: 0.1 sat/vB minimum relay fee and 3 sat/vB dust relay fee.

**Methods**

1. **Proof (Z3).** A model of segwit v0 script execution for the three opcodes the vault uses,
   including the clean-stack rule and the consensus limits on script size, operation count and stack
   depth. Signature checking is an uninterpreted predicate, so the result holds whatever the
   signature check does. Further proofs cover the transaction weight, fee and value arithmetic.
2. **Independent re-implementation.** BIP-143 sighash, BIP-32 derivation, miniscript compilation and
   DER parsing, written fresh from the BIP texts. The tool's output was compared with them on random
   and exhaustive inputs.
3. **Bitcoin Core differential.** Core judged every artifact the tool produces: `testmempoolaccept`
   for policy, and `generateblock` without submitting for consensus. Core also checked descriptors
   and derivation (`getdescriptorinfo`, `deriveaddresses`) and addresses (`validateaddress`), and
   Core's own wallet spent a vault from its descriptor.
4. **The repository's own tests.** All 43 pass, offline and on regtest.

**Checks on the checks**

- **Negative controls (9 of 9 caught).** Two deliberately broken script variants, each at 3 key
  counts, must produce counterexamples, and do. At 202, 203 and 250 keys, honest spends must be
  impossible under the consensus limits, and are. A model that proved everything would fail these.
- **Mutation testing (16 of 16 caught).** Sixteen realistic bugs were planted one at a time in copies
  of the code, and the suite failed on every one: CHECKSIG instead of CHECKSIGVERIFY, spent amount
  dropped from the sighash, fee rounded down, the vault guard removed, placeholder signature one byte
  short, unhardened path level, reversed descriptor keys, unreversed witness, fee taken twice,
  partial-sweep check removed, duplicate-key check removed, coin type ignored, and the four fixes for
  F1/F3, F7, F5 and F9 each removed.
- **Adversarial review.** A separate reviewer with no stake in the results examined the suite on
  `ccb2603` and raised eight points. Each was resolved as follows.

| Reviewer's point | Resolution |
| --- | --- |
| The model lacked consensus limits, so "n ≤ 201" came from the loop, not the proof | Fixed: limits added to the model, boundary controls at 202–250 keys, and Core consensus checks at 101, 201 and 202 keys |
| P1 abstracts the signature check | Accepted: P1 is presented as a model proof tied to the real bytes and backed by 32 consensus-level Core rejections |
| Vaults with different key counts share keys | Confirmed and reproduced: F6 |
| No fee ceiling | Confirmed and reproduced: F7, since fixed |
| The one-time guard checks exact scriptPubKeys only | Confirmed and reproduced: F8 |
| User amounts override the node's; some arguments crash | Confirmed: F9 and F3, since fixed. The claimed crash on a negative output index did not reproduce; the tool refused it cleanly |
| Some checks restate the code | Accepted: test ranges widened, and each property's evidence strength is labelled in the results |
| Properties were stated without their conditions | Fixed: the results state each condition |

No independent third-party firm has reviewed this work.

## The results stop at these limits

They hold only under assumptions A1–A7 in [SPEC.md](SPEC.md), none of which is proven here, and each of
which is standard for Bitcoin software.

- **Not post-quantum security.** A quantum adversary breaks A1. The README's work-factor claim, 100
  discrete logs per spend, depends on the P1 structure proven here, but the timing and odds model is
  physics, not code, and is out of scope.
- **The Z3 interpreter is a hand-written model** of Bitcoin Core's script execution for three opcodes.
  Its fidelity rests on 32 consensus-level differential tests against Core (see P1), not on a proof
  against Core's C++ source.
- **Exhaustive means bounded.** P1 and P3 are complete over every key count the tool accepts,
  n = 1–201. Weight and fee arithmetic is proven for the configurations listed, plus property-based
  tests of up to 40 inputs.
- **Change can go to a deposit that was already spent.** The `ccb2603` run reported this as F2,
  medium: `--change-deposit` may name a deposit whose vault was spent before, and the tool sends the
  change there with a warning. It keeps no record of past unlocks by design, so it cannot know, and
  `findings_repro.py` no longer checks it. Change at a spent deposit sits behind public keys, which is
  why the README tells users to keep the indices they have used with the 24 words and to take change
  above all of them.
- **Not covered:** memory hygiene and side channels (Python cannot wipe secrets, as `SECURITY.md`
  says), RPC transport security, the `demo.py` and `odds.py` modules, and user procedures for storing
  the seed.

## One command reproduces every result

From the repository root, with a Bitcoin Core regtest node running (commands in
[README.md](README.md)):

```bash
PY=.venv/bin/python ./verification/run_all.sh
```

It exits non-zero on any failure. This run ended with `ALL VERIFICATION STEPS PASSED` after 18.5
minutes. Raw outputs are in [results/run_all.log](results/run_all.log),
[results/core_differential.json](results/core_differential.json) and
[results/findings_repro.json](results/findings_repro.json).

## Four items remain open

- **F8:** widen the one-time guard as recommended above.
- **F4:** check the mempool before sweeping, or keep the README rule as the only safeguard.
- **CI:** run the offline suites on every commit.
- **Review:** an independent review of the suite and of [SPEC.md](SPEC.md).
