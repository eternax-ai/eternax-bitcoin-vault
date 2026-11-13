# Verification specification

This spec defines six properties the vault must satisfy and how each one is checked. Together they
answer the three questions an institution asks first: can someone else spend it, can we always
spend it, and can we rebuild it from the seed. [REPORT.md](REPORT.md) gives the results on one
commit, and [README.md](README.md) says how to re-run them.

| | |
| --- | --- |
| Code under verification | The `eternax_vault` package in this repository (MIT); the report names the commit |
| Modules in scope | `script.py`, `descriptor.py`, `keys.py`, `tx.py`, `encoding.py`, `network.py`, and the guards in `cli.py` (`unlock`, `lock`, `new`) |
| Default configuration | n = 100 keys, P2WSH, mainnet coin type 0, Bitcoin Core v31 default relay policy |
| Audience | Institutional risk and custody teams, independent reviewers, the authors |

The spec covers only what the code does. It adds no features and claims nothing the code does not
implement. Any later commit needs the checks re-run.

## The vault is one P2WSH output with a chain of n signature checks

Every key derives from one BIP-39 seed. The checks reason about the objects below, named as they
appear in the code.

| Symbol | Definition | Code |
| --- | --- | --- |
| `W` | 24-word BIP-39 phrase; `seed = PBKDF2(W, passphrase)`, 64 bytes | `keys.seed_from_mnemonic` |
| `sk_i` | Private key i: the BIP-32 child at `m/17752'/coin'/i'/d'` for slot i = 0…n−1 and deposit d, every level hardened | `keys.vault_secrets` |
| `pk_i` | 33-byte compressed public key of `sk_i` | `keys.pubkey` |
| `WS` | Witness script `<pk_0> CHECKSIGVERIFY … <pk_{n−2}> CHECKSIGVERIFY <pk_{n−1}> CHECKSIG`, 35·n bytes | `script.chain_script` |
| `SPK` | `OP_0 <SHA256(WS)>`, 34 bytes | `script.p2wsh_script_pubkey` |
| `D` | Descriptor `wsh(and_v(v:pk(K_0),…pk(K_{n−1})))#checksum` | `descriptor.vault_descriptor` |
| `σ_i` | Low-S, low-R DER ECDSA signature by `sk_i` over the BIP-143 SIGHASH_ALL digest, plus the byte `0x01` | `keys.sign_low_r`, `tx.sighash` |
| `wit` | Witness stack `[σ_{n−1}, …, σ_0, WS]`: n + 1 items, `σ_0` on top | `tx.build_unlock` |
| `T` | Unlock transaction: every listed output of one vault as inputs; as outputs, one destination, or a payment plus change to a fresh deposit d′ | `tx.build_unlock`, `cli.cmd_unlock` |

Script execution, for reference:

```
Eval(WS, wit) = true  ⇔  Verify(pk_i, σ_i, sighash_BIP143(T, WS)) for every i in 0…n−1,  and  |wit| = n + 1
```

Each `CHECKSIGVERIFY` pops one signature and aborts on failure; the final `CHECKSIG` leaves the
result. The checks model only the opcodes this script uses (33-byte pushes, `OP_CHECKSIGVERIFY`,
`OP_CHECKSIG`) under segwit v0 rules: NULLFAIL, low-S and the clean stack.

## Six properties, each tied to the code and a method

| ID | Property | Risk it removes | Method |
| --- | --- | --- | --- |
| P1 | Only all n signatures spend it | Theft | Z3 proof over a script model, tied to the real script bytes; Bitcoin Core differential |
| P2 | A correct unlock is always valid and standard | Funds stuck | Z3 proofs of the size and fee arithmetic; property-based tests; Bitcoin Core differential |
| P3 | Address and descriptor commit to exactly `WS` | Unrecoverable or wrong address | Exhaustive check with an independent compiler; Bitcoin Core differential |
| P4 | Seed → keys → address is deterministic and injective per slot | Loss after software failure | BIP vectors; independent BIP-32; Bitcoin Core's derivation |
| P5 | Signatures bind the outputs; value is conserved | Redirected or burned funds | Z3 proof of the value equations; independent BIP-143; Bitcoin Core differential |
| P6 | An unlock never sends funds back to the vault it exposes | Key reuse after exposure | Property-based tests of the guard; CLI tests with node data |

### P1: spending soundness

- **Statement.** For every n from 1 to 201 and every transaction T: if `Eval(WS, wit)` succeeds
  under segwit v0 rules, then `wit = [σ_{n−1}, …, σ_0, WS]` and `Verify(pk_i, σ_i, sighash(T, WS))`
  holds for every i. Conversely, n valid signatures in that order succeed.
- **Also.** `WS` has no branch or alternative path, and the only witness script accepted for `SPK`
  is `WS` (SHA-256 second-preimage resistance, A2).
- **Meaning.** No subset, reordering, duplicate or substitute signature spends the vault. An
  attacker must forge, or recover, all n keys.
- **Code.** `script.chain_script`.
- **Method.** Model the three opcodes and the consensus limits on script size, operation count and
  stack depth, with the signature check as an uninterpreted predicate. Prove soundness and
  completeness with Z3 for each n from 1 to 201, against a witness of any length and content. Check
  that the real script bytes are the modelled program for every n. Check that the upper bound comes
  from the model: an honest spend must be impossible at n ≥ 202.

### P2: liveness, no stuck funds

- **Statement.** If `build_unlock` returns T without error, then T is consensus-valid and passes
  Bitcoin Core v31 default policy: `|WS| = 35n ≤ 3,600` bytes, at most 100 stack items besides
  `WS`, at most 201 opcodes, `weight(T) ≤ 400,000` WU, every output at or above its dust
  threshold, and sigop cost within the standard limit.
- **Fee bound.** Every real signature is at most 71 bytes with the sighash byte, so the final
  `vsize(T)` is at most the placeholder estimate, and the paid fee rate is at least the requested
  `feerate`.
- **Refusals.** `build_unlock` refuses a fee rate under 0.1 sat/vB (Bitcoin Core's default relay
  minimum) or not finite, and a fee above `max_fee`, by default 10,000,000 sat (0.1 BTC, Core's
  default `-maxtxfee`). With `standard=False` (`--allow-nonstandard`) it refuses any T over the
  4,000,000 WU block weight. Each refusal comes before signing.
- **Meaning.** The tool never produces a transaction that the network would refuse, or that could
  never be mined, and it never under-pays its own fee estimate.
- **Code.** `script.limits`, `tx.build_unlock`, `keys.sign_low_r`.
- **Method.** Z3 proofs over the size and fee arithmetic. Property-based tests that tie
  `build_unlock` to an independent model, including the refusals. `testmempoolaccept` and mining on
  regtest for 1 to 100 keys and 1 to 36 inputs.

### P3: commitment correctness

- **Statement.** `SPK = 0x00 ‖ 0x20 ‖ SHA256(WS)`, the bech32 address decodes to `SPK`, and
  expanding descriptor `D` yields exactly `WS`, for every n from 1 to 201.
- **Meaning.** The address you fund is the script you can spend. Bitcoin Core's own wallet can spend
  it from `D` without this tool for n ≤ 100; Core refuses descriptors with more keys.
- **Code.** `script.p2wsh_script_pubkey`, `descriptor._chain`, `descriptor.checksum`, `encoding`.
- **Method.** An independent compiler for the miniscript fragments the vault uses, run on the tool's
  descriptor for every n from 1 to 201. Address round trips on three networks. Core's
  `getdescriptorinfo`, `deriveaddresses` and `validateaddress`, and a spend by Core's wallet.

### P4: deterministic derivation

- **Statement.** `vault_secrets(seed, net, n, d)` is a pure function: for a fixed seed it returns
  the same list on every run. Paths for distinct (slot, deposit) pairs are distinct, and mainnet
  (coin 0) and the test networks (coin 1) never share a path. A deposit index outside 0…2³¹−1 is
  refused. Any duplicate public key makes `chain_script` raise, so a returned vault has n distinct
  keys.
- **Meaning.** The 24 words plus the path `m/17752'/coin'/0..n−1'/d'` are a complete backup; any
  BIP-32 tool rebuilds the same address.
- **Code.** `keys.seed_from_mnemonic`, `keys.vault_secrets`, `script.chain_script`.
- **Method.** The official BIP-39 vector. An independent BIP-32 implementation written from the BIP.
  Bitcoin Core's own derivation. A path-injectivity check across slots, deposits and coin types.

### P5: transaction integrity

- **Statement.** `tx.sighash` equals BIP-143 SIGHASH_ALL byte for byte, so every `σ_i` commits to
  all inputs, the spent amount, `WS`, every output and the locktime. For the returned T:
  `Σ outputs + fee = Σ inputs`, `fee = ⌈vsize_est · feerate⌉`, all amounts are non-negative 64-bit
  integers, and each listed outpoint appears once.
- **Meaning.** A signed unlock cannot be changed to pay someone else, and no value goes missing
  beyond the stated fee.
- **Code.** `tx.UnlockTx.sighash`, `tx.build_unlock`.
- **Method.** Z3 proof of the value equations. An independent BIP-143 implementation compared byte for
  byte, and signatures verified in Bitcoin Core. The repository's tests cover a listed outpoint
  repeated.

### P6: one-time use

- **Statement.** `build_unlock` raises if `SPK` of the vault being spent equals the destination or
  the change output. With RPC, `cmd_unlock` refuses to proceed unless every confirmed output at the
  vault address is listed, and refuses a listed output, or a typed amount, that the node does not
  show at the vault.
- **Meaning.** Once a spend reveals the vault's keys, no funds are sent back to it, and no confirmed
  funds are left behind at it.
- **Code.** `tx.build_unlock` guard, `cli.cmd_unlock`.
- **Method.** Property-based tests of the guard. CLI tests against a stub node and against Bitcoin
  Core.
- **Boundary.** The guard compares exact scriptPubKeys, so other scripts built from the vault's keys
  get through (F8 in the report). The tool keeps no record of past unlocks, so it cannot tell whether
  the change deposit d′ was spent before, and with RPC it sees confirmed outputs only. The
  repository README sets the user's rules for both.

## The results rest on seven standard assumptions

None of them is proven here, and each is standard for Bitcoin software.

| ID | Assumption | Relied on by |
| --- | --- | --- |
| A1 | ECDSA over secp256k1 is existentially unforgeable against classical adversaries | P1, P5 |
| A2 | SHA-256 is second-preimage and collision resistant | P1, P3, P5 |
| A3 | HMAC-SHA512 (BIP-32) and PBKDF2 (BIP-39) behave as specified | P4 |
| A4 | Bitcoin Core v31 implements consensus and default policy as modelled: opcode semantics, BIP-143, limits | P1, P2, P5 |
| A5 | `coincurve` (libsecp256k1), `bip32` and `mnemonic` correctly implement their BIPs, at the hashes pinned in `requirements.lock` | P4, P5 |
| A6 | The OS random source behind `new_mnemonic` gives 256 bits of entropy | P1 in practice |
| A7 | Without RPC, the outputs the user lists (txid, vout, amount) match the chain; with RPC, the tool checks them against the node | P2, P5 |

A quantum adversary breaks A1. The README's claim is narrower: the vault raises the work, it does not
make theft impossible. That claim sits outside these checks.

## Six areas sit outside the checks

They get review, tests or a stated caveat instead.

- **The quantum work-factor claim.** The odds table and `odds.py` follow a model from Google Quantum
  AI's March 2026 estimate. The arithmetic can be checked; the physical assumptions cannot be proven.
- **Entropy quality.** Seed randomness comes from the OS (A6); review only.
- **RPC, network and demo code.** `rpc.py`, `demo.py` and the I/O in `cli.py` are covered by the
  regtest tests, not by proofs.
- **Memory and side channels.** Python cannot wipe secrets from memory, as `SECURITY.md` states.
  Constant-time behaviour rests on libsecp256k1 (A5).
- **Operational security.** Storing the seed, keeping public keys and descriptors private, and never
  exporting an xpub on the vault path are user procedures, not code properties.
- **Mempool and reorg races.** Once an unlock is broadcast its keys are public; replacement and reorg
  risk belong to the threat model, not to correctness.

## Each property maps to scripts in this folder

The work passes when every check passes on the commit under review and every differential agrees
with Bitcoin Core. An independent review of the checks and of this spec has not yet taken place.

| Property | Checks |
| --- | --- |
| P1 | `p1_spend_soundness.py`; `core_differential.py` (witness mutations, 101/201/202-key boundary) |
| P2 | `p2_p5_tx_proofs.py` P2.1–P2.7; `core_differential.py` (unlocks accepted and mined) |
| P3 | `p3_p4_p6_checks.py` P3.1–P3.2; `core_differential.py` (descriptors, Core's wallet) |
| P4 | `p3_p4_p6_checks.py` P4.1–P4.4 |
| P5 | `p2_p5_tx_proofs.py` P5.1–P5.5; `core_differential.py` (signatures, address decoding) |
| P6 | `p3_p4_p6_checks.py` P6.1–P6.3 |

`findings_repro.py` checks each finding against its expected status, and `mutation_test.py` checks
that the suite fails on planted bugs. `run_all.sh` runs all of it with the repository's own tests.

## Four scope decisions

- **Change deposits.** The tool stays stateless. P6 does not cover a change deposit that was already
  spent; the README tells users to record used indices with the 24 words.
- **Key counts.** n ≤ 100 is the supported standard configuration. P1 and P3 also cover the
  non-standard range from 101 to 201 keys.
- **Node versions.** P2 is checked against Bitcoin Core v31.1. Bitcoin Knots relays at most 15 keys
  on its defaults; the README and `RESULTS.md` record that separately.
- **Review.** No independent reviewer has been named yet.
