# One-time vault for Bitcoin

Google Quantum AI estimates that a first-generation quantum computer, primed in advance, could break a Bitcoin key about nine minutes after it appears, a chance of slightly under 41% to steal an ordinary spend before the next block confirms it. This script makes it break **a hundred keys** in that window instead.

No fork, no new opcode, no private miner involvement: Bitcoin Core default relay policy accepts it as standard. It works today, a spend costs about 2,759 vbytes, and signing takes milliseconds.

It's making a quantum attacker work harder. 

**It is not quantum-safe.**, it is a work factor, the cheapest speed bump available until Bitcoin can verify post-quantum signatures. That takes more than BIP-360: its Pay-to-Merkle-Root outputs remove Taproot's exposed key-path spend, but a script-path spend still signs with ECDSA or Schnorr and reveals its keys in flight, so a separate post-quantum signature mechanism, such as the hash-based BIP-SHRINCS draft, is needed as well.

> Status: experimental, unaudited. Use small amounts.

## The idea

Google Quantum AI's March 2026 paper (Babbush, Gidney, Drake, Boneh and others) estimates that a first-generation fast-clock machine can precompute ("prime") the first half of Shor's algorithm and then finish a secp256k1 discrete log about nine minutes after a public key appears; from a cold start it takes 18 to 23 minutes. A P2WPKH or P2WSH output reveals its public key only when spent, so the attacker races the next block. The paper puts the odds for a single-key spend at slightly under 41%, assuming no congestion and an attacker able to outbid; e<sup>−9/10</sup> = 40.7% reproduces it.

The same paper notes that the cost of this attack on multi-signature outputs such as P2WSH "increases linearly with the number of signatures required". This repo takes that to the limit. `OP_CHECKMULTISIG` stops at 20 keys. A plain chain of signature checks has no such cap, and Bitcoin Core's default relay policy allows 100 of them in a P2WSH script:

```
witness_script = <pk_1> OP_CHECKSIGVERIFY … <pk_99> OP_CHECKSIGVERIFY <pk_100> OP_CHECKSIG     3,500 bytes
scriptPubKey   = OP_0 <SHA256(witness_script)>                                                34 bytes
witness        = <sig_100> … <sig_1> <witness_script>                                         101 items
```

In miniscript that is `and_v(v:pk(K1),and_v(v:pk(K2),…pk(K100)))`, so Bitcoin Core's own wallet can hold and spend it.

- **At rest**, only a SHA-256 hash is on-chain. No public key exists for a quantum computer to work on.
- **In flight**, the attacker must derive all 100 private keys before the next block.

| Attacker's machines | 1 key | 20 keys | **100 keys** |
|---|---|---|---|
| 1 | 40.7% | 1.5 × 10⁻⁸ | **8 × 10⁻⁴⁰** |
| 5 | 40.7% | 2.7% | **1.5 × 10⁻⁸** |
| 20 | 40.7% | 40.7% | **1.1%** |
| 50 | 40.7% | 40.7% | **16.5%** |
| 100 | 40.7% | 40.7% | **40.7%** |

The model: P = exp(−9·⌈keys/machines⌉/10), with the paper's nine minutes per key on a primed machine and 10-minute blocks. Run `eternax-vault odds` to reproduce it. More quantum machines would make it faster: to get the odds it has against an ordinary spend today, an attacker needs a hundred quantum computers working in parallel.

## Keys stay hidden at rest and cost 100 EC discrete logs in flight

- **At rest:** hides every public key behind SHA-256 until the one spend.
- **In flight:** makes a spend cost an attacker 100 discrete logs instead of one.
- **Cost:** about 13,800 sat at 5 sat/vB (~$11 at $82,700/BTC).
- **Today:** runs on the current network with ordinary tools; Bitcoin Core's wallet can do it on its own.
- **Backup:** the whole vault is one 24-word BIP-39 seed phrase.

## It is a work factor, not post-quantum security

- **Bitcoin itself stays vulnerable.** Only a protocol upgrade makes it post-quantum.
- **Coins already exposed stay exposed:** P2PK, reused addresses and Taproot outputs remain vulnerable until moved.
- **A big enough attacker still wins.** The protection is linear: an attacker with 100 machines, or one machine 100× faster, is back to 41% or worse. The paper notes that doubling a machine's qubits doubles its speed.
- **A reorg reopens the race.** Once a spend is mined, its keys are public, so a reorg of that block lets an attacker try again.

## Measured on Bitcoin Core

Bitcoin Core v31.1, regtest, unmodified node. Full numbers are in [RESULTS.md](RESULTS.md); the raw output is in [results/](results/).

| | Witness script | vsize | Node result |
|---|---|---|---|
| 100-key unlock (1 input, 1 output) | 3,500 B | 2,759 vB | accepted to mempool, mined |

Bitcoin Core's own wallet, given the same descriptor, derives the same address and produces the same spend, so the vault doesn't depend on this code.

**Mainnet:** a 100-key vault [funded](https://mempool.space/tx/b77b3538628e78d7902ffaa4bb90106b3b9b342440e037b05d610993780d1085) and [unlocked](https://mempool.space/tx/397b3672fd908901906802fc02ab3307d43264ca72776329340a2173dc84220c) with 100 signatures in one standard transaction: 2,759 vB, a 2,759-sat fee, mined in block 973,546 by MARA Pool. Details in [RESULTS.md](RESULTS.md#mainnet).

## Quickstart

```bash
python3.12 -m venv .venv && . .venv/bin/activate     # Python 3.10 to 3.12
pip install --require-hashes -r requirements.lock   # coincurve, bip32, mnemonic, pinned by hash
pip install --no-deps -e .
pip install pytest && pytest                        # offline tests
```

Run the whole walkthrough against a local regtest node:

```bash
bitcoind -regtest -daemon -fallbackfee=0.0001
python -m eternax_vault.demo --rpc-cookie ~/.bitcoin/regtest/.cookie
```

## Lock and unlock

```bash
eternax-vault new  --seed-file vault.seed                       # 24-word BIP-39 phrase: write it down, with the path (see Keys)
eternax-vault lock --seed-file vault.seed --network mainnet     # prints a bc1q… address
```

To use a phrase you already have, put its 24 words in the file instead (a dedicated phrase, not your main wallet's). The address is an ordinary P2WSH address: pay it from any wallet or exchange, as many times as you like. To spend, sweep every output at the address in one transaction, listing each as `txid:vout:sats`:

```bash
eternax-vault unlock --seed-file vault.seed --network mainnet \
    --utxo <txid>:<vout>:<sats> --utxo <txid>:<vout>:<sats> \
    --to <destination address> --feerate 5
```

`unlock` prints the signed transaction. Broadcast it from your own node, or pass `--rpc-url http://user:pass@127.0.0.1:8332 --broadcast`. With `--rpc-url`, leave out `--utxo`: the tool asks the node for every confirmed output at the address and sweeps them all, and if you do list outputs, it refuses to leave any behind. The transaction signals replace-by-fee, and re-signing at a higher fee rate reveals nothing new: by then the keys are already in the mempool.

### For meaningful amounts: let Bitcoin Core hold and spend

This tool is the reference implementation, and it's fine for testing and small amounts. For anything that matters, let Bitcoin Core's wallet hold and sign. It keeps keys encrypted on disk and in locked, wiped memory, and it signs with libsecp256k1. You only need this tool once, to produce the descriptor:

```bash
eternax-vault descriptor --seed-file vault.seed --network mainnet --private > vault.desc
bitcoin-cli createwallet vault false true "<wallet passphrase>"     # blank, encrypted descriptor wallet
bitcoin-cli -rpcwallet=vault walletpassphrase "<wallet passphrase>" 60
bitcoin-cli -rpcwallet=vault importdescriptors "[{\"desc\": \"$(cat vault.desc)\", \"timestamp\": \"now\"}]"
bitcoin-cli deriveaddresses "$(cat vault.desc)"                     # the same address `lock` prints
rm vault.desc vault.seed                                            # keep the 24 words on paper
# …receive as many payments as you like, then sweep them all at once:
bitcoin-cli -rpcwallet=vault walletpassphrase "<wallet passphrase>" 60
bitcoin-cli -rpcwallet=vault sendall '["<destination address>"]' null unset 5
```

Core signs all 100 keys, ground to low R, and broadcasts. While the wallet is locked, `sendall` returns an incomplete, unsigned result instead. Import before funding, or use an older timestamp to rescan.

For cold storage, the same descriptor works with PSBTs:
- an online watch-only wallet builds the spend;
- an offline Core wallet holding the private descriptor signs it.

The watch-only wallet then holds all 100 public keys, so keep that machine as private as the phrase.

The descriptor lists the 100 keys individually rather than as one xprv with 100 paths. Core's miniscript sanity check compares keys by deriving them without the private key, which hardened paths don't allow, so it would reject them as duplicates.

## Keys

Every key derives from **one BIP-39 seed phrase** (24 words, no passphrase) along a hardened BIP-32 path:

```
m / 17752' / coin' / slot' / deposit'          coin' = 0' on mainnet, 1' on test networks
```

The words and the path are all you need: any BIP-39 and BIP-32 implementation rebuilds the keys without this code. The derivation uses the `mnemonic` (BIP-39 reference) and `bip32` libraries. A test vector, checked against an independent implementation (embit). The phrase is `abandon` 23 times followed by `art`. It is a public test phrase that anyone can spend from, so never send coins to its address:

```
abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art
```

```
slot 0 key  03a1ded4c4ea289e950e73fdd0883d61d67f4fa989cb0aba6d9a390a47347e8271   (m/17752'/0'/0'/0')
address     bc1q9av9cs3u4433y3jkp97frhd9tpyuf8rtccqnpqtjmzkerv9j0meshqvl4w   (mainnet, deposit 0, 100 keys)
```

- **Hardened is what makes one phrase safe.** An attacker who recovers one key's private half learns nothing about the parent or any sibling, so each key still costs its own discrete log.
- **Never expose an extended public key for an ancestor of the vault path** (`m`, `m/17752'`, `m/17752'/coin'` or `m/17752'/coin'/slot'`). An xpub carries its chain code, and a quantum computer turns its public key into the private key; together they give every hardened key below it. The vault never needs one. Branches of the same seed outside `m/17752'` (a BIP-84 or BIP-86 account, say) are separate hardened subtrees and reveal nothing about the vault, but every wallet a phrase is loaded into is one more place it can leak, so use a dedicated phrase.
- **The purpose is a dedicated `17752'` ("EX").** Vault nodes then never coincide with the account nodes standard wallets (BIP-44/49/84/86) export as xpubs. With purpose `86'`, vault slot s would be the very node a Taproot wallet exports as account s.
- **Write the path down with the words.** `17752'` is this project's own purpose number, not a registered standard, so no wallet will guess it. On the same paper as the 24 words, write `m/17752'/0'/0..99'/deposit'` (mainnet), the deposit indices you used and the key count (100). With that, any BIP-32 library rebuilds the keys even without this repo.
- **One backup for everything: BIP-85 (optional).** A hardware wallet that supports BIP-85 (Coldcard, for one) can derive the vault's 24 words from its own seed, as child phrase *i* at `m/83696968'/39'/0'/24'/i'`. A lost vault paper can then be regenerated on the device, and the child phrase can't be turned back into the master seed. The trade-offs:
  - whoever has the master seed has every vault too;
  - rule 4 now covers the device's master xpub.

Add *i* to the paper with the path. This tool takes the child phrase like any other; never type the master seed into it. For larger amounts, keep the vault phrase independent.

## Rules

1. **Receive many times, spend once.** An address can take any number of payments, and its keys stay hidden until the first spend. That spend puts all 100 public keys on-chain, so `unlock` sweeps every output at the address together, and the address is then retired: anything sent to it later is exposed at rest. Unlock once every deposit has confirmed and no more are on the way. Use `--deposit 1`, `2`, … for new vaults.
2. **Sweep everything.** `unlock` spends every output at the address to one destination. For change, sweep to a fresh vault address.
3. **One vault per transaction.** Each input carries its own 100 signatures, about 2,700 vbytes, so one standard transaction sweeps up to 36 outputs. Don't mix vaults. It adds no work for an attacker, since stealing an input needs only its own vault's keys, and an attacker who breaks one vault could replace the whole transaction while the other vaults' keys sit in the mempool.
4. **Keep the 24 words, the descriptor and the master xpub secret.** The address is a hash and safe to share; the public keys behind it are not, until you spend. That is the same rule as for any P2PKH or P2WPKH address under a quantum threat, applied to 100 keys. The master xpub sits above every vault, so to a quantum computer it is as good as the seed.
5. **Cap the value per vault.** An attacker who can't win the race outright can try to delay your spend by outbidding it, and that costs about one block's worth of fees per block of delay. Keep each vault well below what that delay would cost. Defending is cheap: you re-bid one transaction of about 2,760 vbytes per input while the attacker outbids whole blocks.

## Limits

| Keys | Witness script | vsize | Mempool | In a block |
|---|---|---|---|---|
| 100 | 3,500 B | 2,758 vB | accepted | valid |
| 101 | 3,535 B | 2,786 vB | rejected (`bad-witness-nonstandard`) | valid |
| 201 | 7,035 B | 5,460 vB | rejected (`bad-witness-nonstandard`) | valid |
| 202 | 7,070 B | 5,487 vB | rejected | invalid (`Operation limit exceeded`) |

- **100** is the most Bitcoin Core's default policy relays: it allows 100 witness stack items and a 3,600-byte script.
- **15** is the most Bitcoin Knots relays on its defaults. Its `-maxscriptsize` (1,650 bytes, Core's old scriptSig limit, sized for 15-of-15 P2SH multisig) counts the whole witness, about 107 bytes per key, so v29.2 refuses 16 keys and up with `bad-witness-witness-size` ([RESULTS.md](RESULTS.md)). OCEAN [publishes](https://ocean.xyz/docs/nodepolicy) that its pool runs that version with that setting, so OCEAN won't mine a 100-key unlock. Pools on Core's policy do, and Knots nodes accept the block once it is mined; the hash rate that skips the spend only lengthens the wait for a block.
- **201** is the consensus ceiling (the 201-opcode limit). Anything between 101 and 201 has to be handed to a miner directly, and that miner sees every key before anyone else.

## FAQ

**Is this quantum-safe?**
No. It raises the cost of one specific attack, the race to steal a spend in flight, by a factor of the key count. Real safety needs post-quantum signatures in consensus.

**Why not just use a fresh P2WPKH address?**
That protects at rest, but the spend reveals the key. A primed quantum machine can break it in about nine minutes, which beats a ten-minute block slightly under 41% of the time, by Google's estimate.

**Why not Taproot?**
A Taproot output *is* a public key, visible from the moment the coins arrive. That is exposure at rest, the regime this avoids.

**What about a bigger or faster quantum computer?**
Then this stops helping. The attacker needs about as many machines as there are keys, or one machine that much faster. That's why it's a bridge, not a plan.

**Can I use a Trezor or Ledger?**
Not today, at least not without weakening the design.
- **Trezor** can't sign arbitrary scripts.
- **Miniscript-capable devices** (Ledger, Coldcard and some others) sign only through registered wallet policies (BIP-388). Those are built around an exported xpub with non-hardened keys below it, and an xpub is exactly what this design avoids:
  - **At rest:** it's one public key from which a quantum computer can derive every vault key, with no clock running.
  - **In flight:** if it ever leaks, its chain code turns one broken key into all of its siblings.
- **Registration:** confirming 100 keys on a device screen is impractical, if the firmware accepts that many at all.

What would work is firmware that derives the hardened keys internally and signs a registered chain script without ever exporting an xpub. Until then, use an offline computer with Bitcoin Core.

**How does this relate to QSB?**
- **QSB** does genuine hash-based spending without a fork, with real post-quantum security for the spend. It costs hours of GPU grinding per spend (roughly $60) and a non-standard transaction sent directly through a miner.
- **This** is only a work factor, but Bitcoin Core relays it as standard and it signs in milliseconds.
- Different tools; they can coexist.

**And BIP-360?**
It fixes a different exposure. Pay-to-Merkle-Root outputs drop Taproot's key-path spend, so coins no longer sit behind a visible public key at rest. Script-path spends still use ECDSA or Schnorr, though, so they reveal their keys in flight exactly as today. Closing that gap needs a separate post-quantum signature mechanism, such as the hash-based BIP-SHRINCS draft. Once P2MR and such a signature opcode are both active, sweep each vault into an output that uses them; no vault key will have been exposed at rest along the way.

**What if BIP-361 activates?**
BIP-361 (draft; Jameson Lopp, Christian Papathanasiou, Ian Smith, Joe Ross, Steve Vaile, Pierre-Luc Dallaire-Demers) is a migration plan that depends on a post-quantum signature BIP not yet chosen. It has two phases:
- **Phase A**, about three years after activation, allows only sends from legacy scripts to post-quantum ones. The draft doesn't list output types, but an ECDSA chain in P2WSH almost certainly counts as legacy, so vault addresses would stop accepting payments.
- **Phase B**, two years later, restricts ECDSA and Schnorr spends to a quantum-safe rescue protocol. The draft's example proves knowledge of a parent xpriv through a hardened BIP-32 step. These keys meet that precondition, since every vault key is a hardened child of a parent that is never exposed. But the draft doesn't say custom P2WSH scripts are covered.

So treat Phase A as the time to move out, and don't count on a rescue.

**Isn't a 2.8 kB transaction wasteful?**
It's about $7 at 3 sat/vB, it pays for its own block space, and it's smaller than many inscriptions.

## Related work

- S. Holmes and L. Chen, *Assessment of Quantum Threat to Bitcoin and Derived Cryptocurrencies*, IACR ePrint 2021/967 (2021). Briefly notes multi-signature addresses as a further protection: requiring n signatures (up to 20 in Bitcoin) makes a quantum adversary solve n ECDSA keys within the same unprocessed-transaction window. It also lists one-time addresses, higher fees against delay attacks and spreading funds across addresses, which this design uses too. This implementation extends the multi-signature approach to 100 mandatory signatures using chained `OP_CHECKSIGVERIFY` operations within Bitcoin's standard P2WSH relay limits, with deterministic hardened key derivation and Bitcoin Core wallet compatibility.
- R. Babbush, A. Zalcman, C. Gidney, M. Broughton, T. Khattar, H. Neven, T. Bergamaschi, J. Drake, D. Boneh (Google Quantum AI), *Securing Elliptic Curve Cryptocurrencies against Quantum Vulnerabilities: Resource Estimates and Mitigations*, arXiv:2603.28846 (2026). The source of the threat model, the nine-minute primed attack, the 41% single-key figure (section III.2), and the observation that the attack's cost on multi-signature outputs grows linearly with the number of signatures.
- BIP-360 (draft; Hunter Beast, Ethan Heilman, Isabel Foxen Duke). Pay-to-Merkle-Root: removes the key-path spend but adds no new signature scheme.
- BIP-SHRINCS (draft; SHRINCS Working Group: Mike Casey, conduition, Ethan Heilman, Mikhail Kudinov, Oleksandr Kurbatov, Boris Nagaev, Jonas Nick, remix7531). A semi-stateful hash-based signature scheme whose security rests only on SHA-256: 48-byte public keys, stateful signatures from 548 bytes, a 5,777-byte stateless fallback. Deploying it needs a new output type and further BIPs.
- BIP-361 (draft; Jameson Lopp, Christian Papathanasiou, Ian Smith, Joe Ross, Steve Vaile, Pierre-Luc Dallaire-Demers). Post-quantum migration and legacy-signature sunset, pending a post-quantum signature BIP.
- Together, these are the consensus path this repo is a bridge to.
- A. Levy, *Quantum-Safe Bitcoin Transactions* (QSB), StarkWare, 2026.
- Bitcoin Core `src/policy/policy.h`: the P2WSH limits are "adequate for multisignatures up to n-of-100".

## Institutional version

For custodians, EternaX offers an institutional version: post-quantum (SLH-DSA) approval quorums, enforcement inside the HSM, attestation, and private relay for up to 201 keys. Contact info@eternax.ai.

## License

MIT. See [LICENSE](LICENSE). Not a security proof, not financial advice, no warranty. See [SECURITY.md](SECURITY.md) to report issues.
