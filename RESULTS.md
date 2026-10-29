# Measured results

All figures are measured, not estimated. Raw output: [results/regtest-core-v31.1.json](results/regtest-core-v31.1.json), [results/regtest-knots-v29.2.json](results/regtest-knots-v29.2.json).
Reproduce with `python -m eternax_vault.demo --json-out results/<file>.json` against your own regtest node.

## Bitcoin Core v31.1, regtest (unmodified node)

### Lock and unlock, 100 keys

| | This tool | Bitcoin Core wallet (`importdescriptors` + `sendall`) |
|---|---|---|
| Witness script | 3,500 B | 3,500 B |
| Witness items | 101 | 101 |
| Weight / vsize (1 input, 1 output) | 11,034 WU / 2,759 vB | 11,032 WU / 2,758 vB |
| Mempool (`testmempoolaccept`) | accepted, Core reports 2,759 vB | accepted |
| Mined | yes, 1 confirmation | yes, 1 confirmation |
| Descriptor checksum and address match this tool | — | yes |
| Derive keys, build and sign | 17–46 ms on a laptop | — |

Signatures are ground to low R, as Bitcoin Core's signer does, so sizes repeat to within a vbyte between runs (now and then a signature encodes one byte shorter).

### Several deposits, one unlock

Three payments to one vault address, then `unlock --rpc-url … --broadcast` with no outputs listed. The tool found all three and swept them in one 3-input transaction, 101 witness items per input; accepted and mined. An unlock listing only one of the three was refused before signing. Covered by `tests/test_regtest.py`.

### A payment with change to a fresh vault

One 1 BTC deposit, then `unlock --amount 25000000 --change-deposit 1 --feerate 2 --broadcast`: 0.25 BTC to the payee and 0.74994396 BTC to the vault at deposit 1, in one transaction of 2,802 vB (Core's figure; 43 more than the one-output unlock) with a 5,604-sat fee; accepted and mined. The change vault then unlocked like any other (2,759 vB, mined). Change sent back to deposit 0, the vault being spent, was refused before signing. Covered by `tests/test_regtest.py`.

### Fees for a 2,759-vbyte unlock

| Fee rate | Fee | At $82,700/BTC |
|---|---|---|
| 1 sat/vB | 2,759 sat | $2.28 |
| 5 sat/vB | 13,795 sat | $11.41 |
| 20 sat/vB | 55,180 sat | $45.63 |
| 100 sat/vB | 275,900 sat | $228.17 |

### Key-count limits

| Keys | Witness script | vsize | Mempool | Block built with `generateblock` |
|---|---|---|---|---|
| 100 | 3,500 B | 2,758 vB | accepted | valid |
| 101 | 3,535 B | 2,786 vB | `bad-witness-nonstandard` | valid |
| 201 | 7,035 B | 5,460 vB | `bad-witness-nonstandard` | valid |
| 202 | 7,070 B | 5,487 vB | `bad-witness-nonstandard` | invalid: `Operation limit exceeded` |

## Bitcoin Knots v29.2.knots20251110, regtest (default policy)

Knots is a Bitcoin Core fork with stricter relay policy. OCEAN pool [publishes](https://ocean.xyz/docs/nodepolicy) that it runs this version with `-maxscriptsize` at its default of 1,650.

Binary: `bitcoin-29.2.knots20251110-arm64-apple-darwin.tar.gz` from bitcoinknots.org. Its SHA-256 matches `SHA256SUMS`, which carries good signatures from Luke Dashjr, Léo Haf and ataraxia009 (keys from [bitcoinknots/guix.sigs](https://github.com/bitcoinknots/guix.sigs/tree/main/builder-keys)).

| Keys | Witness script | Witness (serialized) | vsize | Knots mempool |
|---|---|---|---|---|
| 1 | 35 B | 109 B | 113 vB | accepted, mined |
| 10 | 350 B | 1,074 B | 354 vB | accepted, mined |
| 15 | 525 B | 1,609 B | 488 vB | accepted, mined |
| 16 | 560 B | 1,716 B | 515 vB | `bad-witness-witness-size` |
| 20 | 700 B | 2,144 B | 622 vB | `bad-witness-witness-size` |
| 50 | 1,750 B | 5,353 B | 1,424 vB | `bad-witness-witness-size` |
| 100 | 3,500 B | 10,703 B | 2,762 vB | `bad-witness-witness-size` |

**15 keys is the most Knots relays by default.** The cause is `-maxscriptsize`: "Maximum size of scripts (including the entire witness stack) we relay and mine, in bytes (default: 1650)". Each key adds about 107 bytes to the witness: 35 bytes of script, a 71-byte signature and its length byte. The number is Bitcoin Core's limit on a legacy scriptSig (`MAX_STANDARD_SCRIPTSIG_SIZE`), sized for a 15-of-15 P2SH multisig; Knots applies it to the whole witness, and the current `29.x-knots` branch keeps the 1,650 default. Changing the setting confirms it is the cause:
- at 1,600, 15 keys (1,609 B) is refused, so the limit counts the serialized witness, length bytes included;
- at 11,000, 100 keys is accepted and mined, and 101 is refused with `bad-witness-stackitem-count`, as on Core. No other Knots default stands in the way.

A node or pool running Knots defaults will neither relay nor mine a 100-key unlock; nodes on Bitcoin Core's defaults relay it.

The vsizes are 3 vB above the Core run because the Knots demo wallet handed out P2PKH addresses, so the sweep output is 3 bytes longer.

## Signet (public test network)

A rehearsal of the mainnet steps on the public signet. A faucet funded a vault; one 100-key unlock swept it into a second, fresh vault; a second unlock returned the coins to the faucet. Both unlocks were signed with `eternax-vault unlock` and broadcast through mempool.space.

| Step | Transaction | Block | Amount | Size and fee |
|---|---|---|---|---|
| Faucet → vault, deposit 0 | [5a7510ac…e485](https://mempool.space/signet/tx/5a7510acec0e90c9e4870b890484f5e320ec28cc7668e3be1643ee58f987e485) | 328,350 | 10,000 sat | — |
| Unlock: vault 0 → vault 1 | [0bee81a6…2d7a](https://mempool.space/signet/tx/0bee81a63c52fcac329c762295ccc1a5beb4932de379cf8f9b7215d195b42d7a) | 328,351 | 7,229 sat | 2,771 vB, 2,771 sat (1 sat/vB) |
| Unlock: vault 1 → faucet | [1a4602c8…4c0f](https://mempool.space/signet/tx/1a4602c838f3af9d3a0729f2dbc807817b299c0b1b91dbad703775f605a94c0f) | 328,352 | 4,458 sat | 2,771 vB, 2,771 sat (1 sat/vB) |

Each unlock is 11,082 WU with 101 witness items: 100 signatures of 71 bytes and the 3,500-byte script. The two vaults, `tb1qzg8j…t0j93` (deposit 0) and `tb1qktux…6gw45w` (deposit 1), derive from one phrase. Both unlocks are 12 vB larger than the regtest one because they pay a P2WSH vault and a Taproot address, whose output scripts are 12 bytes longer than a P2WPKH one.

## Mainnet

28 October 2026. The vault was funded from an ordinary wallet; the unlock was signed with `eternax-vault unlock` in a Docker container with networking off and broadcast through mempool.space.

| Step | Transaction | Block | Amount | Size and fee |
|---|---|---|---|---|
| Wallet → vault | [b77b3538…1085](https://mempool.space/tx/b77b3538628e78d7902ffaa4bb90106b3b9b342440e037b05d610993780d1085) | 973,544 (Luxor) | 110,000 sat | — |
| Unlock: vault → wallet | [397b3672…220c](https://mempool.space/tx/397b3672fd908901906802fc02ab3307d43264ca72776329340a2173dc84220c) | 973,546 (MARA Pool) | 107,241 sat | 11,034 WU / 2,759 vB, 2,759 sat (1 sat/vB) |

The unlock's witness on-chain: 101 items, 100 signatures of 71 bytes with `SIGHASH_ALL`, and the 3,500-byte script, 99 × `<pubkey> OP_CHECKSIGVERIFY` then `<pubkey> OP_CHECKSIG` over 100 distinct compressed keys. Its SHA-256 matches the vault output. The weight, 11,034 WU, is the same as in the regtest run.

