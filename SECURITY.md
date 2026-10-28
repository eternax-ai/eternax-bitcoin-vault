# Security

This is experimental, unaudited software. Use small amounts.

**It claims only the README's at-rest and in-flight properties,** at the strength stated there: a work factor against a quantum attacker racing a spend, not post-quantum security.

**These must stay private:**
- the 24-word seed phrase (the seed file);
- any `--private` descriptor;
- every vault's public keys, until that vault is spent. This is the same rule as for any P2PKH or P2WPKH address under a quantum threat: the address is only a hash, and the public key behind it is what a quantum computer needs. A vault has 100 of them, and the plain descriptor lists them all;
- the master extended public key (xpub), and any xpub on the vault path (`m/17752'`, `m/17752'/coin'`, `m/17752'/coin'/slot'`). Every vault key derives from one seed, and an xpub carries a public key and a chain code. Classically that is harmless for hardened children. Against a quantum computer it is not: the public key becomes the private key, and with the chain code that gives every hardened key below it. The master xpub is the worst case, since it sits above every vault. This tool never produces an xpub; don't load the phrase into wallet software that might show or export the master xpub. The master fingerprint (4 bytes of a hash) is harmless.

## Limits of this implementation

- **Secrets stay in memory.** Python cannot reliably erase the phrase, the seed or the private keys from memory; they remain in the process until it exits and can reach swap. Run the tool on a machine you trust, ideally offline. Bitcoin Core's wallet keeps keys in locked memory and wipes them, which is one reason the README recommends it for meaningful amounts.
- **Constant time.** Operations on secret values run in compiled code:
  - signing, public-key derivation and BIP-32 child-key arithmetic in libsecp256k1, Bitcoin Core's library, via `coincurve`;
  - the HMACs and BIP-39's PBKDF2 in Python's standard library, which is C.

  Python itself only moves secrets around and checks the phrase's checksum. A timing attack on that would need an attacker running code on the same machine.
- **The phrase file is plain text.** `new` writes it with mode 600, but anyone who can read it can spend. Write the words down, and delete the file once the vault is set up.
- **Supply chain.** Three direct dependencies: `coincurve` (which ships a compiled libsecp256k1), `bip32` and `mnemonic`. They are pinned with SHA-256 hashes in `requirements.lock`; install with `pip install --require-hashes -r requirements.lock` so a tampered package is refused.
- **Not audited.** The transaction and signature-hash code is checked against Bitcoin Core in the regtest tests (a wrong signature hash would be rejected by the node), and the encodings against published BIP test vectors. That is not an audit.

## Reporting

To report a vulnerability, email info@eternax.ai with the subject "eternax-bitcoin-vault security". Please don't open a public issue for anything that could put funds at risk.
