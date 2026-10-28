"""One BIP-39 seed phrase, one hardened BIP-32 path per key.

    24 words  --BIP-39-->  seed  --BIP-32-->  m / 17752' / coin' / slot' / deposit'

Every level is hardened. A quantum attacker who recovers one key's private half from its
public key learns nothing about the parent or any sibling, so each of the vault's keys
costs a separate discrete logarithm, while the whole vault is backed up as 24 words. Any
BIP-39 and BIP-32 tool can rebuild the keys from the words and the path.

17752' (0x4558, "EX") is a dedicated purpose, so vault nodes never coincide with the account nodes
standard wallets (BIP-44/49/84/86) export as xpubs; with 86', slot s would be BIP-86 account s.
Other branches of the same seed are separate hardened subtrees. What must never be exposed is an
xpub for an ancestor of the vault path (m, m/17752', m/17752'/coin', m/17752'/coin'/slot'): it
carries the chain code, and a quantum computer turns its public key into the private key, which
together give every hardened key below it. The vault never needs one.
"""
from __future__ import annotations

import coincurve
from bip32 import BIP32
from coincurve._libsecp256k1 import ffi, lib
from mnemonic import Mnemonic

from .encoding import b58check_encode
from .network import Network

PURPOSE = 17752
_BIP39 = Mnemonic("english")


def new_mnemonic() -> str:
    """24 English words from 256 bits of OS randomness."""
    return _BIP39.generate(strength=256)


def seed_from_mnemonic(words: str, passphrase: str = "") -> bytes:
    """BIP-39 seed (64 bytes). Rejects anything that is not a valid English BIP-39 phrase."""
    words = " ".join(words.lower().split())
    if not _BIP39.check(words):
        raise ValueError("not a valid BIP-39 phrase (unknown word or bad checksum)")
    return Mnemonic.to_seed(words, passphrase=passphrase)


def vault_secrets(seed: bytes, net: Network, n_keys: int, deposit: int) -> list[bytes]:
    """The n private keys of one vault output, in slot order."""
    root = BIP32.from_seed(seed)
    return [root.get_privkey_from_path(f"m/{PURPOSE}h/{net.coin}h/{slot}h/{deposit}h") for slot in range(n_keys)]


def pubkey(secret: bytes) -> bytes:
    return coincurve.PrivateKey(secret).public_key.format(compressed=True)


def wif(secret: bytes, net: Network) -> str:
    return b58check_encode(bytes([net.wif]) + secret + b"\x01")      # compressed


def sign_low_r(secret: bytes, sighash: bytes) -> bytes:
    """DER ECDSA signature, low S and low R, as Bitcoin Core signs: retry RFC 6979 with a
    counter as extra entropy until R fits in 32 bytes. Keeps signatures at 70 bytes or less."""
    key = coincurve.PrivateKey(secret)
    sig, counter = key.sign(sighash, hasher=None), 0
    while sig[3] > 0x20:                                              # R length 33 = high R
        counter += 1
        ndata = ffi.new("unsigned char[32]", counter.to_bytes(32, "little"))
        sig = key.sign(sighash, hasher=None, custom_nonce=(lib.secp256k1_nonce_function_rfc6979, ndata))
    return sig
