"""Output descriptors (BIP-380/381/382, miniscript) so Bitcoin Core can hold and spend a vault.

The vault is wsh(and_v(v:pk(K1),and_v(v:pk(K2),…pk(Kn)))). Each key is written out
individually rather than as xprv/path: Bitcoin Core's miniscript sanity check compares keys
by deriving them without the private key, which fails for hardened paths, so 100 hardened
children of one xprv are rejected as "duplicate public keys". Individual keys avoid that.
"""
from __future__ import annotations

from .keys import pubkey, wif
from .network import Network

INPUT_CHARSET = "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ "
CHECKSUM_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _polymod(symbols: list[int]) -> int:
    gen = [0xF5DEE51989, 0xA9FDCA3312, 0x1BAB10E32D, 0x3706B1677A, 0x644D626FFD]
    chk = 1
    for v in symbols:
        top = chk >> 35
        chk = (chk & 0x7FFFFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if (top >> i) & 1 else 0
    return chk


def checksum(desc: str) -> str:
    """BIP-380 descriptor checksum."""
    symbols, groups = [], []
    for c in desc:
        v = INPUT_CHARSET.find(c)
        if v < 0:
            raise ValueError(f"invalid descriptor character {c!r}")
        symbols.append(v & 31)
        groups.append(v >> 5)
        if len(groups) == 3:
            symbols.append(groups[0] * 9 + groups[1] * 3 + groups[2])
            groups = []
    if len(groups) == 1:
        symbols.append(groups[0])
    elif len(groups) == 2:
        symbols.append(groups[0] * 3 + groups[1])
    c = _polymod(symbols + [0] * 8) ^ 1
    return "".join(CHECKSUM_CHARSET[(c >> (5 * (7 - i))) & 31] for i in range(8))


def _chain(keys: list[str]) -> str:
    expr = f"pk({keys[-1]})"
    for k in reversed(keys[:-1]):
        expr = f"and_v(v:pk({k}),{expr})"
    return expr


def vault_descriptor(secrets: list[bytes], net: Network, private: bool) -> str:
    """With private=True the descriptor carries the WIF keys: Bitcoin Core can then sign.
    Either form reveals all public keys, which the vault keeps hidden until it spends."""
    keys = [wif(s, net) if private else pubkey(s).hex() for s in secrets]
    desc = f"wsh({_chain(keys)})"
    return f"{desc}#{checksum(desc)}"
