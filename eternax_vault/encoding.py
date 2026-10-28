"""Address and key encodings: base58check (BIP-13/WIF), bech32 and bech32m (BIP-173, BIP-350).

The bech32 code follows the reference implementation in BIP-350.
"""
from __future__ import annotations

import hashlib

from .network import Network

B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
BECH32M_CONST = 0x2BC830A3


def _checksum4(payload: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]


def b58check_encode(payload: bytes) -> str:
    data = payload + _checksum4(payload)
    n, out = int.from_bytes(data, "big"), ""
    while n:
        n, r = divmod(n, 58)
        out = B58_ALPHABET[r] + out
    return "1" * (len(data) - len(data.lstrip(b"\0"))) + out


def b58check_decode(s: str) -> bytes:
    n = 0
    for c in s:
        if c not in B58_ALPHABET:
            raise ValueError("invalid base58 character")
        n = n * 58 + B58_ALPHABET.index(c)
    data = n.to_bytes((n.bit_length() + 7) // 8, "big")
    data = b"\0" * (len(s) - len(s.lstrip("1"))) + data
    payload, check = data[:-4], data[-4:]
    if len(data) < 5 or _checksum4(payload) != check:
        raise ValueError("bad base58 checksum")
    return payload


def _polymod(values: list[int]) -> int:
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if (top >> i) & 1 else 0
    return chk


def _hrp_expand(hrp: str) -> list[int]:
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _convertbits(data, frombits: int, tobits: int, pad: bool = True):
    acc, bits, out, maxv = 0, 0, [], (1 << tobits) - 1
    for value in data:
        if value < 0 or value >> frombits:
            return None
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            out.append((acc >> bits) & maxv)
    if pad and bits:
        out.append((acc << (tobits - bits)) & maxv)
    elif not pad and (bits >= frombits or ((acc << (tobits - bits)) & maxv)):
        return None
    return out


def segwit_encode(hrp: str, version: int, program: bytes) -> str:
    const = 1 if version == 0 else BECH32M_CONST
    data = [version] + _convertbits(program, 8, 5)
    poly = _polymod(_hrp_expand(hrp) + data + [0] * 6) ^ const
    checksum = [(poly >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(BECH32_CHARSET[d] for d in data + checksum)


def segwit_decode(hrp: str, addr: str) -> tuple[int, bytes]:
    if addr.lower() != addr and addr.upper() != addr:
        raise ValueError("mixed-case bech32 address")
    addr = addr.lower()
    pos = addr.rfind("1")
    if pos < 1 or pos + 7 > len(addr) or len(addr) > 90 or addr[:pos] != hrp:
        raise ValueError(f"not a {hrp}1… segwit address")
    if any(c not in BECH32_CHARSET for c in addr[pos + 1:]):
        raise ValueError("invalid bech32 character")
    data = [BECH32_CHARSET.find(c) for c in addr[pos + 1:]]
    const = _polymod(_hrp_expand(hrp) + data)
    version, program = data[0], _convertbits(data[1:-6], 5, 8, False)
    if program is None or not 2 <= len(program) <= 40 or version > 16:
        raise ValueError("invalid witness program")
    if version == 0 and len(program) not in (20, 32):
        raise ValueError("invalid v0 witness program length")
    if const != (1 if version == 0 else BECH32M_CONST):
        raise ValueError("bad bech32 checksum")
    return version, bytes(program)


def p2wsh_address(witness_script: bytes, net: Network) -> str:
    return segwit_encode(net.hrp, 0, hashlib.sha256(witness_script).digest())


def address_to_script_pubkey(addr: str, net: Network) -> bytes:
    """scriptPubKey for any standard address on `net` (P2PKH, P2SH, P2WPKH, P2WSH, P2TR and later)."""
    if addr.lower().startswith(net.hrp + "1"):
        version, program = segwit_decode(net.hrp, addr)
        return bytes([0x50 + version if version else 0, len(program)]) + program
    payload = b58check_decode(addr)
    if len(payload) == 21 and payload[0] == net.p2pkh:
        return b"\x76\xa9\x14" + payload[1:] + b"\x88\xac"
    if len(payload) == 21 and payload[0] == net.p2sh:
        return b"\xa9\x14" + payload[1:] + b"\x87"
    raise ValueError(f"not a {net.name} address: {addr}")
