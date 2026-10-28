"""Network parameters: address prefixes, WIF prefix, and the BIP-44-style coin type used in key paths."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Network:
    name: str
    hrp: str            # bech32 human-readable part
    coin: int           # coin' level of the key path: 0 on mainnet, 1 on every test network
    wif: int            # WIF private key prefix
    p2pkh: int          # base58 address version bytes
    p2sh: int


_TEST = dict(coin=1, wif=0xEF, p2pkh=0x6F, p2sh=0xC4)

NETWORKS = {
    "mainnet": Network("mainnet", "bc", coin=0, wif=0x80, p2pkh=0x00, p2sh=0x05),
    "testnet": Network("testnet", "tb", **_TEST),
    "testnet4": Network("testnet4", "tb", **_TEST),
    "signet": Network("signet", "tb", **_TEST),
    "regtest": Network("regtest", "bcrt", **_TEST),
}


def get(name: str) -> Network:
    try:
        return NETWORKS[name]
    except KeyError:
        raise ValueError(f"unknown network {name!r}; choose one of {', '.join(NETWORKS)}") from None
