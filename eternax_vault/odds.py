"""In-flight attack model.

An attacker with `machines` quantum computers, each breaking one key in `minutes_per_key`,
must recover all n keys before the next block. Blocks arrive as a Poisson process, so

    T = minutes_per_key * ceil(n / machines)          (keys split across machines)
    P = exp(-T / block_minutes)                        (no block arrives within T)

Nine minutes per key is the single-key time for a primed machine in Google Quantum AI's paper
(arXiv:2603.28846, section II.2); with it a single key gives e^-0.9 = 40.7%, matching the paper's
"slightly less than 41%" (section III.2, which assumes no congestion and an attacker able to outbid).
This is a work factor, not unforgeability: it falls back to 40.7% once machines >= n, or once one
machine is n times faster, and goes higher still when spare machines split a key (the paper's eleven
primed machines give a 6.5x speedup on one key).
"""
from __future__ import annotations

import math


def attack_odds(n_keys: int, machines: int = 1, minutes_per_key: float = 9.0, block_minutes: float = 10.0) -> float:
    return math.exp(-minutes_per_key * math.ceil(n_keys / machines) / block_minutes)
