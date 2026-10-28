"""The vault script: an n-of-n chain of signature checks inside P2WSH.

    witness_script = <pk_1> OP_CHECKSIGVERIFY … <pk_n-1> OP_CHECKSIGVERIFY <pk_n> OP_CHECKSIG
    scriptPubKey   = OP_0 <SHA256(witness_script)>
    witness        = <sig_n> … <sig_1> <witness_script>

In miniscript this is and_v(v:pk(K1),and_v(v:pk(K2),…pk(Kn))), so Bitcoin Core's wallet can
import, sign and spend it natively (see descriptor.py). Keys are in slot order.

Why 100: OP_CHECKMULTISIG stops at 20 keys. The chain needs one witness stack item per
signature and no dummy, and default relay policy allows 100 items and a 3,600-byte script
(35 bytes per key, 3,500 at n = 100). Consensus allows 201 (the opcode limit), but anything
above 100 is non-standard and must be handed to a miner directly.
"""
from __future__ import annotations

import hashlib

OP_0, OP_CHECKSIG, OP_CHECKSIGVERIFY = 0x00, 0xAC, 0xAD

# Bitcoin Core src/policy/policy.h and src/script/script.h
MAX_STANDARD_P2WSH_SCRIPT_SIZE = 3600
MAX_STANDARD_P2WSH_STACK_ITEMS = 100      # excludes the witness script itself
MAX_SCRIPT_SIZE = 10_000                  # consensus
MAX_OPS_PER_SCRIPT = 201                  # consensus; each OP_CHECKSIG(VERIFY) counts one

MAX_STANDARD_KEYS = 100
MAX_CONSENSUS_KEYS = 201


def chain_script(pubkeys: list[bytes]) -> bytes:
    if not pubkeys:
        raise ValueError("need at least one key")
    if any(len(pk) != 33 or pk[0] not in (2, 3) for pk in pubkeys):
        raise ValueError("only compressed public keys are standard in segwit")
    if len(set(pubkeys)) != len(pubkeys):
        raise ValueError("duplicate public key")
    body = b"".join(b"\x21" + pk + bytes([OP_CHECKSIGVERIFY]) for pk in pubkeys[:-1])
    return body + b"\x21" + pubkeys[-1] + bytes([OP_CHECKSIG])


def p2wsh_script_pubkey(witness_script: bytes) -> bytes:
    return bytes([OP_0, 32]) + hashlib.sha256(witness_script).digest()


def limits(n_keys: int) -> dict:
    """What Bitcoin Core does with an n-key chain spend."""
    script_bytes = 35 * n_keys
    standard = n_keys <= MAX_STANDARD_P2WSH_STACK_ITEMS and script_bytes <= MAX_STANDARD_P2WSH_SCRIPT_SIZE
    valid = n_keys <= MAX_OPS_PER_SCRIPT and script_bytes <= MAX_SCRIPT_SIZE
    return {"keys": n_keys, "script_bytes": script_bytes, "witness_items": n_keys + 1,
            "standard": standard, "consensus_valid": valid}
