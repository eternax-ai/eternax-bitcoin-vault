"""Building and signing the unlock transaction.

A vault address can receive any number of payments, but it is spent once: that spend reveals all
of its public keys, so an output left behind would sit exposed at rest. The unlock therefore sweeps
every output at the address in one transaction, each input carrying its own signatures, either all
to one destination or as a payment plus change to a fresh vault. Outputs of different vaults are never
mixed: that adds no work for an attacker, and one broken vault would let them replace the whole
transaction while the other vaults' keys sit in the mempool.
"""
from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass

from .keys import pubkey, sign_low_r
from .script import chain_script, p2wsh_script_pubkey

SIGHASH_ALL = 1
SEQUENCE_RBF = 0xFFFFFFFD          # signals replace-by-fee; re-signing reveals nothing new
PLACEHOLDER_SIG = b"\x30" + b"\x00" * 69 + b"\x01"   # 71 bytes: the size of a low-R signature + sighash byte
MAX_STANDARD_TX_WEIGHT = 400_000   # Bitcoin Core src/policy/policy.h; about 36 hundred-key inputs


def dsha256(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def varint(n: int) -> bytes:
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + n.to_bytes(2, "little")
    return b"\xfe" + n.to_bytes(4, "little")


def push(b: bytes) -> bytes:
    return varint(len(b)) + b


def dust_threshold(script_pubkey: bytes) -> int:
    """Bitcoin Core's dust limit at its default 3 sat/vB dust relay fee (src/policy/policy.cpp GetDustThreshold)."""
    witness_program = (4 <= len(script_pubkey) <= 42 and script_pubkey[0] in (0, *range(0x51, 0x61))
                       and script_pubkey[1] == len(script_pubkey) - 2)
    spend_size = 67 if witness_program else 148      # bytes to spend the output later, witness discounted
    return 3 * (8 + len(push(script_pubkey)) + spend_size)


@dataclass(frozen=True)
class Outpoint:
    txid: str          # as shown by explorers and RPC (big-endian hex)
    vout: int
    amount: int        # satoshis

    def serialize(self) -> bytes:
        return bytes.fromhex(self.txid)[::-1] + self.vout.to_bytes(4, "little")


@dataclass
class UnlockTx:
    prevouts: list[Outpoint]
    outputs: list[tuple[int, bytes]]            # (satoshis, scriptPubKey)
    witnesses: list[list[bytes]]                # one stack per input
    version: int = 2
    locktime: int = 0

    def _outputs(self) -> bytes:
        return varint(len(self.outputs)) + b"".join(v.to_bytes(8, "little") + push(spk) for v, spk in self.outputs)

    def serialize(self, with_witness: bool = True) -> bytes:
        seq = SEQUENCE_RBF.to_bytes(4, "little")
        txins = b"".join(p.serialize() + b"\x00" + seq for p in self.prevouts)        # empty scriptSigs
        body = varint(len(self.prevouts)) + txins + self._outputs()
        head = self.version.to_bytes(4, "little")
        tail = self.locktime.to_bytes(4, "little")
        if not with_witness:
            return head + body + tail
        wit = b"".join(varint(len(w)) + b"".join(push(item) for item in w) for w in self.witnesses)
        return head + b"\x00\x01" + body + wit + tail

    @property
    def txid(self) -> str:
        return dsha256(self.serialize(with_witness=False))[::-1].hex()

    @property
    def weight(self) -> int:
        return 3 * len(self.serialize(with_witness=False)) + len(self.serialize())

    @property
    def vsize(self) -> int:
        return math.ceil(self.weight / 4)

    def sighash(self, index: int, witness_script: bytes) -> bytes:
        """BIP-143 signature hash for input `index`, SIGHASH_ALL."""
        outputs = b"".join(v.to_bytes(8, "little") + push(spk) for v, spk in self.outputs)
        seq = SEQUENCE_RBF.to_bytes(4, "little")
        prevout = self.prevouts[index]
        preimage = (self.version.to_bytes(4, "little")
                    + dsha256(b"".join(p.serialize() for p in self.prevouts)) + dsha256(seq * len(self.prevouts))
                    + prevout.serialize() + push(witness_script)
                    + prevout.amount.to_bytes(8, "little") + seq
                    + dsha256(outputs) + self.locktime.to_bytes(4, "little")
                    + SIGHASH_ALL.to_bytes(4, "little"))
        return dsha256(preimage)


def build_unlock(secrets: list[bytes], prevouts: list[Outpoint], dest_script_pubkey: bytes,
                 feerate: float, standard: bool = True,
                 amount: int | None = None, change_script_pubkey: bytes | None = None) -> UnlockTx:
    """Spend every listed output of one vault at `feerate` sat/vB, signed by every key: all of it to the
    destination, or `amount` satoshis to the destination and the rest to `change_script_pubkey`, a fresh vault."""
    pubkeys = [pubkey(s) for s in secrets]
    ws = chain_script(pubkeys)
    if not prevouts:
        raise ValueError("nothing to unlock: no outputs given")
    if len({(p.txid, p.vout) for p in prevouts}) != len(prevouts):
        raise ValueError("the same output is listed twice")
    if standard and len(secrets) > 100:
        raise ValueError("more than 100 keys is non-standard; pass standard=False and submit to a miner directly")
    if (amount is None) != (change_script_pubkey is None):
        raise ValueError("a payment amount needs a change vault, and a change vault needs a payment amount")
    if p2wsh_script_pubkey(ws) in (dest_script_pubkey, change_script_pubkey):
        raise ValueError("this unlock exposes the vault's keys, so nothing may go back to it; use a fresh vault")
    # size the transaction with placeholder signatures, then sign for real (low-R keeps it within the estimate)
    total = sum(p.amount for p in prevouts)
    outputs = [(total, dest_script_pubkey)]
    if amount is not None:
        outputs = [(amount, dest_script_pubkey), (total, change_script_pubkey)]
    tx = UnlockTx(list(prevouts), outputs, [[PLACEHOLDER_SIG] * len(secrets) + [ws] for _ in prevouts])
    if standard and tx.weight > MAX_STANDARD_TX_WEIGHT:
        raise ValueError(f"{len(prevouts)} outputs make a {tx.weight} WU transaction, over the {MAX_STANDARD_TX_WEIGHT} WU "
                         "standard limit; no standard transaction can sweep them all")
    fee = math.ceil(tx.vsize * feerate)
    if amount is None:
        if total - fee < dust_threshold(dest_script_pubkey):
            raise ValueError(f"amount {total} sat does not cover a {fee} sat fee plus dust")
        tx.outputs = [(total - fee, dest_script_pubkey)]
    else:
        change = total - amount - fee
        if amount < dust_threshold(dest_script_pubkey):
            raise ValueError(f"a {amount} sat payment is under the {dust_threshold(dest_script_pubkey)} sat dust limit")
        if change < 0:
            raise ValueError(f"{total} sat does not cover a {amount} sat payment plus a {fee} sat fee")
        if change < dust_threshold(change_script_pubkey):
            raise ValueError(f"the change would be {change} sat, under the {dust_threshold(change_script_pubkey)} sat "
                             "dust limit; pay less, or send everything to the destination")
        tx.outputs = [(amount, dest_script_pubkey), (change, change_script_pubkey)]
    for i in range(len(prevouts)):
        sighash = tx.sighash(i, ws)
        sigs = [sign_low_r(s, sighash) + bytes([SIGHASH_ALL]) for s in secrets]
        tx.witnesses[i] = sigs[::-1] + [ws]      # pk_1's check runs first and takes the top item
    return tx


def vault_script_pubkey(secrets: list[bytes]) -> bytes:
    return p2wsh_script_pubkey(chain_script([pubkey(s) for s in secrets]))
