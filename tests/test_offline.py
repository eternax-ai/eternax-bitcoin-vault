"""Tests that need no node: encodings, script layout, key derivation, signing, transaction shape."""
import math

import coincurve
import pytest

from eternax_vault import network
from eternax_vault.descriptor import checksum, vault_descriptor
from eternax_vault.encoding import address_to_script_pubkey, p2wsh_address, segwit_decode, segwit_encode
from eternax_vault.keys import new_mnemonic, pubkey, seed_from_mnemonic, sign_low_r, vault_secrets
from eternax_vault.odds import attack_odds
from eternax_vault.script import OP_CHECKSIG, OP_CHECKSIGVERIFY, chain_script, limits, p2wsh_script_pubkey
from eternax_vault.tx import Outpoint, build_unlock

REGTEST, MAINNET = network.get("regtest"), network.get("mainnet")
SEED = bytes(range(32))


# ---------- encodings (published test vectors) ----------
def test_bech32_and_bech32m_vectors():
    # BIP-173 / BIP-350
    assert segwit_encode("bc", 0, bytes.fromhex("751e76e8199196d454941c45d1b3a323f1433bd6")) == \
        "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
    p2wsh = "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7"
    assert segwit_decode("tb", p2wsh) == (0, bytes.fromhex("1863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262"))
    assert segwit_encode("bc", 1, bytes.fromhex("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")) == \
        "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0"
    with pytest.raises(ValueError):
        segwit_decode("bc", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5")       # one character off


def test_address_to_script_pubkey():
    assert address_to_script_pubkey("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", MAINNET).hex() == \
        "76a91477bff20c60e522dfaa3350c39b030a5d004e839a88ac"
    assert address_to_script_pubkey("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", MAINNET).hex() == \
        "0014751e76e8199196d454941c45d1b3a323f1433bd6"
    with pytest.raises(ValueError):
        address_to_script_pubkey("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", REGTEST)   # wrong network


def test_descriptor_checksum_vector():
    assert checksum("raw(deadbeef)") == "89f8spxm"                                   # BIP-380


# ---------- script ----------
def test_hundred_key_chain_layout():
    pks = [pubkey(s) for s in vault_secrets(SEED, REGTEST, 100, 0)]
    ws = chain_script(pks)
    assert len(ws) == 3500                                                           # 35 bytes per key
    assert ws.count(bytes([OP_CHECKSIGVERIFY])) >= 99 and ws[-1] == OP_CHECKSIG
    assert ws[1:34] == pks[0] and ws[-34:-1] == pks[-1]                              # slot order
    assert p2wsh_script_pubkey(ws)[:2] == b"\x00\x20"
    assert p2wsh_address(ws, MAINNET).startswith("bc1q") and len(p2wsh_address(ws, MAINNET)) == 62


def test_limits_match_bitcoin_core():
    assert limits(100) == {"keys": 100, "script_bytes": 3500, "witness_items": 101, "standard": True, "consensus_valid": True}
    assert not limits(101)["standard"] and limits(101)["consensus_valid"]           # 101 signatures > 100 stack items
    assert not limits(201)["standard"] and limits(201)["consensus_valid"]
    assert not limits(202)["consensus_valid"]                                        # 202 ops > 201


def test_rejects_bad_keys():
    pks = [pubkey(s) for s in vault_secrets(SEED, REGTEST, 2, 0)]
    with pytest.raises(ValueError):
        chain_script([pks[0], pks[0]])
    with pytest.raises(ValueError):
        chain_script([b"\x04" + b"\x01" * 64])


# ---------- keys ----------
ABANDON_ART = " ".join(["abandon"] * 23 + ["art"])


def test_bip39_official_vector():
    # BIP-39 test vectors: 256-bit all-zero entropy, passphrase "TREZOR"
    assert seed_from_mnemonic(ABANDON_ART, "TREZOR").hex() == (
        "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd3097170af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8")


def test_bip39_rejects_bad_phrases_and_normalises_good_ones():
    with pytest.raises(ValueError):
        seed_from_mnemonic(ABANDON_ART.replace(" art", " abandon"))                # bad checksum
    with pytest.raises(ValueError):
        seed_from_mnemonic(ABANDON_ART.replace("art", "artt"))                     # not a BIP-39 word
    assert seed_from_mnemonic(f"  {ABANDON_ART.upper()}\n") == seed_from_mnemonic(ABANDON_ART)
    words = new_mnemonic()
    assert len(words.split()) == 24 and len(seed_from_mnemonic(words)) == 64


def test_vault_path_vector():
    """Recomputed independently with embit (BIP-39 + BIP-32 + bech32): any implementation should agree."""
    secrets = vault_secrets(seed_from_mnemonic(ABANDON_ART), MAINNET, 100, 0)
    assert pubkey(secrets[0]).hex() == "03a1ded4c4ea289e950e73fdd0883d61d67f4fa989cb0aba6d9a390a47347e8271"
    assert p2wsh_address(chain_script([pubkey(s) for s in secrets]), MAINNET) == \
        "bc1q9av9cs3u4433y3jkp97frhd9tpyuf8rtccqnpqtjmzkerv9j0meshqvl4w"


def test_one_seed_derives_distinct_reproducible_keys():
    a = vault_secrets(SEED, REGTEST, 100, 0)
    assert a == vault_secrets(SEED, REGTEST, 100, 0)                                 # backup is the seed
    assert len(set(a)) == 100
    assert set(a).isdisjoint(vault_secrets(SEED, REGTEST, 100, 1))                   # next deposit: new keys
    assert set(a).isdisjoint(vault_secrets(SEED, MAINNET, 100, 0))                   # coin type separates networks
    assert vault_secrets(SEED, REGTEST, 5, 0) == a[:5]                               # slot i is the same key for any n


def test_low_r_signatures_verify():
    for i, s in enumerate(vault_secrets(SEED, REGTEST, 50, 0)):
        msg = bytes([i]) * 32
        sig = sign_low_r(s, msg)
        assert len(sig) <= 70 and sig[3] <= 0x20
        assert coincurve.PublicKey(pubkey(s)).verify(sig, msg, hasher=None)


# ---------- transaction ----------
def test_unlock_shape_and_signatures():
    secrets = vault_secrets(SEED, REGTEST, 100, 0)
    prevout = Outpoint("11" * 32, 0, 100_000)
    dest = address_to_script_pubkey("bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080", REGTEST)
    tx = build_unlock(secrets, [prevout], dest, feerate=5)
    ws = tx.witnesses[0][-1]
    assert len(tx.witnesses) == 1 and len(tx.witnesses[0]) == 101 and ws == chain_script([pubkey(s) for s in secrets])
    assert 2750 <= tx.vsize <= 2760
    fee = prevout.amount - tx.outputs[0][0]
    assert fee >= math.ceil(tx.vsize * 5)                                            # never under the requested rate
    sighash = tx.sighash(0, ws)
    for sig, secret in zip(tx.witnesses[0][-2::-1], secrets):                        # sig_1 sits on top of the stack
        assert sig[-1] == 1 and coincurve.PublicKey(pubkey(secret)).verify(sig[:-1], sighash, hasher=None)


def test_unlock_sweeps_several_outputs_in_one_transaction():
    secrets = vault_secrets(SEED, REGTEST, 100, 0)
    prevouts = [Outpoint(f"{i + 1:02x}" * 32, i, 50_000 * (i + 1)) for i in range(3)]
    dest = address_to_script_pubkey("bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080", REGTEST)
    tx = build_unlock(secrets, prevouts, dest, feerate=5)
    ws = chain_script([pubkey(s) for s in secrets])
    assert tx.prevouts == prevouts and len(tx.outputs) == 1 and 3 * 2700 < tx.vsize < 3 * 2760
    assert sum(p.amount for p in prevouts) - tx.outputs[0][0] >= math.ceil(tx.vsize * 5)
    assert len({tx.sighash(i, ws) for i in range(3)}) == 3                          # each input signs its own hash
    for i, witness in enumerate(tx.witnesses):
        assert len(witness) == 101 and witness[-1] == ws
        for sig, secret in zip(witness[-2::-1], secrets):
            assert coincurve.PublicKey(pubkey(secret)).verify(sig[:-1], tx.sighash(i, ws), hasher=None)


def test_unlock_refuses_empty_duplicate_and_oversized_sweeps():
    secrets = vault_secrets(SEED, REGTEST, 100, 0)
    dest = b"\x00\x14" + b"\x01" * 20
    with pytest.raises(ValueError, match="no outputs"):
        build_unlock(secrets, [], dest, feerate=1)
    with pytest.raises(ValueError, match="twice"):
        build_unlock(secrets, [Outpoint("33" * 32, 0, 10**6)] * 2, dest, feerate=1)
    many = [Outpoint("44" * 32, i, 10**6) for i in range(37)]
    assert build_unlock(secrets, many[:36], dest, feerate=1).weight <= 400_000         # 36 hundred-key inputs fit
    with pytest.raises(ValueError, match="standard limit"):
        build_unlock(secrets, many, dest, feerate=1)


def test_unlock_refuses_nonstandard_unless_asked():
    secrets = vault_secrets(SEED, REGTEST, 101, 0)
    prevout = Outpoint("22" * 32, 1, 1_000_000)
    with pytest.raises(ValueError):
        build_unlock(secrets, [prevout], b"\x00\x14" + b"\x01" * 20, feerate=1)
    tx = build_unlock(secrets, [prevout], b"\x00\x14" + b"\x01" * 20, feerate=1, standard=False)
    assert len(tx.witnesses[0]) == 102


def test_descriptor_is_the_same_script():
    secrets = vault_secrets(SEED, REGTEST, 3, 0)
    pub = vault_descriptor(secrets, REGTEST, private=False)
    k = [pubkey(s).hex() for s in secrets]
    assert pub.split("#")[0] == f"wsh(and_v(v:pk({k[0]}),and_v(v:pk({k[1]}),pk({k[2]}))))"
    assert pub.split("#")[1] == checksum(pub.split("#")[0])


# ---------- model ----------
def test_attack_odds():
    assert round(attack_odds(1), 3) == 0.407                                         # Google's single-key figure
    assert attack_odds(100, 5) == attack_odds(20, 1)                                 # 100 keys vs 5 machines = 20 vs 1
    assert attack_odds(100, 100) == attack_odds(1)                                   # work factor, not unforgeability
