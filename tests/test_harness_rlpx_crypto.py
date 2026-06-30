"""RLPx crypto tests — keccak vector, ECDH agreement, ECIES round-trip."""
from __future__ import annotations

import pytest

from harness.drivers.rlpx import crypto as c


def test_keccak256_empty_vector():
    assert c.keccak256(b"").hex() == (
        "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    )


def test_keccak256_known_vector():
    # keccak256("abc")
    assert c.keccak256(b"abc").hex() == (
        "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
    )


def test_ecdh_agreement_is_symmetric():
    a, b = c.gen_private_key(), c.gen_private_key()
    assert c.ecdh_x(a, b.public_key()) == c.ecdh_x(b, a.public_key())


def test_pubkey_raw64_roundtrips():
    priv = c.gen_private_key()
    raw = c.pubkey_raw64(priv)
    assert len(raw) == 64
    # rebuild from the 64-byte form and agree
    pub = c.pubkey_from_bytes(raw)
    other = c.gen_private_key()
    assert c.ecdh_x(other, pub) == c.ecdh_x(priv, other.public_key())


def test_ecies_roundtrip():
    priv = c.gen_private_key()
    msg = b"rlpx auth handshake payload \x00\x01\x02"
    ct = c.ecies_encrypt(priv.public_key(), msg)
    assert c.ecies_decrypt(priv, ct) == msg


def test_ecies_with_shared_mac_data():
    priv = c.gen_private_key()
    msg = b"x" * 100
    prefix = (len(msg) + 113).to_bytes(2, "big")  # EIP-8 style length prefix
    ct = c.ecies_encrypt(priv.public_key(), msg, shared_mac_data=prefix)
    assert c.ecies_decrypt(priv, ct, shared_mac_data=prefix) == msg


def test_ecies_mac_tamper_rejected():
    priv = c.gen_private_key()
    ct = bytearray(c.ecies_encrypt(priv.public_key(), b"hello"))
    ct[-1] ^= 0x01  # flip a tag bit
    with pytest.raises(ValueError):
        c.ecies_decrypt(priv, bytes(ct))


def test_ecies_wrong_shared_mac_data_rejected():
    priv = c.gen_private_key()
    ct = c.ecies_encrypt(priv.public_key(), b"hello", shared_mac_data=b"\x00\x10")
    with pytest.raises(ValueError):
        c.ecies_decrypt(priv, ct, shared_mac_data=b"\x00\x11")
