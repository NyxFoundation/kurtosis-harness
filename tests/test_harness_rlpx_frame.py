"""RLPx framed-transport test — two endpoints frame/unframe with matching MACs.

Runs the full in-memory handshake to get real secrets + auth/ack packets, then
checks the framed transport in both directions and that MAC tampering is caught.
This validates the entire RLPx crypto stack before any socket to a real node.
"""
from __future__ import annotations

import os

import pytest

from harness.drivers.rlpx import crypto as c
from harness.drivers.rlpx import frame as f
from harness.drivers.rlpx import handshake as hs


def _established():
    """Run auth/ack in memory; return (initiator_codec, recipient_codec)."""
    init_static, recv_static = c.gen_private_key(), c.gen_private_key()
    init_eph, recv_eph = c.gen_private_key(), c.gen_private_key()
    init_nonce, recv_nonce = os.urandom(32), os.urandom(32)

    auth = hs.build_auth(init_static, init_eph, init_nonce, recv_static.public_key())
    _, init_eph_pub, _ = hs.read_auth(recv_static, auth)
    ack = hs.build_ack(recv_eph, recv_nonce, init_static.public_key())
    recv_eph_pub, _ = hs.read_ack(init_static, ack)

    isec = hs.derive_secrets(init_eph, recv_eph_pub, init_nonce, recv_nonce)
    rsec = hs.derive_secrets(recv_eph, init_eph_pub, init_nonce, recv_nonce)
    assert isec.aes_secret == rsec.aes_secret

    ic = f.initiator_codec(isec, init_nonce, recv_nonce, auth, ack)
    rc = f.recipient_codec(rsec, init_nonce, recv_nonce, auth, ack)
    return ic, rc


def test_frame_roundtrip_initiator_to_recipient():
    ic, rc = _established()
    for msg in [b"\x80", b"hello rlpx frame", os.urandom(500)]:
        assert rc.read_frame(ic.write_frame(msg)) == msg


def test_frame_roundtrip_recipient_to_initiator():
    ic, rc = _established()
    msg = os.urandom(1234)
    assert ic.read_frame(rc.write_frame(msg)) == msg


def test_consecutive_frames_keep_mac_chain_in_sync():
    ic, rc = _established()
    # the running MAC + CTR stream must stay in lockstep across many frames
    for i in range(50):
        m = bytes([i]) * (i + 1)
        assert rc.read_frame(ic.write_frame(m)) == m


def test_tampered_frame_mac_rejected():
    ic, rc = _established()
    framed = bytearray(ic.write_frame(b"payload to tamper"))
    framed[-1] ^= 0x01  # flip a frame-mac bit
    with pytest.raises(ValueError):
        rc.read_frame(bytes(framed))
