"""RLPx handshake test — full in-memory auth/ack, both sides agree on secrets.

No socket: the initiator builds auth, the recipient reads it (recovering the
ephemeral pubkey from the signature), replies with ack, and both derive the
session secrets independently. They must match — that is the whole handshake
crypto validated before talking to a real node.
"""
from __future__ import annotations

import os

from harness.drivers.rlpx import crypto as c
from harness.drivers.rlpx import handshake as hs


def test_full_handshake_secrets_agree():
    # static identities
    init_static = c.gen_private_key()
    recv_static = c.gen_private_key()
    # ephemerals
    init_eph = c.gen_private_key()
    recv_eph = c.gen_private_key()
    init_nonce = os.urandom(32)
    recv_nonce = os.urandom(32)

    # initiator -> auth -> recipient
    auth = hs.build_auth(init_static, init_eph, init_nonce, recv_static.public_key())
    got_init_pub, got_init_eph_pub, got_nonce = hs.read_auth(recv_static, auth)

    # recipient recovered the initiator's static pubkey, ephemeral pubkey, nonce
    assert got_init_pub == c.pubkey_raw64(init_static)
    assert got_init_eph_pub == c.pubkey_raw64(init_eph)   # recovered from the sig
    assert got_nonce == init_nonce

    # recipient -> ack -> initiator
    ack = hs.build_ack(recv_eph, recv_nonce, init_static.public_key())
    got_recv_eph_pub, got_recv_nonce = hs.read_ack(init_static, ack)
    assert got_recv_eph_pub == c.pubkey_raw64(recv_eph)
    assert got_recv_nonce == recv_nonce

    # both sides derive the session secrets and must agree
    initiator_secrets = hs.derive_secrets(init_eph, got_recv_eph_pub, init_nonce, recv_nonce)
    recipient_secrets = hs.derive_secrets(recv_eph, got_init_eph_pub, init_nonce, recv_nonce)

    assert initiator_secrets.aes_secret == recipient_secrets.aes_secret
    assert initiator_secrets.mac_secret == recipient_secrets.mac_secret
    assert len(initiator_secrets.aes_secret) == 32
    assert len(initiator_secrets.mac_secret) == 32


def test_auth_is_eip8_length_prefixed():
    init_static, recv_static = c.gen_private_key(), c.gen_private_key()
    auth = hs.build_auth(init_static, c.gen_private_key(), os.urandom(32), recv_static.public_key())
    declared = int.from_bytes(auth[:2], "big")
    assert declared == len(auth) - 2  # 2-byte prefix = rest length
