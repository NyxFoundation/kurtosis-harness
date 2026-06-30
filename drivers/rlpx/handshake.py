"""RLPx auth/ack handshake (EIP-8) + session-secret derivation.

Initiator builds an ECIES-encrypted auth (recoverable sig over
static-shared ^ nonce, static pubkey, nonce); recipient replies with an
ECIES-encrypted ack (its ephemeral pubkey, nonce). Both then derive the same
aes-secret / mac-secret. The pieces are pure functions so the full handshake
can be round-tripped in memory before talking to a real node.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from ..rlp import decode_partial, encode
from . import crypto as c

AUTH_VSN = 4


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


@dataclass
class Secrets:
    aes_secret: bytes
    mac_secret: bytes
    egress_mac_seed: bytes
    ingress_mac_seed: bytes


# --- auth (initiator -> recipient) -----------------------------------------

def build_auth(initiator_static, initiator_ephemeral, initiator_nonce: bytes,
               recipient_static_pub) -> bytes:
    static_shared = c.ecdh_x(initiator_static, recipient_static_pub)
    sig = c.sign_recoverable(initiator_ephemeral, _xor(static_shared, initiator_nonce))
    body = encode([
        sig,
        c.pubkey_raw64(initiator_static),
        initiator_nonce,
        AUTH_VSN,
    ])
    return _ecies_frame(body, recipient_static_pub)


def read_auth(recipient_static, auth_packet: bytes):
    """Recipient side: returns (initiator_static_pub64, initiator_ephemeral_pub64, nonce)."""
    body = _ecies_unframe(recipient_static, auth_packet)
    sig, initiator_pub64, nonce, _vsn = decode_partial(body)[0][:4]
    initiator_static_pub = c.pubkey_from_bytes(initiator_pub64)
    static_shared = c.ecdh_x(recipient_static, initiator_static_pub)
    eph_pub64 = c.recover_pubkey64(sig, _xor(static_shared, nonce))
    return initiator_pub64, eph_pub64, nonce


# --- ack (recipient -> initiator) ------------------------------------------

def build_ack(recipient_ephemeral, recipient_nonce: bytes, initiator_static_pub) -> bytes:
    body = encode([
        c.pubkey_raw64(recipient_ephemeral),
        recipient_nonce,
        AUTH_VSN,
    ])
    return _ecies_frame(body, initiator_static_pub)


def read_ack(initiator_static, ack_packet: bytes):
    """Initiator side: returns (recipient_ephemeral_pub64, recipient_nonce)."""
    body = _ecies_unframe(initiator_static, ack_packet)
    eph_pub64, nonce, _vsn = decode_partial(body)[0][:3]
    return eph_pub64, nonce


# --- shared secret derivation (RLPx spec) ----------------------------------

def derive_secrets(our_ephemeral, remote_ephemeral_pub64: bytes,
                   initiator_nonce: bytes, recipient_nonce: bytes) -> Secrets:
    remote_eph_pub = c.pubkey_from_bytes(remote_ephemeral_pub64)
    ephemeral_shared = c.ecdh_x(our_ephemeral, remote_eph_pub)
    shared_secret = c.keccak256(ephemeral_shared + c.keccak256(recipient_nonce + initiator_nonce))
    aes_secret = c.keccak256(ephemeral_shared + shared_secret)
    mac_secret = c.keccak256(ephemeral_shared + aes_secret)
    return Secrets(
        aes_secret=aes_secret,
        mac_secret=mac_secret,
        egress_mac_seed=_xor(mac_secret, recipient_nonce),
        ingress_mac_seed=_xor(mac_secret, initiator_nonce),
    )


# --- EIP-8 ECIES framing (2-byte length prefix as shared_mac_data) ---------

def _ecies_frame(body: bytes, remote_pub) -> bytes:
    body += os.urandom(100 + (os.urandom(1)[0] % 200))  # EIP-8 random padding
    total = len(body) + 113  # ecies overhead: 65 + 16 + 32
    prefix = total.to_bytes(2, "big")
    return prefix + c.ecies_encrypt(remote_pub, body, shared_mac_data=prefix)


def _ecies_unframe(priv, packet: bytes) -> bytes:
    prefix, enc = packet[:2], packet[2:]
    return c.ecies_decrypt(priv, enc, shared_mac_data=prefix)
