"""RLPx framed transport — AES-256-CTR frames with the keccak running MAC.

Per the RLPx spec: each direction has a continuous AES-256-CTR keystream
(zero IV, keyed by aes-secret) and a running keccak MAC seeded from
(mac-secret ^ peer-nonce) || handshake-packet. A frame is
  header-ciphertext(16) || header-mac(16) || frame-ciphertext || frame-mac(16).

The MAC's header/frame update is the notorious bit: encrypt the current MAC
digest with AES-256-ECB(mac-secret), XOR with the seed, absorb, re-read. Built
on the peekable KeccakState so it round-trips in memory before any socket.
"""

from __future__ import annotations

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from ..rlp import encode
from .keccak import KeccakState

HEADER_DATA = encode([0, 0])  # rlp([capability-id, context-id]) = 0xc28080


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _aes_ecb(key: bytes, block16: bytes) -> bytes:
    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return enc.update(block16) + enc.finalize()


def _ctr(aes_secret: bytes):
    # continuous AES-256-CTR keystream, zero IV (encrypt == decrypt)
    return Cipher(algorithms.AES(aes_secret), modes.CTR(b"\x00" * 16)).encryptor()


class _MAC:
    def __init__(self, mac_secret: bytes, seed: bytes):
        self.secret = mac_secret
        self.k = KeccakState()
        self.k.update(seed)

    def header(self, header_ct: bytes) -> bytes:
        sum1 = self.k.digest()[:16]
        self.k.update(_xor(_aes_ecb(self.secret, sum1), header_ct))
        return self.k.digest()[:16]

    def frame(self, frame_ct: bytes) -> bytes:
        self.k.update(frame_ct)
        sum1 = self.k.digest()[:16]
        self.k.update(_xor(_aes_ecb(self.secret, sum1), sum1))
        return self.k.digest()[:16]


class FrameCodec:
    """One connection's framing state (separate egress/ingress streams + MACs)."""

    def __init__(self, aes_secret: bytes, mac_secret: bytes,
                 egress_seed: bytes, ingress_seed: bytes):
        self.enc = _ctr(aes_secret)   # egress keystream
        self.dec = _ctr(aes_secret)   # ingress keystream
        self.egress_mac = _MAC(mac_secret, egress_seed)
        self.ingress_mac = _MAC(mac_secret, ingress_seed)

    def write_frame(self, msg: bytes) -> bytes:
        header = (len(msg).to_bytes(3, "big") + HEADER_DATA).ljust(16, b"\x00")
        header_ct = self.enc.update(header)
        header_mac = self.egress_mac.header(header_ct)
        padded = msg + b"\x00" * ((16 - len(msg) % 16) % 16)
        frame_ct = self.enc.update(padded)
        frame_mac = self.egress_mac.frame(frame_ct)
        return header_ct + header_mac + frame_ct + frame_mac

    def read_header(self, header_part: bytes) -> int:
        """Verify + decrypt the 32-byte header part; return the frame size."""
        header_ct, header_mac = header_part[:16], header_part[16:32]
        if self.ingress_mac.header(header_ct) != header_mac:
            raise ValueError("RLPx header MAC mismatch")
        return int.from_bytes(self.dec.update(header_ct)[:3], "big")

    def read_body(self, size: int, body_part: bytes) -> bytes:
        """Verify + decrypt the frame body (padded ciphertext + 16-byte mac)."""
        padded = size + ((16 - size % 16) % 16)
        frame_ct, frame_mac = body_part[:padded], body_part[padded : padded + 16]
        if self.ingress_mac.frame(frame_ct) != frame_mac:
            raise ValueError("RLPx frame MAC mismatch")
        return self.dec.update(frame_ct)[:size]

    def read_frame(self, data: bytes) -> bytes:
        size = self.read_header(data[:32])
        return self.read_body(size, data[32:])


def _seed(mac_secret: bytes, nonce: bytes, packet: bytes) -> bytes:
    return _xor(mac_secret, nonce) + packet


def initiator_codec(secrets, init_nonce, recv_nonce, auth, ack) -> FrameCodec:
    return FrameCodec(
        secrets.aes_secret, secrets.mac_secret,
        egress_seed=_seed(secrets.mac_secret, recv_nonce, auth),
        ingress_seed=_seed(secrets.mac_secret, init_nonce, ack),
    )


def recipient_codec(secrets, init_nonce, recv_nonce, auth, ack) -> FrameCodec:
    return FrameCodec(
        secrets.aes_secret, secrets.mac_secret,
        egress_seed=_seed(secrets.mac_secret, init_nonce, ack),
        ingress_seed=_seed(secrets.mac_secret, recv_nonce, auth),
    )
