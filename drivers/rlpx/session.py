"""Live RLPx session — TCP handshake + p2p Hello against a real node.

This is the interop layer: connect to the peer's listener, run auth/ack over
the socket, then exchange the p2p Hello. Hello is sent uncompressed (snappy is
only negotiated afterwards), so a successful Hello exchange proves the whole
handshake + framing interoperates with the target client.
"""

from __future__ import annotations

import os
import socket

from ..rlp import decode, decode_partial, encode
from . import crypto as c
from . import handshake as hs
from .frame import FrameCodec, initiator_codec

P2P_VERSION = 5

# p2p base message ids
MSG_HELLO = 0x00
MSG_DISCONNECT = 0x01
MSG_PING = 0x02
MSG_PONG = 0x03

# eth subprotocol message ids (offset 0x10 as the first/only subprotocol)
ETH_STATUS = 0x10
ETH_NEW_BLOCK_HASHES = 0x11
ETH_NEW_POOLED_TX_HASHES = 0x18


def _snappy_compress(data: bytes) -> bytes:
    import cramjam
    return bytes(cramjam.snappy.compress_raw(data))


def _snappy_decompress(data: bytes) -> bytes:
    import cramjam
    return bytes(cramjam.snappy.decompress_raw(data))


class Session:
    def __init__(self, host: str, port: int, remote_pubkey64: bytes,
                 our_static=None, caps=None):
        self.host = host
        self.port = port
        self.remote_pub = c.pubkey_from_bytes(remote_pubkey64)
        self.static = our_static or c.gen_private_key()
        self.caps = caps or [[b"eth", 68], [b"eth", 67]]
        self.sock: socket.socket | None = None
        self.codec: FrameCodec | None = None
        self.snappy = False  # enabled after the p2p Hello exchange

    # --- socket helpers ----------------------------------------------------
    def _recv_exact(self, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("peer closed during read")
            buf += chunk
        return buf

    # --- handshake ---------------------------------------------------------
    def connect(self, timeout: float = 10.0) -> None:
        self.sock = socket.create_connection((self.host, self.port), timeout=timeout)
        eph = c.gen_private_key()
        init_nonce = os.urandom(32)
        auth = hs.build_auth(self.static, eph, init_nonce, self.remote_pub)
        self.sock.sendall(auth)

        prefix = self._recv_exact(2)
        ack = prefix + self._recv_exact(int.from_bytes(prefix, "big"))
        recv_eph_pub, recv_nonce = hs.read_ack(self.static, ack)

        secrets = hs.derive_secrets(eph, recv_eph_pub, init_nonce, recv_nonce)
        self.codec = initiator_codec(secrets, init_nonce, recv_nonce, auth, ack)

    # --- framed messages ---------------------------------------------------
    def write_msg(self, msg_id: int, payload_rlp: bytes) -> None:
        if self.snappy:
            payload_rlp = _snappy_compress(payload_rlp)
        self.sock.sendall(self.codec.write_frame(encode(msg_id) + payload_rlp))

    def read_msg(self) -> tuple[int, bytes]:
        size = self.codec.read_header(self._recv_exact(32))
        padded = size + ((16 - size % 16) % 16)
        frame = self.codec.read_body(size, self._recv_exact(padded + 16))
        msg_id_raw, rest = decode_partial(frame)
        msg_id = int.from_bytes(msg_id_raw, "big") if msg_id_raw else 0
        if self.snappy and rest:
            rest = _snappy_decompress(rest)
        return msg_id, rest

    # --- p2p Hello ---------------------------------------------------------
    def hello(self) -> tuple[int, list]:
        body = encode([
            P2P_VERSION,
            b"speca-harness/1.0",
            self.caps,
            0,                       # listen port (0 = not listening)
            c.pubkey_raw64(self.static),
        ])
        self.write_msg(MSG_HELLO, body)
        msg_id, payload = self.read_msg()
        decoded = decode_partial(payload)[0] if payload else []
        if msg_id == MSG_HELLO:
            self.snappy = True  # all subsequent messages are snappy-compressed
        return msg_id, decoded

    # --- eth Status handshake ---------------------------------------------
    def eth_status(self) -> tuple[int, list]:
        """Read the peer's Status and reply with a compatible one.

        Echoes the peer's network id / genesis / fork id / head so reth accepts
        us and transitions the session to active (where flood handlers run).
        Returns (msg_id, peer_status_fields).
        """
        msg_id, payload = self.read_msg()
        if msg_id != ETH_STATUS:
            return msg_id, decode(payload) if payload else []
        version, netid, td, head, genesis, forkid = decode(payload)[:6]
        ours = encode([0x44, netid, td, head, genesis, forkid])  # eth/68
        self.write_msg(ETH_STATUS, ours)
        return msg_id, [version, netid, td, head, genesis, forkid]

    def handshake(self, timeout: float = 10.0):
        """Full bring-up: connect + Hello + eth Status. Returns peer Status."""
        self.connect(timeout=timeout)
        hid, _ = self.hello()
        if hid != MSG_HELLO:
            raise ConnectionError(f"no Hello (got msg id {hid})")
        sid, status = self.eth_status()
        if sid != ETH_STATUS:
            raise ConnectionError(f"no eth Status (got msg id {sid})")
        return status

    def close(self) -> None:
        if self.sock:
            try:
                self.sock.close()
            finally:
                self.sock = None
