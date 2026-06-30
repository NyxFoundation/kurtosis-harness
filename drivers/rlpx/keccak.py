"""Incremental, peekable Keccak-256 for the RLPx running MAC.

pycryptodome's Keccak can't be copied or peeked mid-stream, but the RLPx MAC
must read the current digest, then keep absorbing. This pure-Python sponge
supports update()/copy()/digest() (digest works on a copy, so absorbing can
continue). Verified against the canonical vectors and pycryptodome.

One-shot hashing elsewhere still uses the fast C keccak in crypto.py; this is
only for the MAC's incremental state.
"""

from __future__ import annotations

_MASK = (1 << 64) - 1
_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]
# rho rotation offsets r[x][y]
_R = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
]


def _rol(x: int, n: int) -> int:
    return ((x << n) | (x >> (64 - n))) & _MASK


def _keccak_f(a: list[int]) -> None:
    for rnd in range(24):
        c = [a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rol(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(0, 25, 5):
                a[x + y] ^= d[x]
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = _rol(a[x + 5 * y], _R[x][y])
        for x in range(5):
            for y in range(0, 25, 5):
                a[x + y] = b[x + y] ^ ((~b[(x + 1) % 5 + y]) & b[(x + 2) % 5 + y])
        a[0] ^= _RC[rnd]


class KeccakState:
    """Incremental Keccak-256 (rate 136 bytes, Keccak pad10*1 with 0x01/0x80)."""

    RATE = 136
    OUT = 32

    def __init__(self):
        self.state = [0] * 25
        self.buf = bytearray()

    def update(self, data: bytes) -> "KeccakState":
        self.buf += data
        while len(self.buf) >= self.RATE:
            self._absorb(self.buf[: self.RATE])
            del self.buf[: self.RATE]
        return self

    def _absorb(self, block: bytes) -> None:
        for i in range(self.RATE // 8):
            self.state[i] ^= int.from_bytes(block[i * 8 : i * 8 + 8], "little")
        _keccak_f(self.state)

    def copy(self) -> "KeccakState":
        k = KeccakState()
        k.state = list(self.state)
        k.buf = bytearray(self.buf)
        return k

    def digest(self) -> bytes:
        k = self.copy()  # so the original can keep absorbing
        msg = bytes(k.buf)
        q = k.RATE - (len(msg) % k.RATE)
        pad = b"\x81" if q == 1 else b"\x01" + b"\x00" * (q - 2) + b"\x80"
        block = msg + pad
        for off in range(0, len(block), k.RATE):
            for i in range(k.RATE // 8):
                k.state[i] ^= int.from_bytes(block[off + i * 8 : off + i * 8 + 8], "little")
            _keccak_f(k.state)
        out = b"".join(k.state[i].to_bytes(8, "little") for i in range(4))
        return out[: k.OUT]
