"""Pure-Python incremental Keccak-256 — vectors, pycryptodome parity, peekability."""
from __future__ import annotations

import os

from harness.drivers.rlpx.keccak import KeccakState


def _k(data: bytes) -> bytes:
    return KeccakState().update(data).digest()


def test_empty_vector():
    assert _k(b"").hex() == (
        "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    )


def test_abc_vector():
    assert _k(b"abc").hex() == (
        "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
    )


def test_spans_rate_boundary():
    # 200 bytes > 136-byte rate -> exercises multi-block absorb
    blob = bytes(range(256)) * 4
    from harness.drivers.rlpx import crypto as c

    assert _k(blob) == c.keccak256(blob)


def test_matches_pycryptodome_random():
    from harness.drivers.rlpx import crypto as c

    for _ in range(20):
        data = os.urandom(os.urandom(1)[0] + 137)  # often spans the rate
        assert _k(data) == c.keccak256(data)


def test_peek_then_continue():
    # the property the MAC needs: read digest mid-stream, then keep absorbing.
    k = KeccakState().update(b"header-bytes")
    peek = k.digest()
    assert peek == _k(b"header-bytes")          # peek matches a fresh hash
    k.update(b"frame-bytes")
    assert k.digest() == _k(b"header-bytesframe-bytes")  # absorbing continued
