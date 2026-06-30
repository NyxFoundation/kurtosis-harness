"""RLP codec + eth-wire message tests (pure, offline).

RLP is checked against the canonical spec vectors; the message encoders are
round-tripped through the decoder to confirm structure and entry counts.
"""
from __future__ import annotations

import pytest

from harness.drivers import wire
from harness.drivers.rlp import decode, encode


@pytest.mark.parametrize(
    "value,expected",
    [
        (b"", b"\x80"),
        (b"\x00", b"\x00"),
        (b"\x0f", b"\x0f"),
        (b"dog", b"\x83dog"),
        (0, b"\x80"),
        (15, b"\x0f"),
        (1024, b"\x82\x04\x00"),
        ([], b"\xc0"),
        ([b"cat", b"dog"], b"\xc8\x83cat\x83dog"),
    ],
)
def test_rlp_canonical_vectors(value, expected):
    assert encode(value) == expected


def test_rlp_long_string_roundtrip():
    blob = b"A" * 1000
    assert decode(encode(blob)) == blob


def test_rlp_decode_rejects_trailing():
    with pytest.raises(ValueError):
        decode(encode(b"dog") + b"\x00")


def test_new_block_hashes_roundtrip():
    entries = [(bytes([i]) * 32, i) for i in range(1, 6)]
    body = wire.encode_new_block_hashes(entries)
    pairs = decode(body)
    assert len(pairs) == 5
    h0, n0 = pairs[0]
    assert h0 == b"\x01" * 32
    assert int.from_bytes(n0, "big") == 1


def test_new_pooled_tx_hashes_68_structure():
    hashes = [bytes([i]) * 32 for i in range(1, 251)]  # 250 announced hashes
    body = wire.encode_new_pooled_transaction_hashes_68(hashes)
    types, sizes, hs = decode(body)
    assert len(types) == 250          # one type byte per tx
    assert len(sizes) == 250
    assert len(hs) == 250
    assert hs[0] == b"\x01" * 32


def test_pooled_tx_hashes_length_mismatch_rejected():
    with pytest.raises(ValueError):
        wire.encode_new_pooled_transaction_hashes_68(
            [b"\x01" * 32], types=b"\x00\x00", sizes=[1]
        )


# --- ground the findings' quantitative frame-limit claims in real RLP -------

MAX_FRAME = 16 * 1024 * 1024  # devp2p eth 16 MiB frame cap


def _pooled(n: int) -> int:
    hashes = [(i.to_bytes(4, "big") + b"\x00" * 28) for i in range(n)]
    return len(wire.encode_new_pooled_transaction_hashes_68(hashes))


def test_audit001_500k_claim_is_numerically_wrong():
    # AUDIT-001 claims ~500k unique hashes "stay under the 16 MiB frame limit".
    # The real eth/68 RLP encoding is 16.69 MiB at 500k — OVER the cap. The
    # harness surfaces the off-by-margin: the attack works but needs ~450k per
    # message (or several messages), not 500k in one. (See findings_index note.)
    assert _pooled(500_000) > MAX_FRAME          # the finding's number is wrong
    assert _pooled(450_000) < MAX_FRAME          # ~450k is the real single-msg max


def test_wire003_250k_blockhashes_message_size():
    # RETH-WIRE-003 sends ~250k entries (~10 MB) per message.
    entries = [(i.to_bytes(4, "big") + b"\x00" * 28, i) for i in range(250_000)]
    body = wire.encode_new_block_hashes(entries)
    assert 8_000_000 < len(body) < MAX_FRAME  # ~10 MB, under the frame cap
