"""Minimal RLP codec — just enough for the eth-wire messages the drivers send.

RLP (Recursive Length Prefix) is the encoding for devp2p eth-protocol message
bodies. No third-party dependency; verified against the canonical spec vectors.
"""

from __future__ import annotations


def _int_to_be(n: int) -> bytes:
    if n < 0:
        raise ValueError("RLP ints must be non-negative")
    if n == 0:
        return b""
    return n.to_bytes((n.bit_length() + 7) // 8, "big")


def _encode_length(length: int, offset: int) -> bytes:
    if length < 56:
        return bytes([offset + length])
    be = _int_to_be(length)
    return bytes([offset + 55 + len(be)]) + be


def _encode_bytes(b: bytes) -> bytes:
    if len(b) == 1 and b[0] < 0x80:
        return b
    return _encode_length(len(b), 0x80) + b


def encode(item) -> bytes:
    """RLP-encode bytes, non-negative int (as big-endian), or a list thereof."""
    if isinstance(item, bytes):
        return _encode_bytes(item)
    if isinstance(item, bool):
        raise TypeError("bool is not RLP-encodable")
    if isinstance(item, int):
        return _encode_bytes(_int_to_be(item))
    if isinstance(item, (list, tuple)):
        payload = b"".join(encode(x) for x in item)
        return _encode_length(len(payload), 0xC0) + payload
    raise TypeError(f"cannot RLP-encode {type(item).__name__}")


def decode(data: bytes):
    """Decode RLP into nested bytes/lists. Raises on trailing bytes."""
    item, rest = _decode_one(data)
    if rest:
        raise ValueError("trailing bytes after RLP item")
    return item


def decode_partial(data: bytes):
    """Decode the first RLP item, returning (item, trailing_bytes).

    Used where trailing padding is expected (EIP-8 auth/ack messages).
    """
    return _decode_one(data)


def _decode_one(data: bytes):
    if not data:
        raise ValueError("empty RLP input")
    p = data[0]
    if p < 0x80:
        return data[:1], data[1:]
    if p < 0xB8:
        n = p - 0x80
        return data[1 : 1 + n], data[1 + n :]
    if p < 0xC0:
        ln = p - 0xB7
        n = int.from_bytes(data[1 : 1 + ln], "big")
        s = 1 + ln
        return data[s : s + n], data[s + n :]
    # list
    if p < 0xF8:
        n = p - 0xC0
        s = 1
    else:
        ln = p - 0xF7
        n = int.from_bytes(data[1 : 1 + ln], "big")
        s = 1 + ln
    body, rest = data[s : s + n], data[s + n :]
    items = []
    while body:
        it, body = _decode_one(body)
        items.append(it)
    return items, rest
