"""eth-protocol wire message bodies for the devp2p drivers.

RLP-encoded bodies for the two flood findings:
- NewBlockHashes (RETH-WIRE-003)
- NewPooledTransactionHashes, eth/68 layout (AUDIT-001)

These are the message payloads the RLPx speaker will frame and send once the
ECIES transport lands; encoded here so the construction is testable now.
"""

from __future__ import annotations

from .rlp import encode

HASH_LEN = 32


def encode_new_block_hashes(entries: list[tuple[bytes, int]]) -> bytes:
    """NewBlockHashes: an RLP list of [block_hash, block_number] pairs."""
    return encode([[h, n] for h, n in entries])


def encode_new_pooled_transaction_hashes_68(
    hashes: list[bytes],
    *,
    types: bytes | None = None,
    sizes: list[int] | None = None,
) -> bytes:
    """eth/68 NewPooledTransactionHashes: [types(bytes), [sizes], [hashes]].

    Defaults: all type-0 (legacy) txs of a nominal size; the announced hashes
    are what the victim iterates into its fixed-size LRU.
    """
    if types is None:
        types = b"\x00" * len(hashes)
    if sizes is None:
        sizes = [100] * len(hashes)
    if not (len(types) == len(sizes) == len(hashes)):
        raise ValueError("types, sizes, hashes must be the same length")
    return encode([types, list(sizes), list(hashes)])


def encode_get_block_headers(
    request_id: int, start_hash: bytes, *, limit: int = 1,
    skip: int = 0, reverse: bool = False,
) -> bytes:
    """eth request/response pair for GetBlockHeaders (eth/68)."""
    return encode([request_id, [start_hash, limit, skip, int(reverse)]])


def encode_block_headers(request_id: int, headers: list[bytes]) -> bytes:
    """eth request/response pair for BlockHeaders (eth/68)."""
    return encode([request_id, headers])


def encode_block_bodies(request_id: int, bodies: list[bytes]) -> bytes:
    """eth request/response pair for BlockBodies (eth/68)."""
    return encode([request_id, bodies])
