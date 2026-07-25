"""SingleAttestation OOB payload builder tests — pure/offline.

Verifies the construction of the CHK-QW-02 attack payload:
a SingleAttestation with an out-of-band attester_index.
"""
from __future__ import annotations

from harness.drivers import payloads as pl


def test_singleattestation_oob_payload_structure():
    p = pl.build_singleattestation_oob(attester_index=0xFFFF_FFFF, slot=42, committee_index=3)
    assert p.generator == "singleattestation_oob_attester_index"
    assert p.count == 1
    assert p.unique_count == 1
    # 232 bytes: attester_index(8) + AttestationData(128) + signature(96)
    assert len(p.artifact) == pl.SINGLE_ATTESTATION_SIZE
    assert len(p.artifact) == 232


def test_singleattestation_oob_attester_index_encoded():
    p = pl.build_singleattestation_oob(attester_index=0xDEAD_BEEF)
    # attester_index is the first 8 bytes (little-endian u64)
    idx = int.from_bytes(p.artifact[:8], "little")
    assert idx == 0xDEAD_BEEF


def test_singleattestation_oob_slot_encoded():
    p = pl.build_singleattestation_oob(slot=99)
    # slot starts at byte 8 (after attester_index)
    slot = int.from_bytes(p.artifact[8:16], "little")
    assert slot == 99


def test_singleattestation_oob_committee_index_encoded():
    p = pl.build_singleattestation_oob(committee_index=7)
    # committee_index starts at byte 16 (after attester_index + slot)
    ci = int.from_bytes(p.artifact[16:24], "little")
    assert ci == 7


def test_singleattestation_oob_zero_signature():
    p = pl.build_singleattestation_oob()
    # signature is the last 96 bytes, all zero
    sig = p.artifact[-96:]
    assert sig == b"\x00" * 96


def test_build_payload_routes_singleattestation():
    p = pl.build_payload("singleattestation_oob_attester_index", {"attester_index": "12345"})
    assert p.generator == "singleattestation_oob_attester_index"
    idx = int.from_bytes(p.artifact[:8], "little")
    assert idx == 12345