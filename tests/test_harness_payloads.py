"""Payload-builder tests — each driver constructs the documented attack regime.

Pure/offline: verifies the construction half of each driver against the real
attack_scenario numbers, without any network.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from harness.drivers import payloads as pl
from harness.drivers.base import get_driver
from harness.schema import load_finding_spec

BUNDLES = [Path("tests/fixtures/sample_finding.json")]


def test_rlpx_header_declares_16mib_body():
    p = pl.build_rlpx_oversized_header(count=500)
    assert len(p.artifact) == pl.RLPX_FRAME_HEADER_LEN
    # first 3 bytes = big-endian body length the victim reserves
    assert int.from_bytes(p.artifact[0:3], "big") == 0xFFFFFF
    # tiny to send, huge to hold: ~16 MiB reserved per session
    assert p.sent_bytes < p.victim_cost_bytes
    assert p.victim_cost_bytes == 0xFFFFFF * 500


def test_pooled_tx_hashes_unique_and_under_frame_limit():
    p = pl.build_newpooledtxhashes(500_000)
    assert p.count == 500_000
    assert p.unique_count == 500_000          # all unique -> no dedup short-circuit
    assert p.sent_bytes < pl.MAX_RLPX_FRAME_BYTES  # stays under the 16 MiB frame cap


def test_block_hashes_entries_unique():
    p = pl.build_newblockhashes(250_000)
    assert p.count == 250_000
    assert p.unique_count == 250_000


def test_fork_blocks_unique_roots_bypass_dedup():
    p = pl.build_fork_blocks(20_000)
    assert p.unique_count == 20_000  # distinct roots -> each retained in TreeState


def test_gossip_blocks_real_ssz_unique_graffiti():
    p = pl.build_far_future_blocks(200, slot_offset=1_000_000)
    assert p.count == 200
    assert p.unique_count == 200  # unique graffiti -> unique hash_tree_root -> bypass dedup
    assert len(p.artifact) > 100  # a real SSZ-encoded SignedBeaconBlock


@pytest.mark.parametrize("spec_path", BUNDLES, ids=[p.parent.name for p in BUNDLES])
def test_driver_builds_payload_for_every_bundle(spec_path):
    spec = load_finding_spec(spec_path)
    driver = get_driver(spec.attack_surface)
    payload = driver.build_payload(spec)
    assert payload.generator == spec.attacker_input.generator
    assert payload.count > 0
    assert payload.unique_count == payload.count  # dedup-bypass holds for all
