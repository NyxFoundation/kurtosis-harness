from __future__ import annotations

import pytest

from harness.probes import engine_lock_starvation as probe


def test_result_serialises_and_flags_not_reproduced():
    r = probe.LockStarvationResult(
        reproduced=False, client="erigon", unknown_parent_status="SYNCING",
        unknown_parent_latency_ms=12.0, sent_during_flood=71, canonical_base_ms=1.0,
        canonical_during_median_ms=84.0, canonical_during_max_ms=86.0,
        seconds_per_slot_ms=6000.0, note="x")
    assert '"reproduced": false' in r.to_json()
    assert r.canonical_during_median_ms < r.seconds_per_slot_ms * 0.5


def test_run_raises_without_container(monkeypatch):
    monkeypatch.setattr(probe, "discover_el", lambda enclave, client: None)
    with pytest.raises(RuntimeError, match="no 'erigon' el- container"):
        probe.run_lock_starvation_probe("no-enclave", "erigon")
