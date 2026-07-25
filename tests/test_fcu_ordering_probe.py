from __future__ import annotations

import pytest

from harness.probes import fcu_ordering as probe


def test_result_flags_bug_when_inverted_accepted():
    r = probe.FcuOrderingResult(
        client="reth", accepts_finalized_ahead_of_safe=True,
        inverted_status="VALID", ordered_status="VALID", head_number=100, note="x")
    assert r.accepts_finalized_ahead_of_safe is True
    assert '"inverted_status": "VALID"' in r.to_json()


def test_run_raises_without_container(monkeypatch):
    monkeypatch.setattr(probe, "discover_el", lambda enclave, client: None)
    with pytest.raises(RuntimeError, match="no 'erigon' el- container"):
        probe.run_fcu_ordering_probe("no-enclave", "erigon")


def test_discover_el_none_for_missing(monkeypatch):
    monkeypatch.setattr(probe, "_el_container", lambda enclave, client: None)
    assert probe.discover_el("no-enclave", "reth") is None
