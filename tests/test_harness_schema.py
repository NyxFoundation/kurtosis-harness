"""Schema tests — the real grandine finding.json must validate, bad specs must not."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from harness.schema import (
    AttackSurface,
    FindingSpec,
    NegativeControlType,
    ResourceSignal,
    load_finding_spec,
)

REAL_FINDING = Path("tests/fixtures/sample_finding.json")


def test_real_grandine_finding_validates():
    spec = load_finding_spec(REAL_FINDING)
    assert spec.vuln_id == "PROP-val-eth-003"
    assert spec.client == "grandine"
    assert spec.attack_surface is AttackSurface.P2P_GOSSIP
    assert spec.resource_signal is ResourceSignal.RSS
    assert spec.threshold.metric == "rss_delta_mb"
    assert spec.negative_control.type is NegativeControlType.PATCH
    # ④ obligation must be expressed
    assert spec.keep_mitigations_on == ["gossipsub_peer_scoring"]
    # spec divergence must be cited
    assert "MAXIMUM_GOSSIP_CLOCK_DISPARITY" in spec.spec_ref


def _base_dict() -> dict:
    return json.loads(REAL_FINDING.read_text(encoding="utf-8"))


def test_driver_must_match_surface():
    bad = _base_dict()
    bad["attacker_input"]["driver"] = "txpool"  # mismatch vs p2p-gossip
    with pytest.raises(ValueError):
        FindingSpec.model_validate(bad)


def test_unknown_metric_rejected():
    bad = _base_dict()
    bad["threshold"]["metric"] = "made_up_metric"
    with pytest.raises(ValueError):
        FindingSpec.model_validate(bad)


def test_unknown_attack_surface_rejected():
    bad = _base_dict()
    bad["attack_surface"] = "carrier-pigeon"
    with pytest.raises(ValueError):
        FindingSpec.model_validate(bad)


def test_negative_control_is_required():
    bad = _base_dict()
    del bad["negative_control"]
    with pytest.raises(ValueError):
        FindingSpec.model_validate(bad)


def test_negative_control_ref_exists_for_patch_type():
    # A patch-type negative control must point at a real diff on disk —
    # otherwise the A/B (E) can't be built and the verdict is unprovable.
    spec = load_finding_spec(REAL_FINDING)
    if spec.negative_control.type is NegativeControlType.PATCH:
        assert Path(spec.negative_control.ref).is_file(), (
            f"negative_control patch missing: {spec.negative_control.ref}"
        )
