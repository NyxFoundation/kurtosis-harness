"""Verdict tests — the four proof obligations map to the right verdicts.

These are the tests that actually defend "zero false positive": each obligation
failure must yield a *non*-CONFIRMED verdict.
"""
from __future__ import annotations

from harness.observer import RunMetrics
from harness.runner import DryRunHarness, run_finding
from harness.schema import Threshold, ThresholdOp, load_finding_spec
from harness.verdict import Variant, Verdict, decide

THRESHOLD = Threshold(metric="rss_delta_mb", op=ThresholdOp.GT, value=300)


def _m(rss_delta_mb=0.0, reachable=True) -> RunMetrics:
    return RunMetrics(rss_delta_mb=rss_delta_mb, peak_rss_mb=rss_delta_mb, reachable=reachable)


def test_confirmed_when_all_obligations_met():
    obs = {
        Variant.BASELINE: _m(900),         # ③ fires
        Variant.GUARDED: _m(5),            # ② cleared
        Variant.MITIGATIONS_ON: _m(700),   # ④ survives
    }
    res = decide(obs, THRESHOLD)
    assert res.verdict is Verdict.CONFIRMED
    assert res.is_confirmed


def test_not_reproduced_when_baseline_silent():
    obs = {
        Variant.BASELINE: _m(10),
        Variant.GUARDED: _m(5),
        Variant.MITIGATIONS_ON: _m(10),
    }
    assert decide(obs, THRESHOLD).verdict is Verdict.NOT_REPRODUCED


def test_false_positive_risk_when_guard_does_not_help():
    # symptom persists even after the proposed missing-guard -> wrong root cause.
    obs = {
        Variant.BASELINE: _m(900),
        Variant.GUARDED: _m(880),
        Variant.MITIGATIONS_ON: _m(900),
    }
    assert decide(obs, THRESHOLD).verdict is Verdict.FALSE_POSITIVE_RISK


def test_mitigated_in_practice_when_defenses_hold():
    obs = {
        Variant.BASELINE: _m(900),
        Variant.GUARDED: _m(5),
        Variant.MITIGATIONS_ON: _m(20),  # defenses suppress it
    }
    assert decide(obs, THRESHOLD).verdict is Verdict.MITIGATED_IN_PRACTICE


def test_not_reachable_short_circuits():
    obs = {
        Variant.BASELINE: _m(900, reachable=False),
        Variant.GUARDED: _m(5),
        Variant.MITIGATIONS_ON: _m(900),
    }
    assert decide(obs, THRESHOLD).verdict is Verdict.NOT_REACHABLE


def test_incomplete_when_variant_missing():
    obs = {Variant.BASELINE: _m(900), Variant.GUARDED: _m(5)}
    assert decide(obs, THRESHOLD).verdict is Verdict.INCOMPLETE


# --- end-to-end through the dry-run harness on the real finding -------------

def test_real_finding_confirmed_via_dryrun_harness():
    spec = load_finding_spec("tests/fixtures/sample_finding.json")
    res = run_finding(spec, DryRunHarness(mitigations_effective=False))
    assert res.verdict is Verdict.CONFIRMED


def test_real_finding_downgraded_when_mitigations_effective():
    spec = load_finding_spec("tests/fixtures/sample_finding.json")
    res = run_finding(spec, DryRunHarness(mitigations_effective=True))
    assert res.verdict is Verdict.MITIGATED_IN_PRACTICE
