"""L3 verdict engine — encodes the four proof obligations as an A/B decision.

A finding is CONFIRMED only when all four hold:

  ① reachable           : the driver's input reached the entry point
  ③ baseline symptom    : the unguarded build shows the symptom
  ② guarded clears it   : applying the negative control removes the symptom
                          (causation, not correlation)
  ④ survives mitigations: with default mitigations enabled, it still fires

Anything short of that maps to a named non-confirmed verdict so we never
report a false positive by accident.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .observer import RunMetrics, evaluate_threshold
from .schema import Threshold


class Variant(str, Enum):
    BASELINE = "baseline"            # unguarded build, mitigations ON
    GUARDED = "guarded"             # negative control applied (E)
    MITIGATIONS_ON = "mitigations_on"  # explicit ④ check (default defenses)


class Verdict(str, Enum):
    CONFIRMED = "CONFIRMED"
    NOT_REACHABLE = "NOT_REACHABLE"            # ① failed
    NOT_REPRODUCED = "NOT_REPRODUCED"          # ③ failed — symptom never seen
    FALSE_POSITIVE_RISK = "FALSE_POSITIVE_RISK"  # ② failed — guard didn't help
    MITIGATED_IN_PRACTICE = "MITIGATED_IN_PRACTICE"  # ④ failed — defenses hold
    INCOMPLETE = "INCOMPLETE"                  # a required variant is missing


@dataclass
class VerdictResult:
    verdict: Verdict
    reasons: list[str]

    @property
    def is_confirmed(self) -> bool:
        return self.verdict is Verdict.CONFIRMED


REQUIRED_VARIANTS = (Variant.BASELINE, Variant.GUARDED, Variant.MITIGATIONS_ON)


def decide(
    observations: dict[Variant, RunMetrics],
    threshold: Threshold,
) -> VerdictResult:
    """Apply the four obligations in order; first failure names the verdict."""
    reasons: list[str] = []

    missing = [v for v in REQUIRED_VARIANTS if v not in observations]
    if missing:
        return VerdictResult(
            Verdict.INCOMPLETE,
            [f"missing required variant(s): {', '.join(v.value for v in missing)}"],
        )

    baseline = observations[Variant.BASELINE]
    guarded = observations[Variant.GUARDED]
    mitig = observations[Variant.MITIGATIONS_ON]

    # ① reachability is a precondition on the baseline run.
    if not baseline.reachable:
        return VerdictResult(
            Verdict.NOT_REACHABLE,
            ["baseline: driver input did not reach the entry point (①)"],
        )

    baseline_symptom = evaluate_threshold(baseline, threshold)
    guarded_symptom = evaluate_threshold(guarded, threshold)
    mitig_symptom = evaluate_threshold(mitig, threshold)

    # ③ impact must actually be realized on the unguarded build.
    if not baseline_symptom:
        return VerdictResult(
            Verdict.NOT_REPRODUCED,
            ["baseline: symptom not observed — finding not reproduced (③)"],
        )
    reasons.append("③ baseline symptom observed")

    # ② the negative control must remove the symptom (proves causation).
    if guarded_symptom:
        return VerdictResult(
            Verdict.FALSE_POSITIVE_RISK,
            reasons
            + [
                "guarded: symptom persists after negative control — "
                "the proposed missing-guard is not the cause (② failed); "
                "treat as false-positive risk",
            ],
        )
    reasons.append("② guarded build clears the symptom (causation established)")

    # ④ it must still fire with default mitigations enabled.
    if not mitig_symptom:
        return VerdictResult(
            Verdict.MITIGATED_IN_PRACTICE,
            reasons
            + [
                "mitigations_on: symptom does not fire with default defenses — "
                "real but defended in practice; downgrade/hold (④ failed)",
            ],
        )
    reasons.append("④ survives default mitigations")

    return VerdictResult(Verdict.CONFIRMED, reasons)
