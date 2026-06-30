"""Harness runner — orchestrates A (devnet repro) + E (negative control).

The real implementation spins a Kurtosis devnet, runs the attack driver, and
samples resources. That substrate (Docker/Kurtosis/client binaries) is *not*
available in unit tests, so it lives behind the ``Harness`` interface. The
``DryRunHarness`` synthesizes observations from the analytic memory model so
the schema → observer → verdict pipeline is fully testable offline.
"""

from __future__ import annotations

from typing import Protocol

from .observer import (
    RunMetrics,
    estimate_memory_growth,
    evaluate_threshold,
    reduce_samples,
    synth_rss_series,
)
from .schema import FindingSpec, ResourceSignal
from .verdict import REQUIRED_VARIANTS, Variant, VerdictResult, decide


class Harness(Protocol):
    """A backend that can run one (finding, variant) and return its metrics."""

    def run(self, spec: FindingSpec, variant: Variant) -> RunMetrics: ...


class DryRunHarness:
    """Offline backend: derives metrics from the analytic model, no devnet.

    Models the expected behaviour of each variant for an unbounded-growth
    finding so verdict wiring can be exercised end-to-end:

    * baseline        — full linear growth (symptom fires)
    * guarded         — negative control caps the buffer (no growth)
    * mitigations_on  — peer scoring slows but does not stop it (still fires)
    """

    def __init__(self, *, mitigations_effective: bool = False):
        # If the existing mitigations actually defend, ④ fails — expose this so
        # tests can model both a real bug and a defended-in-practice one.
        self.mitigations_effective = mitigations_effective

    def run(self, spec: FindingSpec, variant: Variant) -> RunMetrics:
        if spec.resource_signal is ResourceSignal.RSS:
            return self._run_rss(spec, variant)
        if spec.resource_signal is ResourceSignal.CPU:
            return self._run_cpu(spec, variant)
        raise NotImplementedError(
            f"DryRunHarness does not model {spec.resource_signal} yet"
        )

    def _run_rss(self, spec: FindingSpec, variant: Variant) -> RunMetrics:
        """Unbounded-memory model: heap grows linearly with the flood count."""
        count = int(spec.attacker_input.params.get("count", 50_000))
        per_item = int(spec.attacker_input.params.get("per_item_bytes", 1024))
        effective = self._effective_count(variant, count)
        return reduce_samples(
            synth_rss_series(effective, per_item_bytes=per_item), reachable=True
        )

    def _run_cpu(self, spec: FindingSpec, variant: Variant) -> RunMetrics:
        """Task-saturation model: CPU rises with the amount of work processed.

        Used for findings like an O(N) per-message loop over an attacker-sized
        list (e.g. NewPooledTransactionHashes into a fixed-size LRU). The guard
        caps the processed count to the protocol soft limit, dropping CPU back.
        """
        count = int(spec.attacker_input.params.get("count", 100_000))
        soft_limit = int(spec.attacker_input.params.get("soft_limit", 4096))
        effective = self._effective_count(variant, count, guarded_floor=soft_limit)
        cpu_pct = min(99.0, 5.0 + 90.0 * min(1.0, effective / 100_000))
        return RunMetrics(cpu_pct=cpu_pct, reachable=True)

    def _effective_count(
        self, variant: Variant, count: int, *, guarded_floor: int = 0
    ) -> int:
        """How much of the flood each variant actually processes."""
        if variant is Variant.GUARDED:
            # Negative control caps the work to a safe floor (0 for buffers,
            # the protocol soft limit for per-message loops).
            return guarded_floor
        if variant is Variant.MITIGATIONS_ON and self.mitigations_effective:
            return guarded_floor
        if variant is Variant.MITIGATIONS_ON:
            # Default defenses merely slow the flood; symptom still builds.
            return count // 2
        return count  # baseline


def run_finding(spec: FindingSpec, harness: Harness) -> VerdictResult:
    """Run all required variants through ``harness`` and decide a verdict."""
    observations = {v: harness.run(spec, v) for v in REQUIRED_VARIANTS}
    return decide(observations, spec.threshold)


def main(argv: list[str] | None = None) -> int:
    """CLI: ``python -m harness <finding.json> [--devnet]``."""
    import argparse

    from .schema import load_finding_spec

    parser = argparse.ArgumentParser(prog="harness", description="Validate a finding (A+E).")
    parser.add_argument("finding", help="path to a finding.json")
    parser.add_argument(
        "--devnet",
        action="store_true",
        help="use the live Kurtosis backend (needs Docker + kurtosis); "
        "default is the offline DryRun model",
    )
    parser.add_argument(
        "--guarded-image",
        help="patched client image for the guarded variant when --devnet is used",
    )
    parser.add_argument(
        "--keep-enclave",
        action="store_true",
        help="leave Kurtosis enclaves running after a devnet run for inspection",
    )
    args = parser.parse_args(argv)

    spec = load_finding_spec(args.finding)
    if args.devnet:
        from .devnet.kurtosis import KurtosisHarness

        variant_images = None
        if args.guarded_image:
            variant_images = {Variant.GUARDED: {spec.client: args.guarded_image}}
        harness: Harness = KurtosisHarness(
            keep_enclave=args.keep_enclave,
            variant_images=variant_images,
        )
        backend = "kurtosis"
    else:
        harness = DryRunHarness()
        backend = "dryrun"

    result = run_finding(spec, harness)
    print(f"{spec.vuln_id} [{spec.client}/{spec.attack_surface.value}] backend={backend}")
    print(f"  verdict: {result.verdict.value}")
    for r in result.reasons:
        print(f"    - {r}")
    return 0 if result.is_confirmed else 1


__all__ = [
    "Harness",
    "DryRunHarness",
    "run_finding",
    "estimate_memory_growth",
    "evaluate_threshold",
]
