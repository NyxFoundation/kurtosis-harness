"""L2 observer — language-agnostic resource observation.

Two pure pieces, both testable offline:

* ``evaluate_threshold`` — given a sampled resource series + a Threshold,
  decide whether the symptom fired. Process-level metrics (RSS/CPU/restarts)
  are client-language-agnostic, which is what keeps the harness client-agnostic.
* ``estimate_memory_growth`` — the analytic model carried over from the real
  grandine PoC (reports/grandine/poc/PROP-val-eth-003/poc.py). Lets us
  smoke-test verdict logic without a live devnet.
"""

from __future__ import annotations

from dataclasses import dataclass

from .schema import Threshold, ThresholdOp


@dataclass
class ResourceSample:
    """A single point in a resource time series."""

    t_seconds: float
    rss_mb: float
    cpu_pct: float = 0.0


@dataclass
class RunMetrics:
    """Reduced metrics from one run, keyed by the names in schema.KNOWN_METRICS."""

    rss_delta_mb: float = 0.0
    peak_rss_mb: float = 0.0
    cpu_pct: float = 0.0
    restart_count: int = 0
    reexec_count: int = 0
    reachable: bool = True  # did the driver's input reach the entry point? (①)

    def get(self, metric: str) -> float:
        if not hasattr(self, metric):
            raise KeyError(f"unknown metric {metric!r}")
        return float(getattr(self, metric))


def reduce_samples(
    samples: list[ResourceSample],
    *,
    restart_count: int = 0,
    reexec_count: int = 0,
    reachable: bool = True,
) -> RunMetrics:
    """Collapse a sample series into RunMetrics."""
    if not samples:
        return RunMetrics(
            restart_count=restart_count, reexec_count=reexec_count, reachable=reachable
        )
    rss = [s.rss_mb for s in samples]
    baseline = rss[0]
    peak = max(rss)
    return RunMetrics(
        rss_delta_mb=peak - baseline,
        peak_rss_mb=peak,
        cpu_pct=max(s.cpu_pct for s in samples),
        restart_count=restart_count,
        reexec_count=reexec_count,
        reachable=reachable,
    )


_OPS = {
    ThresholdOp.GT: lambda a, b: a > b,
    ThresholdOp.GE: lambda a, b: a >= b,
    ThresholdOp.LT: lambda a, b: a < b,
    ThresholdOp.LE: lambda a, b: a <= b,
}


def evaluate_threshold(metrics: RunMetrics, threshold: Threshold) -> bool:
    """True iff the observed metric satisfies the threshold predicate (= symptom)."""
    observed = metrics.get(threshold.metric)
    return _OPS[threshold.op](observed, threshold.value)


# ---------------------------------------------------------------------------
# Live observation: parse `docker stats` output into a ResourceSample
# ---------------------------------------------------------------------------

# docker reports binary (iB) units; we keep one scale and label it "mb".
_MEM_UNIT_TO_MIB = {
    "B": 1.0 / (1024 * 1024),
    "KiB": 1.0 / 1024,
    "MiB": 1.0,
    "GiB": 1024.0,
    "kB": 1000.0 / (1024 * 1024),
    "MB": 1_000_000.0 / (1024 * 1024),
    "GB": 1_000_000_000.0 / (1024 * 1024),
}


def mem_to_mib(value: str) -> float:
    """Parse a docker mem figure like '12.5MiB' or '1.5GiB' to MiB."""
    s = value.strip()
    for unit, scale in sorted(_MEM_UNIT_TO_MIB.items(), key=lambda kv: -len(kv[0])):
        if s.endswith(unit):
            return float(s[: -len(unit)].strip()) * scale
    raise ValueError(f"unrecognised mem figure: {value!r}")


def parse_docker_stats(mem_usage: str, cpu_perc: str) -> ResourceSample:
    """Build a ResourceSample from `docker stats` MemUsage + CPUPerc fields.

    ``mem_usage`` looks like '12.5MiB / 7.5GiB' (used / limit); ``cpu_perc``
    like '3.40%'. t_seconds is left 0 — the sampler stamps it.
    """
    used = mem_usage.split("/")[0]
    cpu = float(cpu_perc.strip().rstrip("%"))
    return ResourceSample(t_seconds=0.0, rss_mb=mem_to_mib(used), cpu_pct=cpu)


# ---------------------------------------------------------------------------
# Analytic memory model (carried over verbatim in spirit from the PoC)
# ---------------------------------------------------------------------------

# From poc.py estimate_memory_growth: each buffered block costs the SSZ block
# size plus per-PendingBlock metadata overhead (origin, timings, span).
PENDING_BLOCK_OVERHEAD_BYTES = 512


def estimate_memory_growth(count: int, per_item_bytes: int = 1024) -> float:
    """Estimated heap growth in MB for ``count`` buffered items.

    Mirrors the grandine PoC's model so offline smoke tests use the same
    numbers the human-readable PoC reports.
    """
    per_item_heap = per_item_bytes + PENDING_BLOCK_OVERHEAD_BYTES
    total_bytes = count * per_item_heap
    return total_bytes / (1024 * 1024)


def synth_rss_series(
    count: int,
    per_item_bytes: int = 1024,
    *,
    baseline_rss_mb: float = 300.0,
    steps: int = 10,
) -> list[ResourceSample]:
    """Synthesize a plausible RSS series for offline testing.

    Models unbounded linear growth on top of a baseline RSS, matching the
    PoC's "linear with each incoming block, no eviction" behaviour.
    """
    total = estimate_memory_growth(count, per_item_bytes)
    samples: list[ResourceSample] = []
    for i in range(steps + 1):
        frac = i / steps
        samples.append(
            ResourceSample(
                t_seconds=float(i),
                rss_mb=baseline_rss_mb + total * frac,
                cpu_pct=20.0,
            )
        )
    return samples
