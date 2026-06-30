"""Observer tests — threshold evaluation and the PoC-grounded memory model."""
from __future__ import annotations

import pytest

from harness.observer import (
    PENDING_BLOCK_OVERHEAD_BYTES,
    ResourceSample,
    estimate_memory_growth,
    evaluate_threshold,
    reduce_samples,
    synth_rss_series,
)
from harness.schema import Threshold, ThresholdOp


def test_reduce_samples_computes_delta_and_peak():
    samples = [
        ResourceSample(0, 300.0),
        ResourceSample(1, 800.0),
        ResourceSample(2, 1200.0),
    ]
    m = reduce_samples(samples)
    assert m.peak_rss_mb == 1200.0
    assert m.rss_delta_mb == 900.0


@pytest.mark.parametrize(
    "op,value,expected",
    [
        (ThresholdOp.GT, 300, True),
        (ThresholdOp.GT, 900, False),
        (ThresholdOp.GE, 900, True),
        (ThresholdOp.LT, 1000, True),
        (ThresholdOp.LE, 900, True),
    ],
)
def test_evaluate_threshold(op, value, expected):
    m = reduce_samples([ResourceSample(0, 300.0), ResourceSample(1, 1200.0)])
    th = Threshold(metric="rss_delta_mb", op=op, value=value)
    assert evaluate_threshold(m, th) is expected


def test_estimate_memory_growth_matches_poc_model():
    # poc.py: per_item_heap = per_item_bytes + 512; total in MB.
    assert PENDING_BLOCK_OVERHEAD_BYTES == 512
    mb = estimate_memory_growth(100_000, per_item_bytes=1024)
    expected_bytes = 100_000 * (1024 + 512)
    assert mb == pytest.approx(expected_bytes / (1024 * 1024))
    # 100k blocks -> ~146 MB under the PoC's conservative 1.5KB/block model.
    assert 140 < mb < 150


def test_estimate_memory_growth_monotonic():
    assert estimate_memory_growth(10_000) < estimate_memory_growth(50_000)


def test_synth_series_grows_from_baseline():
    series = synth_rss_series(50_000, baseline_rss_mb=300.0, steps=10)
    assert series[0].rss_mb == 300.0
    assert series[-1].rss_mb > series[0].rss_mb
    m = reduce_samples(series)
    # delta should equal the analytic estimate
    assert m.rss_delta_mb == pytest.approx(estimate_memory_growth(50_000), rel=1e-6)
