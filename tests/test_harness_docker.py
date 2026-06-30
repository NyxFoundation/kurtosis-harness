"""Docker backend tests — pure parser (always) + live sampler (skip if no docker).

The live test proves the L2 sampler actually reads resources from a real
container in this environment; it is skipped where Docker is absent (e.g. CI).
"""
from __future__ import annotations

import subprocess
import uuid

import pytest

from harness.devnet.docker import (
    DockerHarness,
    docker_available,
    sample_container,
)
from harness.observer import mem_to_mib, parse_docker_stats

# --- pure parser tests (no docker needed) ----------------------------------


@pytest.mark.parametrize(
    "text,expected_mib",
    [
        ("512B", 512 / (1024 * 1024)),
        ("1.0KiB", 1 / 1024),
        ("12.5MiB", 12.5),
        ("1.5GiB", 1536.0),
    ],
)
def test_mem_to_mib(text, expected_mib):
    assert mem_to_mib(text) == pytest.approx(expected_mib)


def test_parse_docker_stats_line():
    s = parse_docker_stats("250.4MiB / 7.5GiB", "42.0%")
    assert s.rss_mb == pytest.approx(250.4)
    assert s.cpu_pct == pytest.approx(42.0)


def test_mem_to_mib_rejects_garbage():
    with pytest.raises(ValueError):
        mem_to_mib("not-a-size")


# --- live sampler test (real container; skipped without docker) ------------

requires_docker = pytest.mark.skipif(
    not docker_available(), reason="docker not available in this environment"
)


@requires_docker
def test_sample_live_container():
    name = f"harness-sampler-test-{uuid.uuid4().hex[:8]}"
    # caddy:2-alpine is small and stays running; any long-lived local image works.
    run = subprocess.run(
        ["docker", "run", "-d", "--rm", "--name", name, "caddy:2-alpine"],
        capture_output=True, text=True, timeout=60,
    )
    if run.returncode != 0:
        pytest.skip(f"could not start test container: {run.stderr.strip()}")
    try:
        samples = sample_container(name, samples=2, interval=0.3)
        assert len(samples) == 2
        assert all(s.rss_mb > 0 for s in samples)   # a real process uses memory
        assert all(s.cpu_pct >= 0 for s in samples)
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, timeout=30)


@requires_docker
def test_docker_harness_reports_available():
    assert DockerHarness().available() is True
