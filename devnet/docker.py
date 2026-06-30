"""L0 devnet substrate — plain Docker backend.

A single-node DoS reproduction does not need Kurtosis's multi-client
orchestration: run the target client image, drive the attack, sample
`docker stats`. Docker is the only dependency, so this backend actually runs in
environments where Kurtosis isn't available (e.g. NixOS without the kurtosis
CLI).

What works offline-of-a-real-attack today: the resource sampler (verified
against a live throwaway container) and the container lifecycle. The attack
send still needs the driver's network implementation; until then `run` builds
the payload and reports the send as pending rather than faking a verdict.
"""

from __future__ import annotations

import shutil
import subprocess
import time

from ..drivers.base import DriverNotImplemented, DriverTarget, get_driver
from ..observer import ResourceSample, RunMetrics, parse_docker_stats, reduce_samples
from ..schema import FindingSpec
from ..verdict import Variant

_STATS_FORMAT = "{{.MemUsage}};{{.CPUPerc}}"


class DockerUnavailable(RuntimeError):
    """Raised when the Docker CLI/daemon isn't usable."""


def docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        subprocess.run(
            ["docker", "info"], capture_output=True, timeout=10, check=True
        )
        return True
    except (subprocess.SubprocessError, OSError):
        return False


def sample_container(
    name_or_id: str, *, samples: int = 3, interval: float = 0.5
) -> list[ResourceSample]:
    """Sample `docker stats` for a running container into a ResourceSample series."""
    out: list[ResourceSample] = []
    for i in range(samples):
        proc = subprocess.run(
            ["docker", "stats", "--no-stream", "--format", _STATS_FORMAT, name_or_id],
            capture_output=True,
            text=True,
            timeout=15,
        )
        line = proc.stdout.strip()
        if not line:
            raise DockerUnavailable(f"no stats for container {name_or_id!r}: {proc.stderr.strip()}")
        mem, cpu = line.split(";")
        s = parse_docker_stats(mem, cpu)
        s.t_seconds = float(i) * interval
        out.append(s)
        if i + 1 < samples:
            time.sleep(interval)
    return out


class DockerHarness:
    """Live A+E backend over plain Docker (implements runner.Harness)."""

    def __init__(self, *, image_for=None, samples: int = 5, interval: float = 0.5):
        # image_for: (spec, variant) -> docker image tag. The guarded variant
        # should map to an image built with spec.negative_control applied.
        self._image_for = image_for or self._default_image_for
        self.samples = samples
        self.interval = interval

    def available(self) -> bool:
        return docker_available()

    def _default_image_for(self, spec: FindingSpec, variant: Variant) -> str:
        raise DockerUnavailable(
            f"no image mapping for {spec.client}/{variant.value}; pass image_for=..."
        )

    def run(self, spec: FindingSpec, variant: Variant) -> RunMetrics:
        if not self.available():
            raise DockerUnavailable(
                "Docker not usable. Start the daemon / join the docker group, "
                "or use DryRunHarness for the offline model."
            )
        image = self._image_for(spec, variant)
        container = self._boot(spec, image)
        try:
            target = self._target_for(container, spec)
            driver = get_driver(spec.attack_surface)
            driver.emit(spec, target)  # raises DriverNotImplemented until send lands
            return reduce_samples(
                sample_container(container, samples=self.samples, interval=self.interval),
                reachable=True,
            )
        finally:
            self._teardown(container)

    # --- container lifecycle (real docker, used by the live test) ----------
    def _boot(self, spec: FindingSpec, image: str) -> str:
        proc = subprocess.run(
            ["docker", "run", "-d", "--rm", image],
            capture_output=True, text=True, timeout=60,
        )
        if proc.returncode != 0:
            raise DockerUnavailable(f"docker run failed: {proc.stderr.strip()}")
        return proc.stdout.strip()

    def _target_for(self, container: str, spec: FindingSpec) -> DriverTarget:
        # Real impl resolves the container's enode/rpc/engine endpoints.
        raise DriverNotImplemented("endpoint resolution for the target container is pending")

    def _teardown(self, container: str) -> None:
        subprocess.run(["docker", "rm", "-f", container], capture_output=True, timeout=30)
