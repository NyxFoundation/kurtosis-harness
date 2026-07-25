"""L0 devnet substrate — Kurtosis backend (higher fidelity than plain Docker).

Kurtosis boots a spec-correct devnet (real genesis, EL+CL pairing, block
production, a real gossip mesh with peer scoring) via the ethpandaops
ethereum-package. That realistic operating state — with default mitigations
actually running — is what makes obligation ④ credible and is required for the
CL-dependent findings (engine_newPayload, consensus gossip).

Kurtosis services are ordinary Docker containers (labelled
``com.kurtosistech.enclave-name`` / ``com.kurtosistech.id``), so the live
resource sampling reuses the Docker backend's ``sample_container``.

The enclave lifecycle + sampling are real and live-tested against a minimal
enclave. Full-package runs now boot the target, resolve its service endpoints,
drive the registered attack/probe, and reduce pre/post ``docker stats`` samples.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
import time
import threading
from pathlib import Path
import urllib.request

from ..drivers.base import DriverNotImplemented, DriverTarget, get_driver
from ..observer import ResourceSample, RunMetrics, reduce_samples
from ..schema import AttackSurface, FindingSpec, NegativeControlType
from ..verdict import Variant
from .docker import sample_container

DEFAULT_PACKAGE = "github.com/ethpandaops/ethereum-package"

# client -> consensus/execution layer, for building the participant config.
_CLIENT_LAYER = {
    "geth": "el", "nethermind": "el", "besu": "el", "erigon": "el", "reth": "el",
    "lighthouse": "cl", "lodestar": "cl", "nimbus": "cl", "prysm": "cl",
    "teku": "cl", "grandine": "cl",
}
# a light counterpart so the devnet actually produces blocks.
_DEFAULT_EL = "geth"
_DEFAULT_CL = "lighthouse"


class DevnetUnavailable(RuntimeError):
    """Raised when the Kurtosis CLI/engine isn't usable."""


def build_ethereum_package_args(client: str) -> dict:
    """Participant config selecting ``client`` as the node under test.

    Pure/testable: an EL target is paired with a default CL and vice-versa, so
    the devnet finalises and the target runs in a realistic state.
    """
    layer = _CLIENT_LAYER.get(client)
    if layer == "el":
        participant = {"el_type": client, "cl_type": _DEFAULT_CL}
    elif layer == "cl":
        participant = {"el_type": _DEFAULT_EL, "cl_type": client}
    else:
        raise ValueError(f"unknown client {client!r}")
    return {"participants": [participant]}


class KurtosisHarness:
    """Live A+E backend over Kurtosis (implements runner.Harness)."""

    def __init__(
        self,
        *,
        package: str = DEFAULT_PACKAGE,
        kurtosis_bin: str = "kurtosis",
        samples: int = 5,
        interval: float = 0.5,
        keep_enclave: bool = False,
        boot_timeout: int = 1800,
        variant_images: dict[Variant, dict[str, str]] | None = None,
    ):
        self.package = package
        self.kurtosis_bin = kurtosis_bin
        self.samples = samples
        self.interval = interval
        self.keep_enclave = keep_enclave
        self.boot_timeout = boot_timeout
        # Optional image overrides used for negative-control builds. Shape:
        # {Variant.GUARDED: {"grandine": "local/grandine:guarded"}}
        self.variant_images = variant_images or {}

    # --- availability ------------------------------------------------------
    def available(self) -> bool:
        if shutil.which(self.kurtosis_bin) is None:
            return False
        try:
            out = subprocess.run(
                [self.kurtosis_bin, "engine", "status"],
                capture_output=True, text=True, timeout=20,
            )
            return "running" in out.stdout.lower()
        except (subprocess.SubprocessError, OSError):
            return False

    # --- enclave lifecycle (real, live-tested) -----------------------------
    def run_package(self, target: str, *, enclave: str, args_file: str | None = None) -> str:
        cmd = [self.kurtosis_bin, "run", target, "--enclave", enclave]
        if args_file:
            cmd += ["--args-file", args_file]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=self.boot_timeout)
        if proc.returncode != 0:
            raise DevnetUnavailable(f"kurtosis run failed: {proc.stderr.strip()[:400]}")
        return enclave

    def rm_enclave(self, enclave: str) -> None:
        subprocess.run(
            [self.kurtosis_bin, "enclave", "rm", "-f", enclave],
            capture_output=True, timeout=120,
        )

    def resolve_service_container(self, enclave: str, service: str) -> str:
        """Docker container id backing a Kurtosis service, via its labels."""
        proc = subprocess.run(
            [
                "docker", "ps", "-q",
                "--filter", f"label=com.kurtosistech.enclave-name={enclave}",
                "--filter", f"label=com.kurtosistech.id={service}",
            ],
            capture_output=True, text=True, timeout=20,
        )
        cid = proc.stdout.strip().splitlines()
        if not cid:
            raise DevnetUnavailable(f"no container for service {service!r} in {enclave!r}")
        return cid[0]

    def service_private_ip(self, enclave: str, service: str) -> str:
        cid = self.resolve_service_container(enclave, service)
        proc = subprocess.run(
            ["docker", "inspect", cid, "--format",
             "{{index .Config.Labels \"com.kurtosistech.private-ip\"}}"],
            capture_output=True, text=True, timeout=20,
        )
        return proc.stdout.strip()

    def sample_service(self, enclave: str, service: str) -> list[ResourceSample]:
        cid = self.resolve_service_container(enclave, service)
        return sample_container(cid, samples=self.samples, interval=self.interval)

    def find_target_service(self, enclave: str, client: str) -> str:
        """Return the Kurtosis service id for the target client."""
        preferred_prefix = "el-" if _CLIENT_LAYER.get(client) == "el" else "cl-"
        proc = subprocess.run(
            [
                "docker", "ps", "-q",
                "--filter", f"label=com.kurtosistech.enclave-name={enclave}",
            ],
            capture_output=True, text=True, timeout=20,
        )
        for cid in proc.stdout.split():
            label = subprocess.run(
                [
                    "docker", "inspect", cid, "--format",
                    '{{index .Config.Labels "com.kurtosistech.id"}}',
                ],
                capture_output=True, text=True, timeout=20,
            ).stdout.strip()
            if client in label and label.startswith(preferred_prefix):
                return label
        for cid in proc.stdout.split():
            label = subprocess.run(
                [
                    "docker", "inspect", cid, "--format",
                    '{{index .Config.Labels "com.kurtosistech.id"}}',
                ],
                capture_output=True, text=True, timeout=20,
            ).stdout.strip()
            if client in label and (label.startswith("cl-") or label.startswith("el-")):
                return label
        raise DevnetUnavailable(f"no Kurtosis service for client {client!r} in {enclave!r}")

    def _host_port(self, container: str, port: str) -> int | None:
        proc = subprocess.run(
            ["docker", "port", container, port],
            capture_output=True, text=True, timeout=20,
        )
        for line in proc.stdout.splitlines():
            tail = line.rsplit(":", 1)[-1]
            if tail.isdigit():
                return int(tail)
        return None

    def target_for(self, enclave: str, service: str, spec: FindingSpec) -> DriverTarget:
        """Resolve public host endpoints for the selected service."""
        cid = self.resolve_service_container(enclave, service)
        layer = _CLIENT_LAYER.get(spec.client)
        if layer == "cl":
            beacon_port = self._host_port(cid, "4000") or self._host_port(cid, "5052")
            return DriverTarget(
                rpc_url=f"http://127.0.0.1:{beacon_port}" if beacon_port else "",
            )
        if layer == "el":
            rpc_port = self._host_port(cid, "8545")
            engine_port = self._host_port(cid, "8551")
            p2p_port = self._host_port(cid, "30303")
            jwt = subprocess.run(
                ["docker", "exec", cid, "cat", "/jwt/jwtsecret"],
                capture_output=True, text=True, timeout=20,
            ).stdout.strip()
            enode = ""
            if rpc_port and p2p_port:
                deadline = time.time() + 120
                req = urllib.request.Request(
                    f"http://127.0.0.1:{rpc_port}",
                    data=json.dumps(
                        {"jsonrpc": "2.0", "method": "admin_nodeInfo", "params": [], "id": 1}
                    ).encode(),
                    headers={"Content-Type": "application/json"},
                )
                while time.time() < deadline and not enode:
                    try:
                        result = json.loads(urllib.request.urlopen(req, timeout=10).read())["result"]
                        enode = result.get("enode", "")
                        if enode and "@127.0.0.1" not in enode:
                            enode = re.sub(r"@[^:]+:(\d+)$", f"@127.0.0.1:{p2p_port}", enode)
                    except Exception:
                        time.sleep(2)
            return DriverTarget(
                enode_or_multiaddr=enode,
                rpc_url=f"http://127.0.0.1:{rpc_port}" if rpc_port else "",
                engine_url=f"http://127.0.0.1:{engine_port}" if engine_port else "",
                jwt_secret=jwt,
            )
        raise DevnetUnavailable(f"unknown client layer for {spec.client!r}")

    def _args_for(self, spec: FindingSpec, variant: Variant) -> dict:
        args = build_ethereum_package_args(spec.client)
        image = self.variant_images.get(variant, {}).get(spec.client)
        if image:
            participant = args["participants"][0]
            if _CLIENT_LAYER[spec.client] == "cl":
                participant["cl_image"] = image
            else:
                participant["el_image"] = image
        elif variant is Variant.GUARDED and spec.negative_control.type is NegativeControlType.PATCH:
            raise DevnetUnavailable(
                "guarded Kurtosis run requires a prebuilt patched image; pass "
                "variant_images={Variant.GUARDED: {client: image}}"
            )
        return args

    def _write_args_file(self, args: dict) -> str:
        f = tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", suffix=".json", prefix="kurtosis-args-", delete=False
        )
        with f:
            json.dump(args, f)
        return f.name

    def _wait_for_target(self, enclave: str, spec: FindingSpec) -> str:
        deadline = time.time() + 300
        last_error: Exception | None = None
        while time.time() < deadline:
            try:
                return self.find_target_service(enclave, spec.client)
            except DevnetUnavailable as e:
                last_error = e
                time.sleep(3)
        raise DevnetUnavailable(f"target did not appear in {enclave!r}: {last_error}")

    # --- Harness protocol --------------------------------------------------
    def run(self, spec: FindingSpec, variant: Variant) -> RunMetrics:
        if not self.available():
            raise DevnetUnavailable(
                "Kurtosis engine not running. `kurtosis engine start` (needs Docker), "
                "or use DryRunHarness for the offline model."
            )
        enclave = f"repro-{spec.vuln_id.lower()}-{variant.value}"
        args_file = self._write_args_file(self._args_for(spec, variant))
        try:
            self.run_package(self.package, enclave=enclave, args_file=args_file)
            service = self._wait_for_target(enclave, spec)
            cid = self.resolve_service_container(enclave, service)
            before = sample_container(cid, samples=1, interval=0.0)
            target = self.target_for(enclave, service, spec)
            mid_samples: list[ResourceSample] = []
            stop_sampling = threading.Event()

            def _sample_during() -> None:
                while not stop_sampling.is_set():
                    mid_samples.extend(sample_container(cid, samples=1, interval=0.0))
                    time.sleep(self.interval)

            sampler = threading.Thread(target=_sample_during, daemon=True)
            sampler.start()

            try:
                if spec.client == "grandine" and spec.attack_surface is AttackSurface.P2P_GOSSIP:
                    generator = spec.attacker_input.generator
                    if generator == "singleattestation_oob_attester_index":
                        from ..probes.grandine_singleattestation_attack import (
                            run_singleattestation_attack,
                        )

                        run_singleattestation_attack(
                            enclave=enclave,
                            attester_index=int(
                                spec.attacker_input.params.get(
                                    "attester_index", 0xFFFF_FFFF
                                )
                            ),
                            subnet_id=int(spec.attacker_input.params.get("subnet_id", 0)),
                        )
                    else:
                        from ..probes.grandine_libp2p_attack import (
                            run_grandine_libp2p_attack,
                        )

                        run_grandine_libp2p_attack(
                            enclave=enclave,
                            count=int(spec.attacker_input.params.get("count", 100_000)),
                            slot_offset=int(spec.attacker_input.params.get("slot_offset", 1_000_000)),
                        )
                else:
                    driver = get_driver(spec.attack_surface)
                    driver.emit(spec, target)
            finally:
                stop_sampling.set()
                sampler.join(timeout=10)

            after = sample_container(cid, samples=1, interval=0.0)
            return reduce_samples(before + mid_samples + after, reachable=True)
        finally:
            Path(args_file).unlink(missing_ok=True)
            if not self.keep_enclave:
                self.rm_enclave(enclave)

    def _reduce(self, samples: list[ResourceSample]) -> RunMetrics:
        return reduce_samples(samples, reachable=True)
