"""Reusable Engine-API queue-pressure probe against reth — EL-GASPER-LIVE-QUEUE-001.

Finding (reth 03): `ConsensusEngineHandle::new_payload` enqueues onto an
*unbounded* channel (tokio mpsc at engine.rs:146 + crossbeam at mod.rs:392) with
no admission check, so `queue_size` can grow without bound; `should_backpressure`
only delays processing, it never rejects. The static claim is: a CL flooding
`engine_newPayloadV*` faster than the engine drains outpaces processing and grows
memory to OOM.

This probe delivers that flood against a live reth on a Kurtosis devnet and
samples RSS + benign-latency, so the A/B decides the finding on evidence rather
than on the code comment. The measured result on a synced node is that the flood
does **not** grow RSS: reth answers each `newPayloadV3` *synchronously* over
JSON-RPC (INVALID in ~2 ms), so the number of in-flight payloads — and thus the
internal queue depth — is bounded by the client's connection concurrency, not
unbounded. The request/response contract is the admission control the internal
channel lacks. See `run_measured_reth_newpayload_flood` for the metrics contract.
"""

from __future__ import annotations

import collections
import json
import os
import subprocess
import threading
import time
import urllib.error
import urllib.request

from ..drivers.base import make_engine_jwt
from ..observer import mem_to_mib
from .discover import RethTarget, discover_reth


def _jrpc(url, method, params, secret=None, timeout=20):
    headers = {"Content-Type": "application/json"}
    if secret is not None:
        headers["Authorization"] = f"Bearer {make_engine_jwt(secret)}"
    req = urllib.request.Request(
        url,
        data=json.dumps({"jsonrpc": "2.0", "method": method, "params": params, "id": 1}).encode(),
        headers=headers,
    )
    try:
        return json.loads(urllib.request.urlopen(req, timeout=timeout).read())
    except urllib.error.HTTPError as e:
        return {"error": {"http": e.code, "body": e.read()[:160].decode("replace")}}
    except Exception as e:  # noqa: BLE001 — a dropped conn is a datapoint, not a crash
        return {"error": {"exc": str(e)[:160]}}


def _reth_container(enclave: str) -> str | None:
    ids = subprocess.run(
        ["docker", "ps", "-q", "--filter", f"label=com.kurtosistech.enclave-name={enclave}"],
        capture_output=True, text=True, timeout=15,
    ).stdout.split()
    for cid in ids:
        label = subprocess.run(
            ["docker", "inspect", cid, "--format", '{{index .Config.Labels "com.kurtosistech.id"}}'],
            capture_output=True, text=True, timeout=15,
        ).stdout.strip()
        if label.startswith("el-") and "reth" in label:
            return cid
    return None


def _rss_mb(container: str) -> float:
    out = subprocess.run(
        ["docker", "stats", "--no-stream", "--format", "{{.MemUsage}}", container],
        capture_output=True, text=True, timeout=20,
    ).stdout.strip()
    return mem_to_mib(out.split("/")[0].strip())


def _make_payload(head: dict, tx_bytes: int, tx_count: int) -> dict:
    """A well-formed-but-invalid ExecutionPayloadV3.

    parentHash is the live head (so the payload passes the parent lookup and is
    admitted for processing), but blockHash/stateRoot are random, so reth rejects
    it as INVALID cheaply — exactly the fire-and-forget flood the finding assumes.
    Each payload carries ``tx_count`` junk transactions to inflate per-message
    memory, maximising any queue-retention signal.
    """
    return {
        "parentHash": head["hash"],
        "feeRecipient": "0x" + "11" * 20,
        "stateRoot": "0x" + os.urandom(32).hex(),
        "receiptsRoot": "0x" + os.urandom(32).hex(),
        "logsBloom": "0x" + "00" * 256,
        "prevRandao": "0x" + os.urandom(32).hex(),
        "blockNumber": hex(int(head["number"], 16) + 1),
        "gasLimit": head["gasLimit"],
        "gasUsed": "0x0",
        "timestamp": hex(int(head["timestamp"], 16) + 12),
        "extraData": "0x",
        "baseFeePerGas": head.get("baseFeePerGas", "0x7"),
        "blockHash": "0x" + os.urandom(32).hex(),
        "transactions": ["0x" + os.urandom(tx_bytes).hex() for _ in range(tx_count)],
        "withdrawals": [],
        "blobGasUsed": "0x0",
        "excessBlobGas": "0x0",
    }


def run_measured_reth_newpayload_flood(
    t: RethTarget,
    enclave: str,
    *,
    threads: int = 48,
    seconds: int = 16,
    tx_bytes: int = 2048,
    tx_count: int = 64,
    recovery_s: int = 20,
) -> dict:
    """Flood engine_newPayloadV3 and measure the queue-pressure symptom.

    Returns a metrics dict consumable by harness.verdict:

        rss_delta_mb        RSS growth (MiB) from just-before to just-after the flood
        rss_retained_mb     RSS growth still present after ``recovery_s`` idle
        sent                payloads delivered
        status_dist         reth's newPayload status histogram (evidence it processed them)
        benign_latency_*_ms an unrelated engine_getClientVersionV1 call, base vs during
    """
    secret = bytes.fromhex(t.jwt_secret)
    container = _reth_container(enclave)
    if container is None:
        raise RuntimeError(f"no reth el- container in enclave {enclave!r}")

    head = _jrpc(t.rpc_url, "eth_getBlockByNumber", ["latest", False]).get("result")
    if not head:
        raise RuntimeError("could not read reth head block")

    def benign() -> float:
        s = time.time()
        _jrpc(t.engine_url, "engine_getClientVersionV1",
              [{"code": "RH", "name": "x", "version": "1", "commit": "00000000"}], secret)
        return time.time() - s

    base_lat = sorted(benign() for _ in range(5))[2]
    rss_before = _rss_mb(container)

    stop = threading.Event()
    sent = [0]
    status = collections.Counter()
    lock = threading.Lock()

    def flood():
        while not stop.is_set():
            r = _jrpc(t.engine_url, "engine_newPayloadV3",
                      [_make_payload(head, tx_bytes, tx_count), [], "0x" + os.urandom(32).hex()], secret)
            res = r.get("result") or r.get("error") or {}
            with lock:
                sent[0] += 1
                status[res.get("status") or json.dumps(res)[:40]] += 1

    workers = [threading.Thread(target=flood, daemon=True) for _ in range(threads)]
    for w in workers:
        w.start()
    time.sleep(seconds)
    during = sorted(benign() for _ in range(8))
    stop.set()
    time.sleep(1)
    rss_after = _rss_mb(container)
    time.sleep(recovery_s)
    rss_recovered = _rss_mb(container)

    return {
        "sent": sent[0],
        "threads": threads,
        "seconds": seconds,
        "per_payload_bytes": tx_bytes * tx_count,
        "status_dist": dict(status),
        "rss_before_mb": round(rss_before, 1),
        "rss_after_mb": round(rss_after, 1),
        "rss_delta_mb": round(rss_after - rss_before, 1),
        "rss_retained_mb": round(rss_recovered - rss_before, 1),
        "benign_latency_base_ms": round(base_lat * 1000, 1),
        "benign_latency_during_ms": round(during[len(during) // 2] * 1000, 1),
    }


if __name__ == "__main__":
    import sys

    enclave = sys.argv[1] if len(sys.argv) > 1 else "repro-reth"
    target = discover_reth(enclave)
    if target is None:
        print(f"no reth devnet in enclave {enclave!r}; boot it first (see probes/README.md)")
        sys.exit(1)
    m = run_measured_reth_newpayload_flood(target, enclave)
    print(json.dumps(m, indent=2))
    grew = m["rss_delta_mb"] > 100 or m["rss_retained_mb"] > 100
    print(f"\n[EL-GASPER-LIVE-QUEUE-001] sent={m['sent']} status={m['status_dist']}")
    print(f"  RSS {m['rss_before_mb']}->{m['rss_after_mb']} MiB "
          f"(delta {m['rss_delta_mb']:+}, retained {m['rss_retained_mb']:+})")
    print("  symptom: " + ("QUEUE GROWTH OBSERVED" if grew
                           else "NOT REPRODUCED — synchronous newPayload bounds the queue"))
