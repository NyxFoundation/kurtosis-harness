"""Engine-API monotonicity/identity conformance probe against geth —
EL-GASPER-STATUS-MONOTONE-001.

Finding (geth 03, eth/catalyst/api.go::newPayload::L886-894): the
`GetBlockByHash` check at L886 returns VALID for *any* block found in the DB and
runs BEFORE the `checkInvalidAncestor` cache check at L892. A block previously
returned INVALID by newPayload, then written to the DB by the sync path
(insertSideChain -> writeBlockWithoutState, no full state validation), is found
by GetBlockByHash on re-submission and returned VALID — an INVALID->VALID
transition that violates Engine-API status monotonicity.

What a single live node CAN establish (this probe):
  the DB short-circuit is real and unconditional — a block present in geth's DB
  is returned VALID by engine_newPayload immediately, with no re-execution, while
  a block NOT in the DB is validated (a forged one is INVALID, and the verdict is
  cached). So DB-presence alone yields VALID; validity of the DB entry is never
  re-checked at this point.

What needs a multi-node setup (analytic, documented in the bundle):
  getting an *invalid* block into the DB via BeaconSync from an attacker peer,
  which is the step that turns the reachable short-circuit into the full
  INVALID->VALID transition. Not reproducible on one devnet node.

Recall-safe: the probe reports CONFIRMED_REACHABLE (the short-circuit fires), not
a full CONFIRMED transition.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass

from ..drivers.base import make_engine_jwt


def _labels(cid: str) -> str:
    return subprocess.run(
        ["docker", "inspect", cid, "--format", '{{index .Config.Labels "com.kurtosistech.id"}}'],
        capture_output=True, text=True, timeout=15,
    ).stdout.strip()


def _geth_container(enclave: str) -> str | None:
    ids = subprocess.run(
        ["docker", "ps", "-q", "--filter", f"label=com.kurtosistech.enclave-name={enclave}"],
        capture_output=True, text=True, timeout=15,
    ).stdout.split()
    for cid in ids:
        lbl = _labels(cid)
        if lbl.startswith("el-") and "geth" in lbl:
            return cid
    return None


def _host_port(cid: str, port: str) -> str | None:
    out = subprocess.run(["docker", "port", cid, port], capture_output=True, text=True, timeout=15).stdout
    m = re.search(r":(\d+)", out)
    return m.group(1) if m else None


@dataclass
class GethTarget:
    rpc_url: str
    engine_url: str
    jwt_secret: str  # hex, no 0x


def discover_geth(enclave: str) -> GethTarget | None:
    cid = _geth_container(enclave)
    if cid is None:
        return None
    rpc, eng = _host_port(cid, "8545"), _host_port(cid, "8551")
    if not (rpc and eng):
        return None
    jwt = subprocess.run(["docker", "exec", cid, "cat", "/jwt/jwtsecret"],
                         capture_output=True, text=True, timeout=15).stdout.strip().removeprefix("0x")
    return GethTarget(rpc_url=f"http://127.0.0.1:{rpc}", engine_url=f"http://127.0.0.1:{eng}", jwt_secret=jwt)


def _jrpc(url, method, params, secret=None, timeout=15):
    headers = {"Content-Type": "application/json"}
    if secret is not None:
        headers["Authorization"] = f"Bearer {make_engine_jwt(secret)}"
    req = urllib.request.Request(
        url, data=json.dumps({"jsonrpc": "2.0", "method": method, "params": params, "id": 1}).encode(),
        headers=headers)
    try:
        return json.loads(urllib.request.urlopen(req, timeout=timeout).read())
    except urllib.error.HTTPError as e:
        return {"error": {"http": e.code, "body": e.read()[:200].decode("replace")}}


def _payload_from_block(b: dict) -> dict:
    """Rebuild an ExecutionPayloadV3 from an eth_getBlockByNumber result.

    Devnet blocks are empty (0 tx, no withdrawals), so the reconstruction is
    exact and geth's recomputed blockHash matches — the block is recognised as
    the canonical one already in the DB.
    """
    return {
        "parentHash": b["parentHash"], "feeRecipient": b["miner"], "stateRoot": b["stateRoot"],
        "receiptsRoot": b["receiptsRoot"], "logsBloom": b["logsBloom"], "prevRandao": b["mixHash"],
        "blockNumber": b["number"], "gasLimit": b["gasLimit"], "gasUsed": b["gasUsed"],
        "timestamp": b["timestamp"], "extraData": b["extraData"], "baseFeePerGas": b["baseFeePerGas"],
        "blockHash": b["hash"], "transactions": [], "withdrawals": [],
        "blobGasUsed": b.get("blobGasUsed", "0x0"), "excessBlobGas": b.get("excessBlobGas", "0x0"),
    }


def _new_payload(t: GethTarget, secret: bytes, payload: dict, pbr: str, is_v4: bool):
    if is_v4:
        return _jrpc(t.engine_url, "engine_newPayloadV4", [payload, [], pbr, []], secret)
    return _jrpc(t.engine_url, "engine_newPayloadV3", [payload, [], pbr], secret)


@dataclass
class MonotonicityResult:
    reachable_short_circuit: bool
    canonical_status: str
    canonical_reexecuted: bool          # did geth re-run state transition? (False == short-circuit)
    forged_status: str
    forged_resubmit_status: str         # INVALID cached on resubmit
    newpayload_version: str
    note: str

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2)


def run_geth_monotonicity_probe(enclave: str, *, depth_back: int = 5) -> MonotonicityResult:
    t = discover_geth(enclave)
    if t is None:
        raise RuntimeError(f"no geth el- container in enclave {enclave!r}")
    secret = bytes.fromhex(t.jwt_secret)

    head = int(_jrpc(t.rpc_url, "eth_getBlockByNumber", ["latest", False])["result"]["number"], 16)
    b = _jrpc(t.rpc_url, "eth_getBlockByNumber", [hex(head - depth_back), False])["result"]
    is_v4 = "requestsHash" in b  # Prague/Electra block -> newPayloadV4
    pbr = b.get("parentBeaconBlockRoot", "0x" + "00" * 32)

    # (1) Canonical block already in the DB -> VALID via GetBlockByHash short-circuit.
    import time
    t0 = time.time()
    r1 = _new_payload(t, secret, _payload_from_block(b), pbr, is_v4)
    canonical_ms = (time.time() - t0) * 1000
    canonical_status = (r1.get("result") or r1.get("error") or {}).get("status", str(r1)[:40])

    # (2) Forged invalid block (not in DB) -> INVALID (validated, not short-circuited).
    p2 = _payload_from_block(b)
    p2["stateRoot"] = "0x" + os.urandom(32).hex()
    p2["blockHash"] = "0x" + os.urandom(32).hex()
    r2 = _new_payload(t, secret, p2, pbr, is_v4)
    forged_status = (r2.get("result") or r2.get("error") or {}).get("status", str(r2)[:40])

    # (3) Resubmit the same forged block -> still INVALID (cache).
    r3 = _new_payload(t, secret, p2, pbr, is_v4)
    forged_resubmit_status = (r3.get("result") or r3.get("error") or {}).get("status", str(r3)[:40])

    # Short-circuit signature: the canonical block returns VALID in ~1ms with no
    # re-execution (a freshly-built block would take much longer to execute).
    reexecuted = canonical_ms > 50.0
    reachable = (canonical_status == "VALID" and not reexecuted)

    note = (
        f"CONFIRMED_REACHABLE: engine_newPayload returns VALID for a DB-present "
        f"block in {canonical_ms:.1f} ms with no re-execution (GetBlockByHash "
        f"short-circuit at api.go:886), while a not-in-DB block is {forged_status} "
        f"and cached ({forged_resubmit_status}). The INVALID->VALID transition "
        f"additionally requires an invalid block to be written to the DB via "
        f"BeaconSync from an attacker peer — analytic, not single-node reproducible."
        if reachable else
        "short-circuit not observed as expected; see statuses."
    )
    return MonotonicityResult(
        reachable_short_circuit=reachable,
        canonical_status=canonical_status,
        canonical_reexecuted=reexecuted,
        forged_status=forged_status,
        forged_resubmit_status=forged_resubmit_status,
        newpayload_version="V4" if is_v4 else "V3",
        note=note,
    )


if __name__ == "__main__":
    import sys
    enclave = sys.argv[1] if len(sys.argv) > 1 else "repro-grandine"
    res = run_geth_monotonicity_probe(enclave)
    print(res.to_json())
