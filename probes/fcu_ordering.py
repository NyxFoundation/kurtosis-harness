"""Engine-API forkchoice-ordering conformance probe — EL-GASPER-FCU-ANCESTRY-001.

Finding (erigon 03, execution/execmodule/forkchoice.go::verifyForkchoiceHashes):
the FCU validation checks that `finalized` and `safe` are each ancestors of
`head`, but never checks `finalized <= safe` (that finalized precedes safe on the
canonical chain). An FCU with head=100, finalized=80, safe=50 (all canonical) is
accepted, persisting a state where finalized is AHEAD of safe.

This probe tests that invariant directly against any live EL: it sends
engine_forkchoiceUpdatedV3 with finalized at a HIGHER canonical block than safe
(both ancestors of head) and reports whether the client accepts it (VALID == the
bug) or rejects it (-38002 Invalid forkchoice state == enforces the invariant).
It also runs the correctly-ordered control (finalized <= safe) to show the client
does accept a well-formed FCU.

Client-agnostic: point it at whichever EL service is live. The erigon finding is
corroborated cross-client — on the reth and geth devnet nodes both ACCEPT
finalized > safe, i.e. the missing `finalized <= safe` check is not an erigon-only
gap.
"""

from __future__ import annotations

import json
import re
import subprocess
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass

from ..drivers.base import make_engine_jwt


def _el_container(enclave: str, client: str) -> str | None:
    ids = subprocess.run(
        ["docker", "ps", "-q", "--filter", f"label=com.kurtosistech.enclave-name={enclave}"],
        capture_output=True, text=True, timeout=15,
    ).stdout.split()
    for cid in ids:
        lbl = subprocess.run(
            ["docker", "inspect", cid, "--format", '{{index .Config.Labels "com.kurtosistech.id"}}'],
            capture_output=True, text=True, timeout=15,
        ).stdout.strip()
        if lbl.startswith("el-") and client in lbl:
            return cid
    return None


def _host_port(cid: str, port: str) -> str | None:
    out = subprocess.run(["docker", "port", cid, port], capture_output=True, text=True, timeout=15).stdout
    m = re.search(r":(\d+)", out)
    return m.group(1) if m else None


@dataclass
class ELTarget:
    rpc_url: str
    engine_url: str
    jwt_secret: str  # hex


def discover_el(enclave: str, client: str) -> ELTarget | None:
    cid = _el_container(enclave, client)
    if cid is None:
        return None
    rpc, eng = _host_port(cid, "8545"), _host_port(cid, "8551")
    if not (rpc and eng):
        return None
    jwt = subprocess.run(["docker", "exec", cid, "cat", "/jwt/jwtsecret"],
                         capture_output=True, text=True, timeout=15).stdout.strip().removeprefix("0x")
    return ELTarget(f"http://127.0.0.1:{rpc}", f"http://127.0.0.1:{eng}", jwt)


def _jrpc(url, method, params, secret=None, timeout=12):
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


def _fcu_status(t: ELTarget, secret: bytes, head: str, safe: str, finalized: str) -> str:
    r = _jrpc(t.engine_url, "engine_forkchoiceUpdatedV3",
              [{"headBlockHash": head, "safeBlockHash": safe, "finalizedBlockHash": finalized}, None], secret)
    if "error" in r:
        return f"error:{r['error'].get('code', r['error'])}"
    ps = (r.get("result") or {}).get("payloadStatus") or {}
    return ps.get("status", str(r)[:40])


@dataclass
class FcuOrderingResult:
    client: str
    accepts_finalized_ahead_of_safe: bool   # True == the bug (no finalized<=safe check)
    inverted_status: str                     # status for finalized > safe
    ordered_status: str                      # status for the correct finalized <= safe control
    head_number: int
    note: str

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2)


def run_fcu_ordering_probe(enclave: str, client: str, *, safe_back: int = 20, final_back: int = 10) -> FcuOrderingResult:
    t = discover_el(enclave, client)
    if t is None:
        raise RuntimeError(f"no {client!r} el- container in enclave {enclave!r}")
    secret = bytes.fromhex(t.jwt_secret)

    head = _jrpc(t.rpc_url, "eth_getBlockByNumber", ["latest", False])["result"]
    hn = int(head["number"], 16)
    older = _jrpc(t.rpc_url, "eth_getBlockByNumber", [hex(hn - safe_back), False])["result"]["hash"]
    newer = _jrpc(t.rpc_url, "eth_getBlockByNumber", [hex(hn - final_back), False])["result"]["hash"]

    # Bug case: finalized (newer, #hn-final_back) is AHEAD of safe (older, #hn-safe_back).
    inverted = _fcu_status(t, secret, head["hash"], safe=older, finalized=newer)
    # Control: correctly ordered finalized (older) <= safe (newer).
    ordered = _fcu_status(t, secret, head["hash"], safe=newer, finalized=older)

    accepts = inverted == "VALID"
    note = (
        f"BUG PRESENT: {client} accepts FCU with finalized(#{hn-final_back}) AHEAD of "
        f"safe(#{hn-safe_back}) -> {inverted} (no finalized<=safe check); correctly-ordered "
        f"control -> {ordered}."
        if accepts else
        f"{client} rejects finalized-ahead-of-safe -> {inverted} (invariant enforced); "
        f"ordered control -> {ordered}."
    )
    return FcuOrderingResult(
        client=client, accepts_finalized_ahead_of_safe=accepts,
        inverted_status=inverted, ordered_status=ordered, head_number=hn, note=note,
    )


if __name__ == "__main__":
    import sys
    enclave = sys.argv[1] if len(sys.argv) > 1 else "repro-audit-001-baseline"
    client = sys.argv[2] if len(sys.argv) > 2 else "reth"
    print(run_fcu_ordering_probe(enclave, client).to_json())
