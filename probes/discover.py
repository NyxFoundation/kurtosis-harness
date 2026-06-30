"""Discover a running reth EL in the `repro-reth` kurtosis enclave.

Returns the p2p endpoint + node pubkey, the JSON-RPC URL, and the Engine API
URL + JWT secret, so the probe scripts are self-contained and re-runnable
against whatever devnet is currently up (ports change per boot).
"""

from __future__ import annotations

import json
import re
import subprocess
import urllib.request
from dataclasses import dataclass


@dataclass
class RethTarget:
    host: str
    p2p_port: int
    pubkey: bytes          # 64-byte node id
    rpc_url: str
    engine_url: str
    jwt_secret: str        # hex


def _container(enclave: str, service_prefix: str) -> str | None:
    ids = subprocess.run(
        ["docker", "ps", "-q", "--filter", f"label=com.kurtosistech.enclave-name={enclave}"],
        capture_output=True, text=True, timeout=15,
    ).stdout.split()
    for cid in ids:
        label = subprocess.run(
            ["docker", "inspect", cid, "--format", '{{index .Config.Labels "com.kurtosistech.id"}}'],
            capture_output=True, text=True, timeout=15,
        ).stdout.strip()
        if label.startswith(service_prefix) and "reth" in label:
            return cid
    return None


def _host_port(cid: str, container_port: str) -> str | None:
    out = subprocess.run(["docker", "port", cid, container_port],
                         capture_output=True, text=True, timeout=15).stdout
    for line in out.splitlines():
        m = re.search(r":(\d+)$", line.strip())
        if m:
            return m.group(1)
    return None


def discover_reth(enclave: str = "repro-reth") -> RethTarget | None:
    try:
        cid = _container(enclave, "el-")
        if not cid:
            return None
        rpc = _host_port(cid, "8545")
        p2p = _host_port(cid, "30303")
        engine = _host_port(cid, "8551")
        if not (rpc and p2p and engine):
            return None
        req = urllib.request.Request(
            f"http://127.0.0.1:{rpc}",
            data=json.dumps({"jsonrpc": "2.0", "method": "admin_nodeInfo", "params": [], "id": 1}).encode(),
            headers={"Content-Type": "application/json"},
        )
        enode = json.loads(urllib.request.urlopen(req, timeout=10).read())["result"]["enode"]
        pub = re.match(r"enode://([0-9a-f]+)@", enode).group(1)
        jwt = subprocess.run(
            ["docker", "exec", cid, "cat", "/jwt/jwtsecret"],
            capture_output=True, text=True, timeout=15,
        ).stdout.strip().removeprefix("0x")
        return RethTarget(
            host="127.0.0.1", p2p_port=int(p2p), pubkey=bytes.fromhex(pub),
            rpc_url=f"http://127.0.0.1:{rpc}",
            engine_url=f"http://127.0.0.1:{engine}", jwt_secret=jwt,
        )
    except Exception:
        return None


if __name__ == "__main__":
    t = discover_reth()
    print(t if t is None else f"reth p2p=127.0.0.1:{t.p2p_port} rpc={t.rpc_url} engine={t.engine_url} jwt={t.jwt_secret[:8]}…")
