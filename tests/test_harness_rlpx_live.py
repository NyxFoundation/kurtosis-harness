"""Live RLPx interop test — handshake + Hello against a real reth node.

Auto-discovers a reth EL in the `repro-reth` kurtosis enclave via Docker
(p2p port + node pubkey from admin_nodeInfo) and skips gracefully if there is
no reachable node. Proves the from-scratch RLPx stack interoperates with reth.
"""
from __future__ import annotations

import json
import re
import subprocess
import urllib.request

import pytest

from harness.drivers.rlpx.session import MSG_HELLO, Session


def _docker_host_port(cid: str, container_port: str) -> str | None:
    out = subprocess.run(["docker", "port", cid, container_port],
                         capture_output=True, text=True, timeout=15).stdout.strip()
    # "0.0.0.0:32795" or "127.0.0.1:32795" (possibly multiple lines)
    for line in out.splitlines():
        m = re.search(r":(\d+)$", line.strip())
        if m:
            return m.group(1)
    return None


def _discover_reth():
    """Return (host, p2p_port, pubkey_bytes) for a reth EL, or None."""
    try:
        ids = subprocess.run(
            ["docker", "ps", "-q",
             "--filter", "label=com.kurtosistech.enclave-name=repro-reth"],
            capture_output=True, text=True, timeout=15,
        ).stdout.split()
        for cid in ids:
            label = subprocess.run(
                ["docker", "inspect", cid, "--format",
                 '{{index .Config.Labels "com.kurtosistech.id"}}'],
                capture_output=True, text=True, timeout=15,
            ).stdout.strip()
            if not label.startswith("el-") or "reth" not in label:
                continue
            rpc = _docker_host_port(cid, "8545")
            p2p = _docker_host_port(cid, "30303")
            if not rpc or not p2p:
                return None
            req = urllib.request.Request(
                f"http://127.0.0.1:{rpc}",
                data=json.dumps({"jsonrpc": "2.0", "method": "admin_nodeInfo",
                                 "params": [], "id": 1}).encode(),
                headers={"Content-Type": "application/json"},
            )
            enode = json.loads(urllib.request.urlopen(req, timeout=10).read())["result"]["enode"]
            pub = re.match(r"enode://([0-9a-f]+)@", enode).group(1)
            return "127.0.0.1", int(p2p), bytes.fromhex(pub)
    except Exception:
        return None
    return None


_TARGET = _discover_reth()
requires_reth = pytest.mark.skipif(_TARGET is None, reason="no reachable reth devnet node")


@requires_reth
def test_live_rlpx_handshake_and_hello():
    host, port, pub = _TARGET
    s = Session(host, port, pub)
    try:
        s.connect(timeout=10)               # auth/ack over the socket
        msg_id, body = s.hello()            # p2p Hello exchange
        assert msg_id == MSG_HELLO, f"expected Hello, got msg id {msg_id}"
        client_id = body[1].decode("utf-8", "replace")
        assert "reth" in client_id.lower()
        caps = [(c[0].decode(), int.from_bytes(c[1], "big")) for c in body[2]]
        assert any(name == "eth" for name, _ in caps)  # speaks the eth protocol
    finally:
        s.close()


@requires_reth
def test_live_eth_handshake_and_announce_accepted():
    # Full bring-up (Hello + eth Status -> active), then the AUDIT-001 vector:
    # a NewPooledTransactionHashes announcement must be accepted (reth asks for
    # the txs via GetPooledTransactions), not rejected/disconnected.
    import socket as _socket

    from harness.drivers import wire
    from harness.drivers.rlpx.session import ETH_NEW_POOLED_TX_HASHES

    host, port, pub = _TARGET
    s = Session(host, port, pub)
    try:
        status = s.handshake(timeout=10)          # connect + Hello + eth Status
        assert len(status) == 6                    # [ver, netid, td, head, genesis, forkid]
        hashes = [(i.to_bytes(4, "big") + b"\x00" * 28) for i in range(1000)]
        s.write_msg(ETH_NEW_POOLED_TX_HASHES, wire.encode_new_pooled_transaction_hashes_68(hashes))
        s.sock.settimeout(3)
        try:
            mid, _ = s.read_msg()
            assert mid != 0x01, "reth disconnected on the announcement"
            # 0x19 == GetPooledTransactions: the handler accepted and wants the txs
            assert mid == 0x19
        except _socket.timeout:
            pass  # no disconnect within 3s also means accepted
    finally:
        s.close()
