"""Engine-API identity conformance probe against besu —
EL-GASPER-IDENTITY-LATEST-VALID-001.

Finding (besu 03, AbstractEngineNewPayload.java:336-345, syncResponse bad-block
path): a block first marked bad is stored via addBadBlock but its latestValidHash
is never recorded. On RE-submission the bad-block path returns
getLatestValidHashOfBadBlock(hash).orElse(Hash.ZERO) => Hash.ZERO, which the spec
reserves for the PoW->PoS transition block only; the correct value is the highest
valid ancestor (getLatestValidAncestor(parentHash)).

This probe reproduces it live on besu itself. It builds a valid-blockHash but
invalid-STATE block: it re-encodes a real canonical block's RLP header (validated
by recomputing the block's own hash first), mutates the stateRoot to a wrong
value, and recomputes the matching blockHash. besu accepts the hash, executes,
finds the world-state-root mismatch, and marks the block bad. Then:

    submit #1  -> INVALID, latestValidHash = parent (the correct valid ancestor)
    submit #2  -> INVALID, latestValidHash = 0x00..00 (the bug: bad-block path)

The flip from the real ancestor to ZERO on re-submission is the finding.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass

from ..drivers.rlp import encode as rlp_encode
from ..drivers.rlpx.crypto import keccak256
from .fcu_ordering import discover_el, _jrpc

ZERO_HASH = "0x" + "00" * 32


def _b(h: str) -> bytes:
    return bytes.fromhex(h[2:] if h.startswith("0x") else h)


def _i(h: str) -> int:
    return int(h, 16)


def _header_fields(x: dict, state_root: str) -> list:
    """RLP field list for a post-Prague execution block header, taking every
    field from the block JSON so the encoding is exact (self-checked below)."""
    f = [
        _b(x["parentHash"]), _b(x["sha3Uncles"]), _b(x["miner"]),
        _b(state_root), _b(x["transactionsRoot"]), _b(x["receiptsRoot"]),
        _b(x["logsBloom"]), _i(x["difficulty"]), _i(x["number"]), _i(x["gasLimit"]),
        _i(x["gasUsed"]), _i(x["timestamp"]), _b(x["extraData"]), _b(x["mixHash"]),
        _b(x["nonce"]), _i(x["baseFeePerGas"]), _b(x["withdrawalsRoot"]),
        _i(x["blobGasUsed"]), _i(x["excessBlobGas"]), _b(x["parentBeaconBlockRoot"]),
    ]
    if x.get("requestsHash"):  # EIP-7685 (Prague)
        f.append(_b(x["requestsHash"]))
    return f


def _block_hash(x: dict, state_root: str) -> str:
    return "0x" + keccak256(rlp_encode(_header_fields(x, state_root))).hex()


def _payload_from_block(x: dict, state_root: str, block_hash: str) -> dict:
    return {
        "parentHash": x["parentHash"], "feeRecipient": x["miner"], "stateRoot": state_root,
        "receiptsRoot": x["receiptsRoot"], "logsBloom": x["logsBloom"], "prevRandao": x["mixHash"],
        "blockNumber": x["number"], "gasLimit": x["gasLimit"], "gasUsed": x["gasUsed"],
        "timestamp": x["timestamp"], "extraData": x["extraData"], "baseFeePerGas": x["baseFeePerGas"],
        "blockHash": block_hash, "transactions": [], "withdrawals": [],
        "blobGasUsed": x["blobGasUsed"], "excessBlobGas": x["excessBlobGas"],
    }


@dataclass
class BesuIdentityResult:
    reproduced: bool
    first_status: str
    first_latest_valid_hash: str        # expected: the parent (valid ancestor)
    second_status: str
    second_latest_valid_hash: str       # bug: 0x00..00 instead of the ancestor
    parent_hash: str
    header_encoder_verified: bool
    note: str

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2)


def run_besu_identity_probe(enclave: str, *, depth_back: int = 5) -> BesuIdentityResult:
    t = discover_el(enclave, "besu")
    if t is None:
        raise RuntimeError(f"no 'besu' el- container in enclave {enclave!r}")
    secret = bytes.fromhex(t.jwt_secret)

    head = _i(_jrpc(t.rpc_url, "eth_getBlockByNumber", ["latest", False])["result"]["number"])
    blk = _jrpc(t.rpc_url, "eth_getBlockByNumber", [hex(head - depth_back), True])["result"]

    # Self-verify the header encoder against the block's own hash before trusting
    # it with a mutated stateRoot — guards against a header-format drift.
    encoder_ok = _block_hash(blk, blk["stateRoot"]) == blk["hash"]
    if not encoder_ok:
        return BesuIdentityResult(
            reproduced=False, first_status="-", first_latest_valid_hash="-",
            second_status="-", second_latest_valid_hash="-", parent_hash=blk["parentHash"],
            header_encoder_verified=False,
            note="header RLP encoder did not reproduce the block hash; besu header "
                 "format may have changed — aborting rather than sending a malformed block.",
        )

    # Craft a valid-hash / invalid-state block: wrong stateRoot, matching blockHash.
    bad_sr = "0x" + os.urandom(32).hex()
    bad_hash = _block_hash(blk, bad_sr)
    payload = _payload_from_block(blk, bad_sr, bad_hash)
    pbr = blk["parentBeaconBlockRoot"]

    def submit() -> tuple[str, str]:
        r = _jrpc(t.engine_url, "engine_newPayloadV4", [payload, [], pbr, []], secret)
        res = r.get("result") or r.get("error") or {}
        return res.get("status", str(res)[:40]), res.get("latestValidHash", "")

    s1, lvh1 = submit()   # marks it bad; correct latestValidHash = parent
    s2, lvh2 = submit()   # bad-block path: latestValidHash = 0x00..00 (the bug)

    reproduced = (
        s1 == "INVALID" and s2 == "INVALID"
        and lvh1 == blk["parentHash"]          # first submission returns the real ancestor
        and lvh2 == ZERO_HASH                    # re-submission wrongly returns ZERO
    )
    note = (
        f"CONFIRMED: same bad block returns latestValidHash={blk['parentHash'][:12]}… "
        f"(parent, correct) on submit #1, then 0x00..00 (ZERO, wrong) on re-submission "
        f"via the bad-block path — ZERO is spec-reserved for the transition block only."
        if reproduced else
        f"not reproduced as expected: #1 {s1}/{lvh1[:12]}…, #2 {s2}/{lvh2[:12]}…"
    )
    return BesuIdentityResult(
        reproduced=reproduced, first_status=s1, first_latest_valid_hash=lvh1,
        second_status=s2, second_latest_valid_hash=lvh2, parent_hash=blk["parentHash"],
        header_encoder_verified=True, note=note,
    )


if __name__ == "__main__":
    import sys
    enclave = sys.argv[1] if len(sys.argv) > 1 else "repro-besu-erigon"
    print(run_besu_identity_probe(enclave).to_json())
