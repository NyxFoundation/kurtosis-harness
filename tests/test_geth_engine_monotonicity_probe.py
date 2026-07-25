from __future__ import annotations

from harness.probes import geth_engine_monotonicity as probe


def _block() -> dict:
    return {
        "parentHash": "0x" + "11" * 32, "miner": "0x" + "22" * 20, "stateRoot": "0x" + "33" * 32,
        "receiptsRoot": "0x" + "44" * 32, "logsBloom": "0x" + "00" * 256, "mixHash": "0x" + "55" * 32,
        "number": "0x2e2d4", "gasLimit": "0x1c9c380", "gasUsed": "0x0", "timestamp": "0x66a00000",
        "extraData": "0x", "baseFeePerGas": "0x7", "hash": "0x" + "66" * 32,
        "blobGasUsed": "0x0", "excessBlobGas": "0x0", "requestsHash": "0x" + "77" * 32,
        "parentBeaconBlockRoot": "0x" + "88" * 32,
    }


def test_payload_reconstruction_maps_block_fields():
    p = probe._payload_from_block(_block())
    assert p["blockHash"] == _block()["hash"]
    assert p["feeRecipient"] == _block()["miner"]       # miner -> feeRecipient
    assert p["prevRandao"] == _block()["mixHash"]       # mixHash -> prevRandao
    assert p["transactions"] == [] and p["withdrawals"] == []
    for k in ("parentHash", "stateRoot", "receiptsRoot", "logsBloom", "blockNumber",
              "gasLimit", "gasUsed", "timestamp", "baseFeePerGas", "blobGasUsed", "excessBlobGas"):
        assert k in p


def test_v4_detected_from_requests_hash():
    assert "requestsHash" in _block()          # Prague block -> newPayloadV4
    b3 = _block()
    del b3["requestsHash"]
    assert "requestsHash" not in b3            # pre-Prague -> V3


def test_result_serialises():
    r = probe.MonotonicityResult(
        reachable_short_circuit=True, canonical_status="VALID", canonical_reexecuted=False,
        forged_status="INVALID", forged_resubmit_status="INVALID", newpayload_version="V4", note="x")
    assert '"reachable_short_circuit": true' in r.to_json()


def test_discover_geth_none_for_missing_enclave(monkeypatch):
    monkeypatch.setattr(probe, "_geth_container", lambda enclave: None)
    assert probe.discover_geth("no-such-enclave") is None
