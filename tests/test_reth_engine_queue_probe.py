from __future__ import annotations

import pytest

from harness.probes import reth_engine_queue as probe


def _head() -> dict:
    return {
        "hash": "0x" + "ab" * 32,
        "number": "0x2d9f0",
        "gasLimit": "0x1c9c380",
        "timestamp": "0x66a00000",
        "baseFeePerGas": "0x7",
    }


def test_make_payload_shape_is_valid_execution_payload_v3():
    pl = probe._make_payload(_head(), tx_bytes=16, tx_count=4)
    # parentHash must be the live head so reth admits the payload for processing.
    assert pl["parentHash"] == _head()["hash"]
    # blockNumber is head+1.
    assert int(pl["blockNumber"], 16) == int(_head()["number"], 16) + 1
    # all V3 fields present.
    for k in ("stateRoot", "receiptsRoot", "logsBloom", "prevRandao", "blockHash",
              "blobGasUsed", "excessBlobGas", "withdrawals", "transactions"):
        assert k in pl
    assert len(pl["transactions"]) == 4
    # each junk tx is 16 bytes -> 0x + 32 hex chars.
    assert all(len(tx) == 2 + 16 * 2 for tx in pl["transactions"])


def test_make_payload_randomises_per_call():
    a = probe._make_payload(_head(), tx_bytes=8, tx_count=1)
    b = probe._make_payload(_head(), tx_bytes=8, tx_count=1)
    assert a["blockHash"] != b["blockHash"]
    assert a["stateRoot"] != b["stateRoot"]


def test_run_measured_raises_without_a_reth_container(monkeypatch):
    monkeypatch.setattr(probe, "_reth_container", lambda enclave: None)
    target = probe.RethTarget(
        host="127.0.0.1", p2p_port=1, pubkey=b"\x00" * 64,
        rpc_url="http://127.0.0.1:1", engine_url="http://127.0.0.1:2",
        jwt_secret="00" * 32,
    )
    with pytest.raises(RuntimeError, match="no reth el- container"):
        probe.run_measured_reth_newpayload_flood(target, "no-such-enclave")
