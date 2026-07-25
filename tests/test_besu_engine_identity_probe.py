from __future__ import annotations

import pytest

from harness.probes import besu_engine_identity as probe

# A real post-Prague besu/erigon devnet block header + its hash. Golden fixture:
# the RLP header encoder MUST reproduce this hash, or the crafted-block probe
# would send a malformed (hash-mismatched) payload.
GOLDEN = {
    "parentHash": "0x25c26894165fbde26eea9d1768faccd34c8d586e856744ebf91845b90e04879c",
    "sha3Uncles": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
    "miner": "0x8943545177806ed17b9f23f0a21ee5948ecaa776",
    "stateRoot": "0xa49e92083814ffba167fb8b841c376b49e0541d9e5821f0366bd7907d247cffc",
    "transactionsRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
    "receiptsRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
    "logsBloom": "0x" + "00" * 256,
    "difficulty": "0x0", "number": "0x9e", "gasLimit": "0x3938700", "gasUsed": "0x0",
    "timestamp": "0x6a647f8b", "extraData": "0x657269676f6e2d332e352e332d6565383635663263",
    "mixHash": "0x309992977fac827b69a5d36b206d6af0923f49d8802782e0fe7ceb5996ce8cc5",
    "nonce": "0x0000000000000000", "baseFeePerGas": "0x7",
    "withdrawalsRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
    "blobGasUsed": "0x0", "excessBlobGas": "0x0",
    "parentBeaconBlockRoot": "0x12762f4d7c5f7c0caee6ba527c41312168789367a150834e04d9b6a9941acc90",
    "requestsHash": "0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "hash": "0x789bca9613407fc85eb72a7f94a5f2d16178b5efcb8c18e6e77240fc2e603bfc",
}


def test_header_encoder_reproduces_real_block_hash():
    assert probe._block_hash(GOLDEN, GOLDEN["stateRoot"]) == GOLDEN["hash"]


def test_mutating_state_root_changes_the_block_hash():
    mutated = probe._block_hash(GOLDEN, "0x" + "ab" * 32)
    assert mutated != GOLDEN["hash"]
    # deterministic for a fixed stateRoot
    assert mutated == probe._block_hash(GOLDEN, "0x" + "ab" * 32)


def test_requests_hash_included_only_when_present():
    with_req = probe._header_fields(GOLDEN, GOLDEN["stateRoot"])
    no_req = probe._header_fields({k: v for k, v in GOLDEN.items() if k != "requestsHash"},
                                  GOLDEN["stateRoot"])
    assert len(with_req) == len(no_req) + 1


def test_payload_maps_fields():
    p = probe._payload_from_block(GOLDEN, "0x" + "cd" * 32, "0x" + "ef" * 32)
    assert p["feeRecipient"] == GOLDEN["miner"]        # miner -> feeRecipient
    assert p["prevRandao"] == GOLDEN["mixHash"]        # mixHash -> prevRandao
    assert p["stateRoot"] == "0x" + "cd" * 32
    assert p["blockHash"] == "0x" + "ef" * 32
    assert p["transactions"] == [] and p["withdrawals"] == []


def test_run_raises_without_besu(monkeypatch):
    monkeypatch.setattr(probe, "discover_el", lambda enclave, client: None)
    with pytest.raises(RuntimeError, match="no 'besu' el- container"):
        probe.run_besu_identity_probe("no-enclave")
