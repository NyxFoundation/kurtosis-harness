from __future__ import annotations

from pathlib import Path

from harness.probes import grandine_libp2p_attack as probe


def test_peer_id_from_identity_peer_id():
    assert probe._peer_id({"data": {"peer_id": "16Uiu2H"}}) == "16Uiu2H"


def test_peer_id_from_identity_multiaddr():
    identity = {"data": {"p2p_addresses": ["/ip4/1.2.3.4/tcp/9000/p2p/16Uiu2X"]}}
    assert probe._peer_id(identity) == "16Uiu2X"


def test_ensure_rust_test_installed_patches_grandine_test_tree(tmp_path):
    root = tmp_path / "grandine"
    tests = root / "eth2_libp2p" / "tests"
    tests.mkdir(parents=True)
    (tests / "main.rs").write_text("mod common;\nmod rpc_tests;\n", encoding="utf-8")
    (tests / "common.rs").write_text(
        "\n".join(
            [
                "#![cfg(test)]",
                "use eth2_libp2p::types::{GossipKind, ForkContext};",
                "use std::sync::Arc;",
                "use types::{config::Config as ChainConfig, preset::Preset};",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    installed = probe.ensure_rust_test_installed(root)

    assert installed == tests / "grandine_gossip_attack.rs"
    assert "flood_far_future_beacon_blocks" in installed.read_text(encoding="utf-8")
    assert "mod grandine_gossip_attack;" in (tests / "main.rs").read_text(encoding="utf-8")
    common = (tests / "common.rs").read_text(encoding="utf-8")
    assert "pub async fn build_attacker_instance" in common


def test_run_grandine_libp2p_attack_builds_expected_cargo_env(monkeypatch, tmp_path):
    root = tmp_path / "grandine"
    tests = root / "eth2_libp2p" / "tests"
    tests.mkdir(parents=True)
    (tests / "main.rs").write_text("mod common;\n", encoding="utf-8")
    (tests / "common.rs").write_text(
        "use eth2_libp2p::types::{GossipKind};\n",
        encoding="utf-8",
    )
    cfg = tmp_path / "cfg"
    cfg.mkdir()
    target = probe.GrandineTarget(
        container_id="cid",
        beacon_api="http://127.0.0.1:4000",
        metrics_api="http://127.0.0.1:8008",
        multiaddr="/ip4/127.0.0.1/tcp/9000/p2p/peer",
        config_dir=cfg,
    )
    monkeypatch.setattr(probe, "discover_grandine_target", lambda enclave: target)
    monkeypatch.setattr(probe, "_find_libclang_path", lambda: "/clang/lib")
    calls = []

    class Done:
        returncode = 0

    def fake_run(cmd, **kwargs):
        calls.append((cmd, kwargs))
        return Done()

    monkeypatch.setattr(probe.subprocess, "run", fake_run)

    probe.run_grandine_libp2p_attack(
        enclave="repro-grandine",
        grandine_dir=root,
        count=123,
        slot_offset=456,
        warmup=7,
        timeout=9,
    )

    cmd, kwargs = calls[-1]
    assert cmd[:4] == ["cargo", "test", "-p", "eth2_libp2p"]
    assert kwargs["cwd"] == Path(root)
    assert kwargs["timeout"] == 9
    assert kwargs["env"]["GR_CFG"] == str(cfg)
    assert kwargs["env"]["GR_TARGET"] == target.multiaddr
    assert kwargs["env"]["GR_FLOOD"] == "123"
    assert kwargs["env"]["GR_SLOT_OFFSET"] == "456"
    assert kwargs["env"]["LIBCLANG_PATH"] == "/clang/lib"
