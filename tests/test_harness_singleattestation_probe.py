"""SingleAttestation probe tests — verify Rust test installation + cargo env.

Offline: does not run the live attack. Verifies that:
- ensure_rust_test_installed copies the .rs file and registers the module
- run_singleattestation_attack assembles the correct cargo command + env
"""
from __future__ import annotations

from pathlib import Path

from harness.probes import grandine_singleattestation_attack as probe


def test_ensure_rust_test_installed_copies_source_and_registers_module(tmp_path):
    root = tmp_path / "grandine"
    tests = root / "eth2_libp2p" / "tests"
    tests.mkdir(parents=True)
    (tests / "main.rs").write_text("mod common;\nmod rpc_tests;\n", encoding="utf-8")
    (tests / "common.rs").write_text(
        "#![cfg(test)]\nuse eth2_libp2p::types::GossipKind;\n",
        encoding="utf-8",
    )

    installed = probe.ensure_rust_test_installed(root)

    assert installed == tests / "grandine_singleattestation_attack.rs"
    assert "publish_oob_singleattestation" in installed.read_text(encoding="utf-8")
    main_text = (tests / "main.rs").read_text(encoding="utf-8")
    assert "mod grandine_singleattestation_attack;" in main_text


def test_run_singleattestation_attack_builds_expected_cargo_env(monkeypatch, tmp_path):
    root = tmp_path / "grandine"
    tests = root / "eth2_libp2p" / "tests"
    tests.mkdir(parents=True)
    (tests / "main.rs").write_text("mod common;\n", encoding="utf-8")
    (tests / "common.rs").write_text("use eth2_libp2p::types::GossipKind;\n", encoding="utf-8")
    cfg = tmp_path / "cfg"
    cfg.mkdir()
    target = probe.GrandineTarget(
        container_id="cid",
        beacon_api="http://127.0.0.1:4000",
        metrics_api="http://127.0.0.1:8008",
        multiaddr="/ip4/127.0.0.1/tcp/9000/p2p/peer",
        config_dir=cfg,
    )
    # Patch discover_grandine_target in the source module (grandine_libp2p_attack),
    # since run_singleattestation_attack imports it at call time.
    from harness.probes import grandine_libp2p_attack as block_probe

    monkeypatch.setattr(block_probe, "discover_grandine_target", lambda enclave: target)
    monkeypatch.setattr(probe, "_find_libclang_path", lambda: "/clang/lib")
    # Patch auto-detection so the test uses deterministic values.
    monkeypatch.setattr(probe, "_detect_committees_per_slot", lambda api: 64)
    monkeypatch.setattr(probe, "_detect_target_subnet", lambda api, mapi, cps: 5)
    calls = []

    class Done:
        returncode = 0

    def fake_run(cmd, **kwargs):
        calls.append((cmd, kwargs))
        return Done()

    monkeypatch.setattr(probe.subprocess, "run", fake_run)

    probe.run_singleattestation_attack(
        enclave="repro-grandine",
        grandine_dir=root,
        attester_index=0xDEAD,
        subnet_id=5,
        warmup=3,
        timeout=7,
    )

    cmd, kwargs = calls[-1]
    assert cmd[:4] == ["cargo", "test", "-p", "eth2_libp2p"]
    assert "publish_oob_singleattestation" in cmd
    assert kwargs["cwd"] == Path(root)
    assert kwargs["timeout"] == 7
    assert kwargs["env"]["GR_ATTESTER_INDEX"] == str(0xDEAD)
    assert kwargs["env"]["GR_SUBNET_ID"] == "5"
    assert kwargs["env"]["LIBCLANG_PATH"] == "/clang/lib"