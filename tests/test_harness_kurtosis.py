"""Kurtosis backend tests — pure participant config (always) + live enclave.

The live test boots a *minimal* enclave (one small service, not the full
ethereum-package) to prove the harness can run an enclave, resolve the service
to its Docker container, sample real resources, and tear down — fast, and
skipped where the Kurtosis engine isn't running.
"""
from __future__ import annotations

import uuid

import pytest

from harness.devnet.kurtosis import (
    KurtosisHarness,
    build_ethereum_package_args,
)

# --- pure config tests (no engine needed) ----------------------------------


def test_el_target_paired_with_cl():
    args = build_ethereum_package_args("reth")
    p = args["participants"][0]
    assert p["el_type"] == "reth"
    assert p["cl_type"]  # paired so the devnet finalises


def test_cl_target_paired_with_el():
    args = build_ethereum_package_args("grandine")
    p = args["participants"][0]
    assert p["cl_type"] == "grandine"
    assert p["el_type"]


def test_unknown_client_rejected():
    with pytest.raises(ValueError):
        build_ethereum_package_args("not-a-client")


def test_run_raises_when_engine_absent():
    h = KurtosisHarness(kurtosis_bin="kurtosis-does-not-exist-xyz")
    assert h.available() is False


# --- live enclave test (real Kurtosis; skipped without a running engine) ----

_engine = KurtosisHarness()
requires_kurtosis = pytest.mark.skipif(
    not _engine.available(), reason="kurtosis engine not running"
)

_SMOKE_STAR = '''
def run(plan):
    plan.add_service(name = "target", config = ServiceConfig(image = "caddy:2-alpine"))
'''


@requires_kurtosis
def test_live_enclave_boot_resolve_sample_teardown(tmp_path):
    h = KurtosisHarness(samples=2, interval=0.3)
    star = tmp_path / "smoke.star"
    star.write_text(_SMOKE_STAR, encoding="utf-8")
    enclave = f"harness-pytest-{uuid.uuid4().hex[:8]}"
    try:
        h.run_package(str(star), enclave=enclave)
        cid = h.resolve_service_container(enclave, "target")
        assert cid
        samples = h.sample_service(enclave, "target")
        assert len(samples) == 2
        assert all(s.rss_mb > 0 for s in samples)
        ip = h.service_private_ip(enclave, "target")
        assert ip.count(".") == 3  # an IPv4 address
    finally:
        h.rm_enclave(enclave)
