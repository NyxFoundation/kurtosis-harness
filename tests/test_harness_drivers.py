"""L0/L1 contract tests — drivers + devnet skeleton (no live network needed).

These assert the *contracts* hold: every attack surface and every real finding
maps to a registered driver, and the network/devnet paths fail loudly (never
silently succeed) when no live substrate is present.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from harness.devnet.kurtosis import DevnetUnavailable, KurtosisHarness
from harness.drivers.base import (
    BlockImportDriver,
    DRIVER_REGISTRY,
    DriverNotImplemented,
    DriverTarget,
    get_driver,
)
from harness.schema import AttackSurface, load_finding_spec
from harness.verdict import Variant

BUNDLES = [Path("tests/fixtures/sample_finding.json")]


def test_every_surface_has_a_driver():
    for surface in AttackSurface:
        assert surface in DRIVER_REGISTRY, f"no driver for {surface}"
        assert get_driver(surface).surface is surface


@pytest.mark.parametrize("spec_path", BUNDLES, ids=[p.parent.name for p in BUNDLES])
def test_every_finding_maps_to_a_driver_advertising_its_generator(spec_path):
    spec = load_finding_spec(spec_path)
    driver = get_driver(spec.attack_surface)
    assert driver.surface is spec.attack_surface
    assert spec.attacker_input.generator in driver.generators, (
        f"{spec.vuln_id}: generator {spec.attacker_input.generator!r} not advertised "
        f"by {driver.surface.value} driver"
    )


def test_stub_driver_emit_raises_clearly():
    spec = load_finding_spec(BUNDLES[0])
    driver = get_driver(spec.attack_surface)
    with pytest.raises(DriverNotImplemented):
        driver.emit(spec, DriverTarget())


def test_lifecycle_factory_embeds_destroy_then_refund_sequence():
    child = BlockImportDriver._child_init()
    init, runtime_len = BlockImportDriver._factory_init()

    # The factory deployment init copies exactly the runtime, and the runtime
    # embeds the child init at the declared CODECOPY offset.  DUP6 is the
    # deliberate stack operation that reuses A as CALL's destination after
    # the five CALL arguments have been pushed.
    runtime = init[-runtime_len:]
    assert runtime[42:] == child
    assert runtime[0:7] == bytes([0x60, len(child), 0x60, 0x2A, 0x60, 0x00, 0x39])
    assert runtime.count(bytes([0x85])) == 2  # DUP6 before the two CALLs


def test_kurtosis_reports_unavailable_rather_than_faking():
    # With no kurtosis binary, run() must raise — never return fake metrics.
    h = KurtosisHarness(kurtosis_bin="kurtosis-does-not-exist-xyz")
    assert h.available() is False
    spec = load_finding_spec(BUNDLES[0])
    with pytest.raises(DevnetUnavailable):
        h.run(spec, Variant.BASELINE)
