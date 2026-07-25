"""CLI tests — `python -m harness <finding.json>` runs the offline model."""
from __future__ import annotations

from harness.runner import main

GRANDINE = "tests/fixtures/sample_finding.json"


def test_cli_confirms_real_finding_offline(capsys):
    rc = main([GRANDINE])
    out = capsys.readouterr().out
    assert rc == 0  # CONFIRMED -> exit 0
    assert "PROP-val-eth-003" in out
    assert "CONFIRMED" in out


def test_cli_devnet_never_fakes_a_verdict(monkeypatch):
    import pytest

    from harness.devnet.kurtosis import DevnetUnavailable, KurtosisHarness
    from harness.drivers.base import DriverNotImplemented

    monkeypatch.setattr(KurtosisHarness, "available", lambda self: False)

    # --devnet must never silently return a verdict: it either reports the
    # substrate unavailable (no engine) or that the attack send is pending
    # (engine up). Both are honest failures, not a fake CONFIRMED.
    with pytest.raises((DevnetUnavailable, DriverNotImplemented)):
        main([GRANDINE, "--devnet"])


def test_cli_build_guarded_invokes_builder_and_devnet(monkeypatch):
    """--build-guarded should build the image then run --devnet with it."""
    from harness.devnet import guarded_image
    from harness.devnet.kurtosis import KurtosisHarness

    built = {}

    def fake_build(client, guard, *, tag=None, **kw):
        built["client"] = client
        built["guard"] = guard
        built["tag"] = tag or f"{client}:guarded"
        return built["tag"]

    monkeypatch.setattr(guarded_image, "build_guarded_image", fake_build)
    monkeypatch.setattr(KurtosisHarness, "available", lambda self: False)

    import pytest

    from harness.devnet.kurtosis import DevnetUnavailable

    # Should build the image, then try --devnet (which fails because engine
    # is unavailable — but the build should have happened first).
    with pytest.raises(DevnetUnavailable):
        main([GRANDINE, "--build-guarded", "tests/fixtures/sample_guard.diff"])

    assert built["client"] == "grandine"
    assert "sample_guard.diff" in built["guard"]
    assert built["tag"] == "grandine:guarded"
