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
